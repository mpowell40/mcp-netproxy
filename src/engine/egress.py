"""Egress URL Policy & Enforcing Forward Proxy.

Decides whether an outbound URL may be fetched, and enforces that decision
at the network layer for every request a fetch-style backend makes.

``EgressPolicy.check`` is shared by two enforcement points:

1. Layer 1 in the proxy, on a tool's ``url`` argument, before forwarding.
2. ``EgressGuard``, a small HTTP forward proxy the fetch backend is pointed
   at (``--proxy-url``).  Every request, including each redirect hop the
   backend follows on its own, is re-validated here, and the guard connects
   to the address it validated, so DNS cannot be re-pointed in between.

Rules: scheme must be allowed (http/https), host must be on the allowlist
(exact match), and every resolved address must be public.  Loopback,
link-local (incl. cloud metadata), multicast, reserved and unspecified
addresses are always refused; private ranges only for hosts listed in
``private_hosts``.  Anything unresolvable fails closed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import Awaitable, Callable
from urllib.parse import urlsplit

from src.models.policy import EgressConfig

logger = logging.getLogger("mcp-netproxy")

Resolver = Callable[[str, int], Awaitable[list[str]]]

_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAX_HEADER_BYTES = 64 * 1024


@dataclass(frozen=True)
class EgressVerdict:
    allowed: bool
    reason: str
    host: str = ""
    port: int = 0
    addresses: tuple[str, ...] = ()


async def _system_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


def address_allowed(address: str, allow_private: bool) -> bool:
    """Whether a connection to *address* is acceptable."""
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    if ip.is_private:
        return allow_private
    return ip.is_global


class EgressPolicy:
    """Evaluates outbound URLs against an ``EgressConfig``."""

    def __init__(self, config: EgressConfig, resolver: Resolver | None = None) -> None:
        self._config = config
        self._schemes = {s.lower() for s in config.schemes}
        self._hosts = {h.lower().rstrip(".") for h in config.allowed_hosts}
        self._private_hosts = {h.lower().rstrip(".") for h in config.private_hosts}
        self._resolve = resolver or _system_resolver

    async def check(self, url: str) -> EgressVerdict:
        if not isinstance(url, str):
            return EgressVerdict(False, "URL is not a string")
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            return EgressVerdict(False, f"Malformed URL ({exc})")
        scheme = parts.scheme.lower()
        if scheme not in self._schemes:
            return EgressVerdict(False, f"Scheme '{scheme or '(none)'}' not allowed")
        host = (parts.hostname or "").rstrip(".")
        if not host:
            return EgressVerdict(False, "URL has no host")
        if host not in self._hosts:
            return EgressVerdict(False, f"Host '{host}' not on the egress allowlist")
        port = port or _DEFAULT_PORTS[scheme]
        try:
            addresses = await self._resolve(host, port)
        except OSError as exc:
            return EgressVerdict(False, f"Host '{host}' did not resolve ({exc})", host, port)
        if not addresses:
            return EgressVerdict(False, f"Host '{host}' did not resolve", host, port)
        allow_private = host in self._private_hosts
        refused = [a for a in addresses if not address_allowed(a, allow_private)]
        if refused:
            return EgressVerdict(False, f"Host '{host}' resolves to a refused address ({refused[0]})", host, port)
        return EgressVerdict(True, "Allowed", host, port, tuple(addresses))


class EgressGuard:
    """HTTP forward proxy that applies an ``EgressPolicy`` to every request.

    Supports absolute-form HTTP requests and ``CONNECT`` tunnels (https).
    Each request uses a fresh upstream connection (``Connection: close``),
    so a redirect is always a new, re-validated request.
    """

    def __init__(self, policy: EgressPolicy) -> None:
        self._policy = policy

    async def start(self, host: str, port: int) -> asyncio.base_events.Server:
        return await asyncio.start_server(self._handle, host, port)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            if len(head) > _MAX_HEADER_BYTES:
                return await self._refuse(writer, 431, "Request header too large")
            lines = head.decode("latin-1").split("\r\n")
            method, target, version = lines[0].split(" ", 2)
            headers = [line for line in lines[1:] if line]

            if method.upper() == "CONNECT":
                url = f"https://{target}/"
            elif target.lower().startswith(("http://", "https://")):
                url = target
            else:
                return await self._refuse(writer, 400, "Absolute-form request required")

            verdict = await self._policy.check(url)
            if not verdict.allowed:
                logger.warning(f"[EGRESS GUARD BLOCKED] {method} {url}: {verdict.reason}")
                return await self._refuse(writer, 403, verdict.reason)

            up_reader, up_writer = await asyncio.open_connection(verdict.addresses[0], verdict.port)
            if method.upper() == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            else:
                parts = urlsplit(url)
                path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
                kept = [h for h in headers
                        if h.split(":", 1)[0].strip().lower() not in ("proxy-connection", "connection", "proxy-authorization")]
                up_writer.write(f"{method} {path} {version}\r\n".encode("latin-1"))
                up_writer.write(("\r\n".join(kept + ["Connection: close"]) + "\r\n\r\n").encode("latin-1"))
                length = next((int(h.split(":", 1)[1]) for h in headers
                               if h.split(":", 1)[0].strip().lower() == "content-length"), 0)
                if length:
                    up_writer.write(await reader.readexactly(length))
                await up_writer.drain()
            await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            await self._refuse(writer, 400, "Bad request")
        except OSError as exc:
            await self._refuse(writer, 502, f"Upstream connection failed ({exc})")
        finally:
            writer.close()

    @staticmethod
    async def _refuse(writer: asyncio.StreamWriter, status: int, reason: str) -> None:
        body = f"mcp-netproxy egress guard: {reason}\n".encode()
        try:
            writer.write(
                f"HTTP/1.1 {status} Refused\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
            )
            await writer.drain()
        except OSError:
            pass


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
    except OSError:
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass
