#!/usr/bin/env python3
"""Compare a fresh evaluation run against a committed reference run.

Checks, per scenario, the fields that define a reported result:

  outcome      TP / FN / FP / TN
  first_block  index of the first blocked call (blank if none)
  layer        layer of the first block (routing, L1, L2, guard, ...)
  leaks        what leaked, if anything

Latency, timestamps and backend error text are not compared: they vary from
machine to machine and are reported as indicative only (see REPRODUCING.md).

Usage:
  python eval/compare_runs.py eval/runs/phase5-dev my-run/
  python eval/compare_runs.py eval/runs/final my-run/ --ids-from my-run

Exits 0 when every compared scenario matches, 1 otherwise.  Scenarios that
exist in only one run are reported; by default the comparison covers the
scenarios in the reference run, and missing ones count as mismatches.
"""

from __future__ import annotations

import argparse
import csv
import pathlib
import sys

FIELDS = ("outcome", "first_block", "layer", "leaks")


def load(run: pathlib.Path) -> dict[str, dict[str, str]]:
    path = run / "results.csv" if run.is_dir() else run
    with path.open(newline="", encoding="utf-8") as fh:
        return {row["id"]: row for row in csv.DictReader(fh)}


def headline(rows: dict[str, dict[str, str]]) -> str:
    counts = {k: 0 for k in ("TP", "FN", "FP", "TN")}
    for row in rows.values():
        counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
    attacks = counts["TP"] + counts["FN"]
    benign = counts["FP"] + counts["TN"]
    return f"blocked {counts['TP']}/{attacks} attacks, {counts['FP']}/{benign} false positives"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reference", type=pathlib.Path, help="committed run dir (or its results.csv)")
    ap.add_argument("candidate", type=pathlib.Path, help="fresh run dir (or its results.csv)")
    ap.add_argument(
        "--ids-from",
        choices=("reference", "candidate"),
        default="reference",
        help="which run defines the scenarios to compare (candidate: e.g. a dev-only rerun of a dev+holdout reference)",
    )
    args = ap.parse_args()

    ref, cand = load(args.reference), load(args.candidate)
    ids = sorted(ref if args.ids_from == "reference" else cand)

    mismatches: list[str] = []
    for sid in ids:
        if sid not in ref or sid not in cand:
            where = "reference" if sid not in ref else "candidate"
            mismatches.append(f"  {sid}: missing from {where} run")
            continue
        diffs = [
            f"{f} {ref[sid].get(f, '')!r} -> {cand[sid].get(f, '')!r}"
            for f in FIELDS
            if ref[sid].get(f, "") != cand[sid].get(f, "")
        ]
        if diffs:
            mismatches.append(f"  {sid}: " + "; ".join(diffs))

    compared = {sid: cand[sid] for sid in ids if sid in cand}
    ref_subset = {sid: ref[sid] for sid in ids if sid in ref}
    print(f"reference  {args.reference}: {headline(ref_subset)}")
    print(f"candidate  {args.candidate}: {headline(compared)}")
    if mismatches:
        print(f"MISMATCH: {len(mismatches)} of {len(ids)} scenarios differ")
        print("\n".join(mismatches))
        return 1
    print(f"MATCH: all {len(ids)} scenarios agree on {', '.join(FIELDS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
