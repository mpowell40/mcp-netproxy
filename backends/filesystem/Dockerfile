FROM python:3.11-slim

WORKDIR /app

# Install Node.js (v20 because some MCP packages complain about v18)
RUN apt-get update && \
    apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install python dependencies for the wrapper
RUN pip install --no-cache-dir fastapi uvicorn

COPY server.py .

CMD ["python", "server.py"]