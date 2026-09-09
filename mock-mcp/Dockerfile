FROM python:3.11-slim

WORKDIR /app

# This installs the dependencies inside the mock tool server's container
RUN pip install --no-cache-dir fastapi uvicorn

COPY server.py .

CMD ["python", "server.py"]