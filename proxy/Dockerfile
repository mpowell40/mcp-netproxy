FROM python:3.11-slim

WORKDIR /app

# This installs the dependencies inside the proxy's virtual container
RUN pip install --no-cache-dir fastapi uvicorn httpx

COPY main.py .

CMD ["python", "main.py"]