FROM python:3.11-slim-bookworm

WORKDIR /app

# Pinned dependencies (requirements.txt) so a fresh clone builds the same proxy
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and config
COPY src/ ./src/
COPY config/ ./config/

CMD ["uvicorn", "src.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
