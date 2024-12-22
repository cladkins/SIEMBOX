FROM python:3.11-slim

WORKDIR /app

# Install system dependencies required for cryptography package
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Initialize database
CMD ["sh", "-c", "python init_db.py && uvicorn main:app --host 0.0.0.0 --port 8080"]