FROM python:3.10-slim

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Make the start script executable
RUN chmod +x start.sh

COPY . .

CMD ["/app/start.sh"]