FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    rsyslog \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Make start script executable
RUN chmod +x start.sh

# Create required directories
RUN mkdir -p /var/log/collector /var/spool/rsyslog /var/run/rsyslog

EXPOSE 5514/tcp 5514/udp 8000

ENTRYPOINT ["./start.sh"]