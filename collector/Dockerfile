FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Configure rsyslog
COPY rsyslog.conf /etc/rsyslog.conf

# Expose ports
EXPOSE 514/udp 514/tcp 8000

# Start services
CMD ["./start.sh"]
