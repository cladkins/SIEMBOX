FROM python:3.11-slim

# Add metadata
LABEL maintainer="SIEMBox Team"
LABEL description="SIEMBox Log Collector Service"
LABEL version="1.0"

WORKDIR /app

# Install system dependencies and debugging tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    rsyslog \
    procps \
    net-tools \
    netcat-traditional \
    tcpdump \
    curl \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create required directories with proper permissions
RUN mkdir -p /var/log/collector && \
    mkdir -p /var/spool/rsyslog && \
    mkdir -p /var/run/rsyslog && \
    chmod -R 755 /var/log/collector && \
    chmod -R 755 /var/spool/rsyslog && \
    chmod -R 755 /var/run/rsyslog && \
    chown -R root:root /var/log/collector && \
    chown -R root:root /var/spool/rsyslog && \
    chown -R root:root /var/run/rsyslog

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Configure rsyslog
COPY rsyslog.conf /etc/rsyslog.conf
RUN chmod 644 /etc/rsyslog.conf

# Make start script executable
RUN chmod +x start.sh

# Create log file with proper permissions
RUN touch /var/log/collector/syslog.json && \
    chmod 644 /var/log/collector/syslog.json

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=info
ENV API_URL=http://api:8080
ENV RETRY_COUNT=3
ENV BACKOFF_FACTOR=1.5
ENV BUFFER_SIZE=100
ENV FLUSH_INTERVAL=5

# Expose ports
EXPOSE 5514/udp 5514/tcp 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start services with logging
CMD ["./start.sh"]