FROM python:3.10-slim

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    rsyslog \
    net-tools \
    netcat-openbsd \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create required directories and set permissions
RUN mkdir -p /var/log/collector /var/spool/rsyslog /var/run/rsyslog && \
    touch /var/log/collector/syslog.json \
         /var/log/collector/rsyslog-debug.log && \
    chmod -R 777 /var/log/collector /var/spool/rsyslog /var/run/rsyslog && \
    chmod 666 /var/log/collector/syslog.json \
              /var/log/collector/rsyslog-debug.log && \
    chown -R root:root /var/log/collector /var/spool/rsyslog /var/run/rsyslog

# Copy and set up rsyslog configuration first
COPY rsyslog.conf /etc/rsyslog.conf
RUN chmod 644 /etc/rsyslog.conf && \
    chown root:root /etc/rsyslog.conf

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Make the start script executable after copying
RUN chmod +x start.sh

# Set the entrypoint to the start script
CMD ["/app/start.sh"]