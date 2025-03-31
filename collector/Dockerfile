FROM python:3.10-slim

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    rsyslog \
    net-tools \
    netcat \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Make the start script executable after copying
RUN chmod +x start.sh

# Create required directories with proper permissions
RUN mkdir -p /var/log/collector /var/spool/rsyslog /var/run/rsyslog && \
    chmod -R 777 /var/log/collector /var/spool/rsyslog /var/run/rsyslog

# Copy and set up rsyslog configuration
COPY rsyslog.conf /etc/rsyslog.conf
RUN chmod 644 /etc/rsyslog.conf

# Set the entrypoint to the start script
CMD ["/app/start.sh"]