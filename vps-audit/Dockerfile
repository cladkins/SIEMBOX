FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including PostgreSQL client
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    openssh-client \
    curl \
    postgresql-client \
    libpq-dev \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Clone vps-audit tool
RUN git clone https://github.com/vernu/vps-audit.git /opt/vps-audit

# Copy application code
COPY . .

# Create directory for SSH keys
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh

# Expose port
EXPOSE 8004

# Make start script executable
RUN chmod +x start.sh

# Command to run the application
CMD ["./start.sh"]