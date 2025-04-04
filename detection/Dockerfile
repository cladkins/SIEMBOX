FROM python:3.12-slim

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install build tools first
RUN pip install --no-cache-dir pip setuptools wheel build

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all files (including start.sh)
COPY . .

# Make the start script executable
RUN chmod +x start.sh

# Use the start script as the command
CMD ["/app/start.sh"]