FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    python3-dev \
    redis-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create startup script
RUN echo '#!/bin/bash\n\
\n\
echo "Waiting for Redis..."\n\
until redis-cli -h redis ping; do\n\
    echo "Redis is unavailable - sleeping"\n\
    sleep 2\n\
done\n\
\n\
echo "Redis is ready!"\n\
\n\
echo "Starting IP Lookup service..."\n\
exec uvicorn main:app --host 0.0.0.0 --port 8000 --log-level info\n\
' > /app/start.sh && chmod +x /app/start.sh

# Expose port
EXPOSE 8000

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start the service using the startup script
CMD ["/app/start.sh"]