FROM python:3.11-slim

WORKDIR /app

# Install system dependencies and curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    postgresql-client \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create startup script
RUN echo '#!/bin/bash\n\
echo "Waiting for database..."\n\
while ! pg_isready -h $DB_HOST -U $DB_USER; do\n\
    sleep 1\n\
done\n\
\n\
echo "Database is ready!"\n\
\n\
echo "Starting API service..."\n\
exec uvicorn main:app --host 0.0.0.0 --port 8080 --log-level info\n\
' > /app/start.sh && chmod +x /app/start.sh

# Expose port for API
EXPOSE 8080

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start the service using the startup script
CMD ["/app/start.sh"]