FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including git and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create directory for Sigma rules with proper permissions
RUN mkdir -p /app/rules && \
    chmod 755 /app/rules && \
    chown -R nobody:nogroup /app/rules

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set proper permissions for application files
RUN chown -R nobody:nogroup /app && \
    chmod -R 755 /app

# Switch to non-root user
USER nobody

# Expose port for API
EXPOSE 8000

# Add health check with longer startup period
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start the service
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]