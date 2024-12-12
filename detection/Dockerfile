FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including git and build tools for psutil
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Clean pip cache and install Python dependencies
COPY requirements.txt .
RUN pip cache purge && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directory for Sigma rules
RUN mkdir -p /app/rules

# Expose port for API
EXPOSE 8000

# Start the service
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]