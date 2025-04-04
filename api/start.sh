#!/bin/sh

# Wait for database to be ready
echo "Waiting for database..."
while ! curl -s http://db:5432/ >/dev/null; do
    sleep 1
done

# Run database migrations
echo "Running database migrations..."
alembic upgrade head

# Initialize database tables
echo "Initializing database tables..."
python init_db.py

# Start the application
echo "Starting API service..."
exec uvicorn main:app --host 0.0.0.0 --port 8080