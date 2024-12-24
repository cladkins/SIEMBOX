#!/bin/bash

# Function to wait for PostgreSQL to be ready
wait_for_postgres() {
    echo "Waiting for PostgreSQL to be ready..."
    until pg_isready -h ${POSTGRES_HOST} -p ${POSTGRES_PORT} -U ${POSTGRES_USER}; do
        echo "PostgreSQL is unavailable - sleeping"
        sleep 1
    done
    echo "PostgreSQL is ready!"
}

# Wait for PostgreSQL
wait_for_postgres

# Add a small delay to ensure PostgreSQL is fully ready
echo "Waiting for PostgreSQL to complete initialization..."
sleep 5

# Run database migration
echo "Running database migration..."
if python migrations/create_vps_tables.py; then
    echo "Database migration completed successfully"
else
    echo "Database migration failed"
    exit 1
fi

# Start the application
echo "Starting VPS Audit service..."
exec uvicorn main:app --host 0.0.0.0 --port 8004