#!/bin/bash

# Test Docker socket access and list containers for log shipping

echo "========================================="
echo "Docker Source Diagnostic"
echo "========================================="
echo ""

# Check if running inside the shipper container
if [ -f "/.dockerenv" ]; then
    echo "✓ Running inside container"
    CONTAINER_NAME="siembox-log-shipper"
else
    echo "Running on host - will test both host and container"
    CONTAINER_NAME="siembox-log-shipper"
fi

echo ""
echo "1. Testing Docker socket access..."
echo "----------------------------------------"

# Test docker command
if command -v docker &> /dev/null; then
    echo "✓ Docker CLI available"

    # Test docker ps
    if docker ps &> /dev/null; then
        echo "✓ Docker socket accessible"
        echo ""
        echo "Running containers:"
        docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
    else
        echo "✗ Docker socket NOT accessible"
        echo "  Error: $(docker ps 2>&1)"
    fi
else
    echo "✗ Docker CLI not installed"
fi

echo ""
echo "2. Testing from shipper container..."
echo "----------------------------------------"

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
    echo "✓ Shipper container is running"
    echo ""

    # Test docker access from inside container
    echo "Testing Docker CLI inside container..."
    if docker exec "$CONTAINER_NAME" docker --version &> /dev/null; then
        echo "✓ Docker CLI available in container"
    else
        echo "✗ Docker CLI not available in container"
    fi

    echo ""
    echo "Testing Docker socket access from container..."
    if docker exec "$CONTAINER_NAME" docker ps &> /dev/null; then
        echo "✓ Docker socket accessible from container"
        echo ""
        echo "Containers visible from shipper:"
        docker exec "$CONTAINER_NAME" docker ps --format "  - {{.Names}}"
    else
        echo "✗ Docker socket NOT accessible from container"
        echo "  Error: $(docker exec "$CONTAINER_NAME" docker ps 2>&1)"
        echo ""
        echo "Checking socket mount..."
        docker inspect "$CONTAINER_NAME" | jq '.[0].Mounts[] | select(.Destination == "/var/run/docker.sock")'
    fi
else
    echo "✗ Shipper container not running: $CONTAINER_NAME"
fi

echo ""
echo "3. Example Docker source configuration..."
echo "----------------------------------------"
echo ""
echo "To tail a container's logs, add a Docker source in the UI:"
echo ""
echo "  Source Type: docker"
echo "  Container Name: siembox-backend  (or any container name)"
echo "  Tag: BACKEND"
echo "  Facility: local1"
echo ""
echo "Or check the API response for existing Docker sources:"
echo ""
echo "  curl http://192.168.1.76:3001/api/shippers/config/YOUR_API_KEY | jq '.sources[] | select(.source_type == \"docker\")'"
echo ""
echo "========================================="
