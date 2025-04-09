#!/bin/bash

# This script copies the test_sigma_inside_container.py script to the detection container
# and runs it to test Sigma rule matching directly.

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Testing Sigma Rule Matching Inside Container ===${NC}"

# Check if the detection container is running
CONTAINER_ID=$(docker ps -q -f name=detection)
if [ -z "$CONTAINER_ID" ]; then
    echo -e "${RED}Detection container is not running.${NC}"
    echo -e "${YELLOW}Please start it with: docker-compose up -d detection${NC}"
    exit 1
fi

echo -e "${GREEN}Detection container is running with ID: $CONTAINER_ID${NC}"

# Copy the test script to the container
echo -e "${YELLOW}Copying test script to container...${NC}"
docker cp test_sigma_inside_container.py $CONTAINER_ID:/app/

# Make the script executable
echo -e "${YELLOW}Making script executable...${NC}"
docker exec $CONTAINER_ID chmod +x /app/test_sigma_inside_container.py

# Run the test script
echo -e "${YELLOW}Running test script inside container...${NC}"
docker exec $CONTAINER_ID python /app/test_sigma_inside_container.py

echo -e "\n${GREEN}Test complete!${NC}"