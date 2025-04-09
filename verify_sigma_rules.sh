#!/bin/bash

# This script verifies that Sigma rules are being processed against logs
# by sending test logs and checking the detection service logs.

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Verifying Sigma Rule Processing ===${NC}"

# Step 1: Check if the detection service is running
echo -e "\n${YELLOW}Step 1: Checking if the detection service is running...${NC}"
if docker-compose ps | grep -q "detection.*Up"; then
    echo -e "${GREEN}Detection service is running.${NC}"
else
    echo -e "${RED}Detection service is not running. Please start it with:${NC}"
    echo -e "  docker-compose up -d detection"
    exit 1
fi

# Step 2: Send test logs
echo -e "\n${YELLOW}Step 2: Sending test logs...${NC}"
echo -e "${YELLOW}Running simple_test_sigma.py...${NC}"
./simple_test_sigma.py

# Step 3: Wait a moment for logs to be processed
echo -e "\n${YELLOW}Step 3: Waiting for logs to be processed...${NC}"
sleep 5

# Step 4: Check detection service logs for rule matching
echo -e "\n${YELLOW}Step 4: Checking detection service logs for rule matching...${NC}"
echo -e "${YELLOW}Fetching recent logs from detection service...${NC}"
LOGS=$(docker-compose logs --tail=100 detection)

# Check for rule matching logs
if echo "$LOGS" | grep -q "Rule.*match"; then
    echo -e "${GREEN}Found rule matching logs!${NC}"
    echo -e "${YELLOW}Here are the matching log entries:${NC}"
    echo "$LOGS" | grep -i "Rule.*match" | tail -n 10
else
    echo -e "${RED}No rule matching logs found.${NC}"
    echo -e "${YELLOW}This could indicate that:${NC}"
    echo -e "  1. The rules are not loaded correctly"
    echo -e "  2. The rules are not enabled"
    echo -e "  3. The test logs don't match any rules"
    echo -e "  4. The rule matching is not working correctly"
fi

# Step 5: Check for alerts
echo -e "\n${YELLOW}Step 5: Checking for alerts...${NC}"
ALERTS=$(curl -s http://localhost:8000/api/alerts)
if [ $? -eq 0 ] && [ -n "$ALERTS" ]; then
    echo -e "${GREEN}Found alerts!${NC}"
    echo -e "${YELLOW}Number of alerts: $(echo $ALERTS | grep -o '"id"' | wc -l)${NC}"
else
    echo -e "${RED}No alerts found or API not accessible.${NC}"
    echo -e "${YELLOW}Check if the API is running and accessible.${NC}"
fi

echo -e "\n${GREEN}Verification complete!${NC}"
echo -e "${YELLOW}To further verify, check the Detections page in the UI.${NC}"