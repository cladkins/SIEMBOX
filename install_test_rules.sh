#!/bin/bash

# This script installs the test Sigma rules into the appropriate directories
# in the rules structure.

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Define paths
RULES_DIR="/app/rules"
TEST_RULES_DIR="./test_rules"
WINDOWS_RULES_DIR="${RULES_DIR}/rules/windows/process_creation"
LINUX_RULES_DIR="${RULES_DIR}/rules/linux/auditd"
WEB_RULES_DIR="${RULES_DIR}/rules/web/webserver"

# Create test rules directory if it doesn't exist
mkdir -p ${TEST_RULES_DIR}

# Copy test rules to the test directory
echo -e "${YELLOW}Copying test rules to ${TEST_RULES_DIR}...${NC}"
cp test_sigma_rule.yml ${TEST_RULES_DIR}/
cp test_linux_auth_rule.yml ${TEST_RULES_DIR}/
cp test_web_attack_rule.yml ${TEST_RULES_DIR}/
echo -e "${GREEN}Test rules copied to ${TEST_RULES_DIR}${NC}"

# Check if we're running in Docker
if [ -d "$RULES_DIR" ]; then
    echo -e "${YELLOW}Installing test rules into Sigma rules directory...${NC}"
    
    # Create directories if they don't exist
    mkdir -p ${WINDOWS_RULES_DIR}
    mkdir -p ${LINUX_RULES_DIR}
    mkdir -p ${WEB_RULES_DIR}
    
    # Copy rules to appropriate directories
    cp test_sigma_rule.yml ${WINDOWS_RULES_DIR}/test_suspicious_powershell.yml
    cp test_linux_auth_rule.yml ${LINUX_RULES_DIR}/test_failed_ssh_auth.yml
    cp test_web_attack_rule.yml ${WEB_RULES_DIR}/test_command_injection.yml
    
    echo -e "${GREEN}Test rules installed into Sigma rules directory${NC}"
    echo -e "${YELLOW}Rules installed at:${NC}"
    echo -e "  - ${WINDOWS_RULES_DIR}/test_suspicious_powershell.yml"
    echo -e "  - ${LINUX_RULES_DIR}/test_failed_ssh_auth.yml"
    echo -e "  - ${WEB_RULES_DIR}/test_command_injection.yml"
    
    # Restart detection service to reload rules
    echo -e "${YELLOW}To apply the rules, you may need to restart the detection service:${NC}"
    echo -e "  docker-compose restart detection"
else
    echo -e "${RED}Sigma rules directory not found at ${RULES_DIR}${NC}"
    echo -e "${YELLOW}This script should be run inside the Docker container or with the rules directory mounted.${NC}"
    echo -e "${YELLOW}You can manually copy the rules to the appropriate directories in your Sigma rules repository.${NC}"
fi

echo -e "${GREEN}Done!${NC}"