#!/bin/bash

# This script uses docker exec to directly check Sigma rule processing in the detection container

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Checking Sigma Rule Processing ===${NC}"

# Find the detection container
CONTAINER=$(docker ps | grep detection | awk '{print $1}')

if [ -z "$CONTAINER" ]; then
    echo -e "${RED}Detection container not found. Make sure it's running.${NC}"
    exit 1
fi

echo -e "${GREEN}Found detection container: $CONTAINER${NC}"

# Create a simple Python script to check rules
echo -e "${YELLOW}Creating a Python script to check rules...${NC}"

cat > check_rules.py << 'EOF'
#!/usr/bin/env python3
import sys
import json
import os

# Try to import from the detection service
try:
    from main import sigma_rules, match_rule, match_ocsf_rule
    print(f"Successfully imported from detection service")
except ImportError as e:
    print(f"Error importing from detection service: {e}")
    sys.exit(1)

def print_rule_info():
    """Print information about loaded rules."""
    if not sigma_rules:
        print("No Sigma rules are loaded!")
        return False
    
    enabled_rules = [r for r in sigma_rules if r.enabled]
    
    print(f"\nTotal rules loaded: {len(sigma_rules)}")
    print(f"Enabled rules: {len(enabled_rules)}")
    print(f"Disabled rules: {len(sigma_rules) - len(enabled_rules)}")
    
    # Print categories
    categories = {}
    for rule in sigma_rules:
        cat = rule.category or "uncategorized"
        categories[cat] = categories.get(cat, 0) + 1
    
    print("\nRules by category:")
    for cat, count in sorted(categories.items()):
        print(f"  {cat}: {count}")
    
    # Print some enabled rules
    if enabled_rules:
        print("\nSample of enabled rules:")
        for rule in enabled_rules[:5]:  # Show up to 5 enabled rules
            print(f"  - {rule.id}: {rule.title} ({rule.level})")
    
    return len(enabled_rules) > 0

def test_rule_matching():
    """Test if rules match sample logs."""
    # Create a sample log that should match a rule
    sample_logs = [
        # PowerShell encoded command
        {
            "message": "New Process: powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA",
            "class_name": "Process",
            "category_name": "Process Activity",
            "raw_event": {
                "process": "powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA",
                "event_id": 4688
            }
        },
        # Failed SSH login
        {
            "message": "Failed password for root from 192.168.1.100 port 12345 ssh2",
            "class_name": "Authentication",
            "category_name": "Authentication",
            "raw_event": {
                "program": "sshd",
                "source": "auth"
            }
        },
        # Web command injection
        {
            "message": "192.168.1.100 - - [09/Apr/2025:10:00:00 +0000] \"GET /admin/config.php?cmd=whoami HTTP/1.1\" 200 287",
            "class_name": "HTTP Activity",
            "category_name": "Network Activity",
            "raw_event": {
                "url_path": "/admin/config.php?cmd=whoami",
                "source": "apache"
            }
        }
    ]
    
    print("\nTesting rule matching with sample logs:")
    
    for i, log in enumerate(sample_logs):
        print(f"\nTesting log #{i+1}: {log['message'][:50]}...")
        
        matched_rules = []
        for rule in sigma_rules:
            if not rule.enabled:
                continue
                
            if match_ocsf_rule(rule, log):
                matched_rules.append(rule)
        
        if matched_rules:
            print(f"  ✅ Matched {len(matched_rules)} rules:")
            for rule in matched_rules:
                print(f"     - {rule.id}: {rule.title}")
        else:
            print(f"  ❌ No rules matched this log")

if __name__ == "__main__":
    print("Checking Sigma rules in detection service...")
    
    if print_rule_info():
        test_rule_matching()
    else:
        print("\nNo enabled rules found. Please enable some rules and try again.")
EOF

# Copy the script to the container
echo -e "${YELLOW}Copying script to container...${NC}"
docker cp check_rules.py $CONTAINER:/app/

# Make the script executable
echo -e "${YELLOW}Making script executable...${NC}"
docker exec $CONTAINER chmod +x /app/check_rules.py

# Run the script in the container
echo -e "${YELLOW}Running script in container...${NC}"
docker exec -it $CONTAINER python /app/check_rules.py

# Clean up
echo -e "${YELLOW}Cleaning up...${NC}"
rm check_rules.py

echo -e "${GREEN}Done!${NC}"