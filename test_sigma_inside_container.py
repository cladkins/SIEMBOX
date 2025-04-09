#!/usr/bin/env python3
"""
This script is designed to be run inside the detection container to test
Sigma rule matching directly without relying on external APIs.
"""
import json
import time
import random
import os
import sys
from datetime import datetime

# Import the rule matching functions directly from the detection service
try:
    from main import match_rule, match_ocsf_rule, sigma_rules
except ImportError:
    print("Error: This script must be run inside the detection container.")
    print("Run it with: docker-compose exec detection python /app/test_sigma_inside_container.py")
    sys.exit(1)

def generate_powershell_log(should_match=True):
    """Generate a Windows PowerShell log that should/shouldn't match our test rule."""
    timestamp = datetime.now().isoformat()
    
    if should_match:
        # This should match our test rule for PowerShell encoded commands
        command = "powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA"
    else:
        # This should not match
        command = "powershell.exe Get-Process"
    
    # Create the log entry
    log = {
        "time": timestamp,
        "class_uid": 3002,
        "class_name": "Process",
        "category_uid": 3,
        "category_name": "Process Activity",
        "activity_id": 3002,
        "activity_name": "Process Creation",
        "severity": "medium",
        "severity_id": 50,
        "message": f"New Process: {command}",
        "raw_event": {
            "original_message": f"New Process: {command}",
            "source": "Microsoft-Windows-Security-Auditing",
            "event_id": 4688,
            "process": command,
            "timestamp": timestamp
        }
    }
    
    return log

def generate_ssh_log(should_match=True):
    """Generate a Linux SSH log that should/shouldn't match our test rule."""
    timestamp = datetime.now().isoformat()
    username = random.choice(["root", "admin", "user"])
    source_ip = f"192.168.1.{random.randint(2, 254)}"
    
    if should_match:
        # This should match our test rule for failed SSH auth
        message = f"Failed password for {username} from {source_ip} port {random.randint(30000, 65000)} ssh2"
    else:
        # This should not match
        message = f"Accepted password for {username} from {source_ip} port {random.randint(30000, 65000)} ssh2"
    
    # Create the log entry
    log = {
        "time": timestamp,
        "class_uid": 3002,
        "class_name": "Authentication",
        "category_uid": 3,
        "category_name": "Authentication",
        "activity_id": 3002,
        "activity_name": "Logon",
        "severity": "medium",
        "severity_id": 50,
        "message": message,
        "raw_event": {
            "original_message": message,
            "source": "auth",
            "program": "sshd",
            "timestamp": timestamp
        }
    }
    
    return log

def generate_web_log(should_match=True):
    """Generate a web server log that should/shouldn't match our test rule."""
    timestamp = datetime.now().isoformat()
    source_ip = f"192.168.1.{random.randint(2, 254)}"
    
    if should_match:
        # This should match our test rule for web command injection
        path = "/admin/config.php?cmd=whoami"
    else:
        # This should not match
        path = "/index.html"
    
    # Create the log entry
    log = {
        "time": timestamp,
        "class_uid": 4001,
        "class_name": "HTTP Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": 4001,
        "activity_name": "HTTP Request",
        "severity": "medium",
        "severity_id": 50,
        "message": f"{source_ip} - - [{datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')}] \"GET {path} HTTP/1.1\" 200 287",
        "raw_event": {
            "original_message": f"{source_ip} - - [{datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')}] \"GET {path} HTTP/1.1\" 200 287",
            "source": "apache",
            "http_method": "GET",
            "url_path": path,
            "timestamp": timestamp
        }
    }
    
    return log

def test_rule_matching():
    """Test rule matching directly."""
    print("=== Testing Sigma Rule Matching ===")
    
    # Check if any rules are loaded
    if not sigma_rules:
        print("No Sigma rules are loaded. Please check the rules directory.")
        return
    
    print(f"Found {len(sigma_rules)} Sigma rules.")
    print(f"Enabled rules: {len([r for r in sigma_rules if r.enabled])}")
    
    # Print some info about the rules
    print("\nRule IDs:")
    for rule in sigma_rules:
        status = "Enabled" if rule.enabled else "Disabled"
        print(f"  - {rule.id} ({status})")
    
    # Test PowerShell logs
    print("\nTesting PowerShell logs...")
    powershell_log = generate_powershell_log(should_match=True)
    print("  PowerShell log with encoded command:")
    matched_rules = []
    for rule in sigma_rules:
        if not rule.enabled:
            continue
        if match_ocsf_rule(rule, powershell_log):
            matched_rules.append(rule.id)
    if matched_rules:
        print(f"  ✅ Matched rules: {', '.join(matched_rules)}")
    else:
        print("  ❌ No rules matched")
    
    # Test SSH logs
    print("\nTesting SSH logs...")
    ssh_log = generate_ssh_log(should_match=True)
    print("  SSH log with failed password:")
    matched_rules = []
    for rule in sigma_rules:
        if not rule.enabled:
            continue
        if match_ocsf_rule(rule, ssh_log):
            matched_rules.append(rule.id)
    if matched_rules:
        print(f"  ✅ Matched rules: {', '.join(matched_rules)}")
    else:
        print("  ❌ No rules matched")
    
    # Test web logs
    print("\nTesting web logs...")
    web_log = generate_web_log(should_match=True)
    print("  Web log with command injection:")
    matched_rules = []
    for rule in sigma_rules:
        if not rule.enabled:
            continue
        if match_ocsf_rule(rule, web_log):
            matched_rules.append(rule.id)
    if matched_rules:
        print(f"  ✅ Matched rules: {', '.join(matched_rules)}")
    else:
        print("  ❌ No rules matched")
    
    print("\nTest complete!")

if __name__ == "__main__":
    test_rule_matching()