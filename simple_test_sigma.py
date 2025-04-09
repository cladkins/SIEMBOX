#!/usr/bin/env python3
import requests
import json
import time
import random
from datetime import datetime

# Configuration
API_URL = "http://localhost:8000/api/logs/ocsf"
NUM_LOGS = 3  # Number of logs to generate per type

def generate_powershell_log(should_match=True):
    """Generate a Windows PowerShell log that should/shouldn't match our test rule."""
    timestamp = datetime.now().isoformat()
    
    if should_match:
        # This should match our test rule for PowerShell encoded commands
        command = "powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA"
    else:
        # This should not match
        command = "powershell.exe Get-Process"
    
    # Create the OCSF log
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
    
    # Create the OCSF log
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
    
    # Create the OCSF log
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

def send_log(log):
    """Send a log to the API."""
    try:
        response = requests.post(API_URL, json=log)
        if response.status_code == 200:
            print(f"Log sent successfully: {log['message'][:100]}...")
            return True
        else:
            print(f"Failed to send log: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"Error sending log: {str(e)}")
        return False

def main():
    print("=== Testing Sigma Rule Matching ===")
    
    # Send PowerShell logs
    print("\nSending PowerShell logs that should match our test rule...")
    for i in range(NUM_LOGS):
        log = generate_powershell_log(should_match=True)
        send_log(log)
        time.sleep(1)
    
    # Send SSH logs
    print("\nSending SSH logs that should match our test rule...")
    for i in range(NUM_LOGS):
        log = generate_ssh_log(should_match=True)
        send_log(log)
        time.sleep(1)
    
    # Send web logs
    print("\nSending web logs that should match our test rule...")
    for i in range(NUM_LOGS):
        log = generate_web_log(should_match=True)
        send_log(log)
        time.sleep(1)
    
    print("\nDone! Check the detection service logs and UI for alerts.")
    print("If no alerts appear, make sure the test rules are installed and enabled.")

if __name__ == "__main__":
    main()