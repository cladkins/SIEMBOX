#!/usr/bin/env python3
import requests
import json
import time
import random
import uuid
from datetime import datetime

# Configuration
API_URL = "http://localhost:8000/api/logs/ocsf"
NUM_LOGS = 5  # Number of logs to generate per type

def generate_unique_id():
    """Generate a unique ID for each log."""
    return str(uuid.uuid4())

def generate_linux_auth_log(should_match=True):
    """Generate a Linux auth log that should/shouldn't match common Sigma rules."""
    # This should match rules for failed SSH logins
    username = random.choice(["root", "admin", "user", "test"])
    source_ip = f"192.168.1.{random.randint(2, 254)}"
    
    if should_match:
        # This pattern should match common Sigma rules for failed SSH logins
        message = f"Failed password for {username} from {source_ip} port {random.randint(30000, 65000)} ssh2"
    else:
        # This pattern should not match
        message = f"Accepted password for {username} from {source_ip} port {random.randint(30000, 65000)} ssh2"
    
    # Create the OCSF log
    log = {
        "time": datetime.now().isoformat(),
        "class_uid": 3002,
        "class_name": "Authentication",
        "category_uid": 3,
        "category_name": "Authentication",
        "activity_id": 3002,
        "activity_name": "Logon",
        "severity": "medium",
        "severity_id": 50,
        "message": message,
        "src_endpoint": {
            "ip": source_ip,
            "hostname": f"host-{source_ip.split('.')[-1]}"
        },
        "dst_endpoint": {
            "ip": "10.0.0.1",
            "hostname": "server"
        },
        "raw_event": {
            "original_message": message,
            "source": "auth",
            "program": "sshd",
            "timestamp": datetime.now().isoformat()
        }
    }
    
    return log

def generate_windows_event_log(should_match=True):
    """Generate a Windows event log that should/shouldn't match common Sigma rules."""
    username = random.choice(["Administrator", "SYSTEM", "Guest", "User"])
    source_ip = f"192.168.1.{random.randint(2, 254)}"
    
    if should_match:
        # This pattern should match common Sigma rules for suspicious PowerShell commands
        command = "powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEEAQQBBAEEAQQBBAEEAQQBLAHoAVgB5AFIAWQB1AHIATQBCAEEARgA5AHoAVgBzAEkAQQBBAD0AIgApACkAOwBJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAegBpAHAAUwB0AHIAZQBhAG0AKAAkAHMALABbAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6AEQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACkALgBSAGUAYQBkAFQAbwBFAG4AZAAoACkA"
        event_id = 4688  # Process creation
    else:
        # This pattern should not match
        command = "notepad.exe C:\\Users\\User\\Documents\\notes.txt"
        event_id = 4688  # Process creation
    
    # Create the OCSF log
    log = {
        "time": datetime.now().isoformat(),
        "class_uid": 3002,
        "class_name": "Process",
        "category_uid": 3,
        "category_name": "Process Activity",
        "activity_id": 3002,
        "activity_name": "Process Creation",
        "severity": "medium",
        "severity_id": 50,
        "message": f"New Process: {command}",
        "src_endpoint": {
            "ip": source_ip,
            "hostname": f"DESKTOP-{random.randint(10000, 99999)}"
        },
        "raw_event": {
            "original_message": f"New Process: {command}",
            "source": "Microsoft-Windows-Security-Auditing",
            "event_id": event_id,
            "user": username,
            "process": command,
            "timestamp": datetime.now().isoformat()
        }
    }
    
    return log

def generate_web_log(should_match=True):
    """Generate a web server log that should/shouldn't match common Sigma rules."""
    source_ip = f"192.168.1.{random.randint(2, 254)}"
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    
    if should_match:
        # This pattern should match common Sigma rules for web attacks
        path = "/admin/config.php?cmd=whoami"  # Command injection attempt
        status_code = 403
    else:
        # This pattern should not match
        path = "/index.html"
        status_code = 200
    
    # Create the OCSF log
    log = {
        "time": datetime.now().isoformat(),
        "class_uid": 4001,
        "class_name": "HTTP Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": 4001,
        "activity_name": "HTTP Request",
        "severity": "medium",
        "severity_id": 50,
        "message": f"{source_ip} - - [{datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')}] \"GET {path} HTTP/1.1\" {status_code} 287",
        "src_endpoint": {
            "ip": source_ip
        },
        "dst_endpoint": {
            "ip": "10.0.0.2",
            "hostname": "webserver"
        },
        "raw_event": {
            "original_message": f"{source_ip} - - [{datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')}] \"GET {path} HTTP/1.1\" {status_code} 287",
            "source": "apache",
            "http_method": "GET",
            "url_path": path,
            "status_code": status_code,
            "user_agent": user_agent,
            "timestamp": datetime.now().isoformat()
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
    
    # Send Linux auth logs
    print("\nSending Linux auth logs that should match Sigma rules...")
    for i in range(NUM_LOGS):
        log = generate_linux_auth_log(should_match=True)
        send_log(log)
        time.sleep(1)  # Wait 1 second between logs
    
    print("\nSending Linux auth logs that should NOT match Sigma rules...")
    for i in range(NUM_LOGS):
        log = generate_linux_auth_log(should_match=False)
        send_log(log)
        time.sleep(1)  # Wait 1 second between logs
    
    # Send Windows event logs
    print("\nSending Windows event logs that should match Sigma rules...")
    for i in range(NUM_LOGS):
        log = generate_windows_event_log(should_match=True)
        send_log(log)
        time.sleep(1)  # Wait 1 second between logs
    
    print("\nSending Windows event logs that should NOT match Sigma rules...")
    for i in range(NUM_LOGS):
        log = generate_windows_event_log(should_match=False)
        send_log(log)
        time.sleep(1)  # Wait 1 second between logs
    
    # Send web logs
    print("\nSending web logs that should match Sigma rules...")
    for i in range(NUM_LOGS):
        log = generate_web_log(should_match=True)
        send_log(log)
        time.sleep(1)  # Wait 1 second between logs
    
    print("\nSending web logs that should NOT match Sigma rules...")
    for i in range(NUM_LOGS):
        log = generate_web_log(should_match=False)
        send_log(log)
        time.sleep(1)  # Wait 1 second between logs
    
    print("\nDone! Check the detection service logs and UI for alerts.")

if __name__ == "__main__":
    main()