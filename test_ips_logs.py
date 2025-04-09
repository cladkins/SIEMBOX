#!/usr/bin/env python3
import requests
import json
import time
import random
from datetime import datetime

# Configuration
API_URL = "http://localhost:8000/api/logs/ocsf"
NUM_LOGS = 5  # Number of logs to generate

# IPS Alert templates
IPS_ALERTS = [
    {
        "alert_id": "1001",
        "alert_type": "Critical Threat",
        "signature": "SQL Injection Attempt",
        "src": "192.168.1.100",
        "dst": "10.0.0.5",
        "protocol": "TCP"
    },
    {
        "alert_id": "1002",
        "alert_type": "High Threat",
        "signature": "Cross-Site Scripting",
        "src": "192.168.1.101",
        "dst": "10.0.0.6",
        "protocol": "HTTP"
    },
    {
        "alert_id": "1003",
        "alert_type": "Medium Threat",
        "signature": "Port Scan",
        "src": "192.168.1.102",
        "dst": "10.0.0.7",
        "protocol": "TCP"
    },
    {
        "alert_id": "1004",
        "alert_type": "Low Threat",
        "signature": "Suspicious Connection",
        "src": "192.168.1.103",
        "dst": "10.0.0.8",
        "protocol": "UDP"
    },
    {
        "alert_id": "1005",
        "alert_type": "Critical Threat",
        "signature": "Command Injection",
        "src": "192.168.1.104",
        "dst": "10.0.0.9",
        "protocol": "HTTP"
    }
]

def generate_ips_log():
    # Select a random IPS alert template
    alert = random.choice(IPS_ALERTS)
    
    # Create the log message
    message = f"IPS Alert {alert['alert_id']}: {alert['alert_type']}. Signature {alert['signature']}. From: {alert['src']}, to: {alert['dst']}, protocol: {alert['protocol']}"
    
    # Create the OCSF log
    log = {
        "time": datetime.now().isoformat(),
        "class_uid": 7000,
        "class_name": "Security Finding",
        "category_uid": 7,
        "category_name": "Security",
        "activity_id": 7001,
        "activity_name": "Intrusion Detection",
        "severity": "high" if "High" in alert["alert_type"] or "Critical" in alert["alert_type"] else "medium",
        "severity_id": 70 if "High" in alert["alert_type"] or "Critical" in alert["alert_type"] else 50,
        "message": message,
        "src_endpoint": {
            "ip": alert["src"],
            "hostname": f"host-{alert['src'].split('.')[-1]}"
        },
        "dst_endpoint": {
            "ip": alert["dst"],
            "hostname": f"host-{alert['dst'].split('.')[-1]}"
        },
        "raw_event": {
            "original_message": message,
            "source": "ips",
            "timestamp": datetime.now().isoformat()
        }
    }
    
    return log

def send_log(log):
    try:
        response = requests.post(API_URL, json=log)
        if response.status_code == 200:
            print(f"Log sent successfully: {log['message']}")
        else:
            print(f"Failed to send log: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error sending log: {str(e)}")

def main():
    print(f"Generating {NUM_LOGS} IPS alert logs...")
    
    for i in range(NUM_LOGS):
        log = generate_ips_log()
        send_log(log)
        time.sleep(1)  # Wait 1 second between logs
    
    print("Done!")

if __name__ == "__main__":
    main()