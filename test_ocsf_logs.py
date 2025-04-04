#!/usr/bin/env python3
import requests
import json
import sys
from datetime import datetime

# Test data that matches the OCSF log format
test_ocsf_log = {
    "activity_id": 5001,
    "activity_name": "User Authentication",
    "category_uid": 3,
    "category_name": "Identity & Access Management",
    "class_uid": 5000,
    "class_name": "Authentication",
    "time": datetime.utcnow().isoformat(),
    "severity": "Informational",
    "severity_id": 40,
    "status": "Success",
    "status_id": 1,
    "message": "Test OCSF log message from script",
    "src_endpoint": {
        "hostname": "test-host",
        "ip": "192.168.1.100",
        "port": "22"
    },
    "device": {
        "product": {
            "name": "SIEMBox",
            "vendor_name": "SIEMBox"
        }
    },
    "raw_event": {
        "source": "test_script",
        "level": "INFO",
        "log_metadata": {
            "test_field": "test_value"
        }
    }
}

# API endpoint
url = "http://localhost:8080/api/ocsf-logs"

# Print the JSON that will be sent
print("Sending OCSF JSON:")
print(json.dumps(test_ocsf_log, indent=2))

# Send the request
headers = {"Content-Type": "application/json"}
response = requests.post(url, json=test_ocsf_log, headers=headers)

# Print the results
print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")

# If successful, print a confirmation
if response.status_code == 200 or response.status_code == 201:
    print("Successfully sent OCSF log to API!")
    
    # Now try to get the logs
    get_url = "http://localhost:8080/api/ocsf-logs"
    get_response = requests.get(get_url)
    print(f"\nGET Status Code: {get_response.status_code}")
    
    if get_response.status_code == 200:
        logs = get_response.json()
        print(f"Retrieved {logs.get('total', 0)} OCSF logs")
        if logs.get('logs'):
            print("First log:")
            print(json.dumps(logs['logs'][0], indent=2))
    else:
        print(f"Failed to retrieve OCSF logs: {get_response.text}")
else:
    print("Failed to send OCSF log to API.")
    
    # If we got a 422 error, print more details
    if response.status_code == 422:
        print("\nDetailed error information:")
        try:
            error_details = response.json()
            print(json.dumps(error_details, indent=2))
        except:
            print("Could not parse error details.")