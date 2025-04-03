#!/usr/bin/env python3
import requests
import json
import sys

# Test data that matches the CreateLogRequest model
test_log = {
    "source": "test_script",
    "message": "Test log message from script",
    "level": "INFO",
    "log_metadata": {
        "test_field": "test_value",
        "hostname": "test_host"
    }
}

# API endpoint
url = "http://localhost:8080/api/logs"

# Print the JSON that will be sent
print("Sending JSON:")
print(json.dumps(test_log, indent=2))

# Send the request
headers = {"Content-Type": "application/json"}
response = requests.post(url, json=test_log, headers=headers)

# Print the results
print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")

# If successful, print a confirmation
if response.status_code == 200 or response.status_code == 201:
    print("Successfully sent log to API!")
else:
    print("Failed to send log to API.")
    
    # If we got a 422 error, print more details
    if response.status_code == 422:
        print("\nDetailed error information:")
        try:
            error_details = response.json()
            print(json.dumps(error_details, indent=2))
        except:
            print("Could not parse error details.")