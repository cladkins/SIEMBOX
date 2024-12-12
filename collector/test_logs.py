import socket
import json
import time
import requests
from datetime import datetime
import logging
import sys

def send_udp_syslog(message, host='localhost', port=5514):
    """Send a syslog message via UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        print(f"Sending UDP syslog message: {message}")
        sock.sendto(message.encode(), (host, port))
        return True
    except Exception as e:
        print(f"Error sending UDP syslog: {e}")
        return False
    finally:
        sock.close()

def send_tcp_syslog(message, host='localhost', port=5514):
    """Send a syslog message via TCP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        print(f"Sending TCP syslog message: {message}")
        sock.send(message.encode() + b'\n')
        return True
    except Exception as e:
        print(f"Error sending TCP syslog: {e}")
        return False
    finally:
        sock.close()

def send_http_log(message, host='localhost', port=8000):
    """Send a log message via HTTP API."""
    url = f'http://{host}:{port}/logs'
    data = {
        'source': 'test_script',
        'timestamp': datetime.now().isoformat(),
        'level': 'INFO',
        'message': message,
        'metadata': {'test': True}
    }
    try:
        print(f"Sending HTTP log message: {message}")
        response = requests.post(url, json=data)
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending HTTP log: {e}")
        return False

def check_log_file():
    """Check if logs are being written to the file."""
    try:
        # Updated to use the correct file path
        filename = "/var/log/collector/syslog.json"
        with open(filename, 'r') as f:
            lines = f.readlines()
            print(f"\nFound {len(lines)} log entries in {filename}")
            for line in lines[-5:]:  # Show last 5 entries
                try:
                    entry = json.loads(line)
                    print(f"Log entry: {json.dumps(entry, indent=2)}")
                except json.JSONDecodeError:
                    print(f"Invalid JSON: {line}")
    except FileNotFoundError:
        print(f"Log file not found. Make sure you're running this inside the collector container.")
    except Exception as e:
        print(f"Error reading log file: {e}")

def verify_log_forwarding(log_id, host='localhost', port=8080, max_retries=5):
    """Verify that a log was successfully forwarded to the API."""
    url = f'http://{host}:{port}/api/logs'
    for attempt in range(max_retries):
        try:
            response = requests.get(url, params={'id': log_id})
            if response.status_code == 200:
                logs = response.json()
                if logs:
                    print(f"Log successfully forwarded to API")
                    return True
            time.sleep(1)  # Wait before retry
        except Exception as e:
            print(f"Error verifying log forwarding: {e}")
        print(f"Retry {attempt + 1}/{max_retries}")
    return False

def check_api_logs(host='localhost', port=8080):
    """Check if logs are appearing in the API."""
    url = f'http://{host}:{port}/api/logs'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            logs = response.json()
            print(f"\nFound {len(logs)} logs in API")
            for log in logs[:5]:  # Show first 5 entries
                print(f"API Log: {json.dumps(log, indent=2)}")
        else:
            print(f"Error getting logs from API: {response.status_code}")
    except Exception as e:
        print(f"Error checking API logs: {e}")

def check_collector_health(host='localhost', port=8000):
    """Check the health of the collector service."""
    url = f'http://{host}:{port}/health'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            health_data = response.json()
            print("\nCollector Health Status:")
            print(json.dumps(health_data, indent=2))
            return health_data['status'] == 'healthy'
        else:
            print(f"Error checking collector health: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error checking collector health: {e}")
        return False

def main():
    print("Starting log test...")
    
    # Check collector health first
    if not check_collector_health():
        print("Collector service is not healthy. Aborting tests.")
        return
    
    # Test messages with unique IDs
    test_id = int(time.time())
    messages = [
        f"Test UDP syslog message {test_id}",
        f"Test TCP syslog message {test_id}",
        f"Test HTTP log message {test_id}"
    ]
    
    # Send test messages
    for msg in messages:
        if "UDP" in msg:
            send_udp_syslog(msg)
        elif "TCP" in msg:
            send_tcp_syslog(msg)
        else:
            send_http_log(msg)
        time.sleep(1)  # Wait between messages
    
    print("\nWaiting 5 seconds for logs to be processed...")
    time.sleep(5)
    
    # Check results
    print("\nChecking log file...")
    check_log_file()
    
    print("\nChecking API logs...")
    check_api_logs()
    
    # Verify log forwarding for the test messages
    print("\nVerifying log forwarding...")
    verify_log_forwarding(str(test_id))

if __name__ == "__main__":
    main()