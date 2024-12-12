import socket
import json
import time
import requests
from datetime import datetime

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

def check_api_logs():
    """Check if logs are appearing in the API."""
    url = 'http://localhost:8080/api/logs'
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

def main():
    print("Starting external log test...")
    
    # Test messages
    messages = [
        "<34>1 {} localhost test_script - - - Test UDP syslog message".format(
            datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        ),
        "<34>1 {} localhost test_script - - - Test TCP syslog message".format(
            datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        )
    ]
    
    # Send test messages
    for msg in messages:
        # Try UDP first
        if send_udp_syslog(msg):
            print("UDP message sent successfully")
        else:
            print("UDP message failed")
        
        time.sleep(1)
        
        # Then TCP
        if send_tcp_syslog(msg):
            print("TCP message sent successfully")
        else:
            print("TCP message failed")
        
        time.sleep(1)
    
    print("\nWaiting 5 seconds for logs to be processed...")
    time.sleep(5)
    
    print("\nChecking API logs...")
    check_api_logs()

if __name__ == "__main__":
    main()