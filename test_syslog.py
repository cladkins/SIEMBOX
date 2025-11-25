#!/usr/bin/env python3
"""
Simple syslog test client - sends test syslog messages to SIEM BOX
"""
import socket
import time
from datetime import datetime

SIEM_HOST = 'localhost'
SIEM_PORT = 514

def send_syslog(message, facility=16, severity=6):
    """
    Send a syslog message

    facility: 16 = local0 (default for network devices)
    severity: 6 = info
    """
    pri = (facility * 8) + severity
    timestamp = datetime.now().strftime('%b %d %H:%M:%S')
    hostname = 'test-firewall'
    tag = 'kernel'

    # RFC 3164 format
    syslog_message = f"<{pri}>{timestamp} {hostname} {tag}: {message}"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(syslog_message.encode('utf-8'), (SIEM_HOST, SIEM_PORT))
    sock.close()

    print(f"📤 Sent: {syslog_message}")

def main():
    print("=" * 60)
    print("SIEM BOX - Syslog Test Client")
    print("=" * 60)
    print(f"Target: {SIEM_HOST}:{SIEM_PORT}")
    print()

    # Test 1: Normal firewall log
    print("Test 1: Firewall BLOCK log")
    send_syslog(
        "FIREWALL: BLOCK IN=eth0 OUT= SRC=203.0.113.5 DST=192.168.1.100 PROTO=TCP SPT=54321 DPT=22",
        facility=16, severity=5  # local0.notice
    )
    time.sleep(0.5)

    # Test 2: SSH brute force simulation (send 6 to trigger detection)
    print("\nTest 2: SSH brute force attack (6 attempts)")
    for i in range(6):
        send_syslog(
            f"sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port {50000+i} ssh2",
            facility=10, severity=4  # authpriv.warning
        )
        time.sleep(0.3)

    # Test 3: Successful SSH login
    print("\nTest 3: Successful SSH login")
    send_syslog(
        "sshd[1235]: Accepted publickey for root from 192.168.1.50 port 51234 ssh2",
        facility=10, severity=6  # authpriv.info
    )
    time.sleep(0.5)

    # Test 4: High volume of firewall blocks (should trigger detection)
    print("\nTest 4: Port scan simulation (25 blocks)")
    for i in range(25):
        port = 22 + i
        send_syslog(
            f"FIREWALL: BLOCK IN=eth0 SRC=203.0.113.99 DST=192.168.1.100 PROTO=TCP DPT={port}",
            facility=16, severity=5
        )
        time.sleep(0.1)

    print("\n" + "=" * 60)
    print("✅ Test syslogs sent!")
    print()
    print("Next steps:")
    print("  1. Wait 5 seconds for detection to process")
    print("  2. Check dashboard: http://localhost:3000")
    print("  3. Go to Alerts page to see if alerts were generated")
    print("  4. Go to Logs page to see ingested syslogs")
    print()
    print("Or run: python3 test_detection_flow.py")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nMake sure SIEM BOX is running:")
        print("  docker compose up -d")
        exit(1)
