#!/usr/bin/env python3
"""
Test script to verify the basic SIEM flow:
1. Send test logs via HTTP
2. Verify they're stored
3. Verify detections run
4. Verify alerts are created
"""
import requests
import time
from datetime import datetime
import json

BASE_URL = "http://localhost:8000/api/v1"

def login():
    """Get auth token"""
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": "admin", "password": "admin123"}
    )
    if response.status_code != 200:
        print(f"❌ Login failed: {response.text}")
        return None
    token = response.json()["access_token"]
    print("✅ Logged in successfully")
    return token

def send_test_logs(count=10):
    """Send test logs that should trigger detection rules"""
    print(f"\n📝 Sending {count} test logs...")

    # SSH brute force simulation (should trigger after 5 failed attempts)
    for i in range(count):
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "hostname": "test-server",
            "source_ip": "192.168.1.100",
            "app_name": "sshd",
            "raw_message": f"Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
            "severity": "warning",
            "log_type": "authentication",
            "fields": {
                "action": "Failed",
                "user": "admin",
                "src_ip": "192.168.1.100",
                "protocol": "ssh"
            }
        }

        response = requests.post(
            f"{BASE_URL}/logs/ingest",
            json=log_data
        )

        if response.status_code == 200:
            print(f"  ✅ Log {i+1} ingested: {response.json()['log_id']}")
        else:
            print(f"  ❌ Log {i+1} failed: {response.text}")

        time.sleep(0.5)  # Small delay between logs

    print(f"✅ Sent {count} test logs\n")

def check_logs(token):
    """Check if logs were stored"""
    print("🔍 Checking stored logs...")
    response = requests.get(
        f"{BASE_URL}/logs?limit=20",
        headers={"Authorization": f"Bearer {token}"}
    )

    if response.status_code != 200:
        print(f"❌ Failed to get logs: {response.text}")
        return 0

    data = response.json()
    log_count = data.get("total", 0)
    print(f"✅ Found {log_count} total logs in database\n")
    return log_count

def check_detection_rules(token):
    """Check active detection rules"""
    print("🔍 Checking detection rules...")
    response = requests.get(
        f"{BASE_URL}/detection/rules?enabled_only=true",
        headers={"Authorization": f"Bearer {token}"}
    )

    if response.status_code != 200:
        print(f"❌ Failed to get rules: {response.text}")
        return 0

    rules = response.json()
    print(f"✅ Found {len(rules)} enabled detection rules:")
    for rule in rules[:5]:  # Show first 5
        print(f"  - {rule['name']} ({rule['severity']}, {rule['rule_type']})")
    if len(rules) > 5:
        print(f"  ... and {len(rules) - 5} more")
    print()
    return len(rules)

def check_alerts(token):
    """Check if alerts were generated"""
    print("🚨 Checking for alerts...")
    response = requests.get(
        f"{BASE_URL}/alerts?limit=20",
        headers={"Authorization": f"Bearer {token}"}
    )

    if response.status_code != 200:
        print(f"❌ Failed to get alerts: {response.text}")
        return 0

    data = response.json()

    # Handle both array and paginated response
    if isinstance(data, dict) and "items" in data:
        alerts = data["items"]
        alert_count = data.get("total", len(alerts))
    else:
        alerts = data if isinstance(data, list) else []
        alert_count = len(alerts)

    if alert_count == 0:
        print("❌ NO ALERTS GENERATED - Detection may not be working!\n")
        return 0

    print(f"✅ Found {alert_count} alerts!")
    for alert in alerts[:5]:
        print(f"  - {alert['title']} ({alert['severity']}, {alert['status']})")
        print(f"    Triggered: {alert['triggered_at']}")
    if len(alerts) > 5:
        print(f"  ... and {len(alerts) - 5} more")
    print()
    return alert_count

def get_dashboard_stats(token):
    """Get dashboard statistics"""
    print("📊 Checking dashboard stats...")
    response = requests.get(
        f"{BASE_URL}/dashboard/stats",
        headers={"Authorization": f"Bearer {token}"}
    )

    if response.status_code != 200:
        print(f"❌ Failed to get stats: {response.text}")
        return

    stats = response.json()
    print(f"Dashboard Statistics:")
    print(f"  Total Logs: {stats.get('total_logs', 0)}")
    print(f"  Total Alerts: {stats.get('total_alerts', 0)}")
    print(f"  Open Alerts: {stats.get('open_alerts', 0)}")
    print(f"  Critical Alerts: {stats.get('critical_alerts', 0)}")
    print()

def main():
    print("=" * 60)
    print("SIEM BOX - Detection Flow Test")
    print("=" * 60)
    print()

    # Step 1: Login
    token = login()
    if not token:
        print("\n❌ TEST FAILED: Cannot login")
        return False

    time.sleep(1)

    # Step 2: Check detection rules exist
    rule_count = check_detection_rules(token)
    if rule_count == 0:
        print("\n⚠️  WARNING: No detection rules enabled")
        print("   Run this in the container:")
        print("   docker exec siembox-backend python -c \"from app.services.detection_service import detection_service; import asyncio; asyncio.run(detection_service.initialize_default_rules(None))\"")

    time.sleep(1)

    # Step 3: Send test logs
    send_test_logs(10)

    # Wait for detection to process
    print("⏳ Waiting 3 seconds for detection engine to process logs...")
    time.sleep(3)

    # Step 4: Verify logs stored
    log_count = check_logs(token)

    # Step 5: Check alerts
    alert_count = check_alerts(token)

    # Step 6: Dashboard stats
    get_dashboard_stats(token)

    # Results
    print("=" * 60)
    print("TEST RESULTS")
    print("=" * 60)

    if log_count > 0:
        print("✅ Log ingestion: WORKING")
    else:
        print("❌ Log ingestion: FAILED")

    if alert_count > 0:
        print("✅ Detection engine: WORKING")
        print("✅ Alert creation: WORKING")
        print()
        print("🎉 BASIC SIEM FLOW IS FUNCTIONAL!")
    else:
        print("❌ Detection engine: NOT WORKING or NO RULES MATCHED")
        print()
        print("⚠️  THE CORE SIEM FUNCTIONALITY MAY BE BROKEN")

    print("=" * 60)

    return log_count > 0 and alert_count > 0

if __name__ == "__main__":
    try:
        success = main()
        exit(0 if success else 1)
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Cannot connect to SIEM BOX")
        print("   Make sure it's running: docker compose up -d")
        exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
