#!/bin/bash

echo "=== System Information ==="
uname -a
cat /etc/os-release

echo "=== User Information ==="
cat /etc/passwd
echo "Sudo users:"
grep -l sudo /etc/group

echo "=== Network Information ==="
netstat -tulpn

echo "=== Service Information ==="
systemctl list-units --type=service --state=running

echo "=== File Permissions ==="
ls -la /etc/passwd /etc/shadow /etc/sudoers

echo "=== Last Logins ==="
last | head -n 10

echo "=== System Logs ==="
tail -n 20 /var/log/syslog || tail -n 20 /var/log/messages