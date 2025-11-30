# SIEMBox Community Parsers

This document contains community-contributed log parsers for SIEMBox. These parsers can be imported into your SIEMBox instance to parse various types of logs.

## Table of Contents
- [Built-in Parsers](#built-in-parsers)
  - [SSH Authentication](#ssh-authentication)
  - [Apache/Nginx Access Log](#apachenginx-access-log)
  - [Linux Sudo](#linux-sudo)
  - [Generic Syslog](#generic-syslog)
  - [JSON Parser](#json-parser)
- [Community Parsers](#community-parsers)
  - [Ubiquiti UniFi](#ubiquiti-unifi)
    - [Firewall Logs](#unifi-firewall)
    - [IDS/IPS Logs](#unifi-idsips)

---

## Built-in Parsers

These parsers are automatically included with every SIEMBox installation.

### SSH Authentication

Parses SSH authentication logs for both successful and failed login attempts.

**Configuration:**
- **Name:** `SSH Authentication`
- **Description:** `Parses SSH authentication logs (success and failure)`
- **Parser Type:** `Regex`
- **Priority:** `10`

**Pattern:**
```regex
^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+sshd\[(?<pid>\d+)\]:\s+(?<event>Failed password|Accepted password|Accepted publickey)\s+for\s+(?<user>\S+)\s+from\s+(?<src_ip>[\d.]+)\s+port\s+(?<src_port>\d+)
```

**Field Mappings (Named Groups):**
| Field Name | Description |
|------------|-------------|
| `timestamp` | Event timestamp |
| `hostname` | Server hostname |
| `pid` | SSH daemon process ID |
| `event` | Event type (Failed/Accepted password/publickey) |
| `user` | Username attempting authentication |
| `source_ip` | Source IP address |
| `source_port` | Source port number |

**Example Log:**
```
Nov 29 19:30:15 server1 sshd[12345]: Failed password for root from 192.168.1.100 port 54321
```

**Parsed Fields:**
```json
{
  "timestamp": "Nov 29 19:30:15",
  "hostname": "server1",
  "pid": "12345",
  "event": "Failed password",
  "user": "root",
  "source_ip": "192.168.1.100",
  "source_port": "54321"
}
```

**Use Cases:**
- Detect brute force attacks
- Monitor failed login attempts
- Track root login attempts
- Audit successful SSH connections

---

### Apache/Nginx Access Log

Parses standard Apache and Nginx combined access log format.

**Configuration:**
- **Name:** `Apache/Nginx Access Log`
- **Description:** `Parses standard Apache/Nginx access logs`
- **Parser Type:** `Regex`
- **Priority:** `20`

**Pattern:**
```regex
^(?<client_ip>[\d.]+)\s+-\s+-\s+\[(?<timestamp>[^\]]+)\]\s+"(?<method>\S+)\s+(?<path>\S+)\s+(?<protocol>[^"]+)"\s+(?<status>\d+)\s+(?<size>\d+)
```

**Field Mappings (Named Groups):**
| Field Name | Description |
|------------|-------------|
| `client_ip` | Client IP address |
| `timestamp` | Request timestamp |
| `method` | HTTP method (GET/POST/etc) |
| `path` | Request path/URI |
| `protocol` | HTTP protocol version |
| `status_code` | HTTP status code |
| `response_size` | Response size in bytes |

**Example Log:**
```
192.168.1.50 - - [29/Nov/2025:19:45:23 +0000] "GET /api/users HTTP/1.1" 200 1234
```

**Parsed Fields:**
```json
{
  "client_ip": "192.168.1.50",
  "timestamp": "29/Nov/2025:19:45:23 +0000",
  "method": "GET",
  "path": "/api/users",
  "protocol": "HTTP/1.1",
  "status_code": "200",
  "response_size": "1234"
}
```

**Use Cases:**
- Detect directory scanning (multiple 404s)
- Monitor server errors (5xx codes)
- Track API usage patterns
- Identify suspicious paths

---

### Linux Sudo

Parses Linux sudo command execution logs.

**Configuration:**
- **Name:** `Linux Sudo`
- **Description:** `Parses sudo command execution logs`
- **Parser Type:** `Regex`
- **Priority:** `15`

**Pattern:**
```regex
^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+sudo:\s+(?<user>\S+)\s+:\s+TTY=(?<tty>\S+)\s+;\s+PWD=(?<pwd>\S+)\s+;\s+USER=(?<target_user>\S+)\s+;\s+COMMAND=(?<command>.+)$
```

**Field Mappings (Named Groups):**
| Field Name | Description |
|------------|-------------|
| `timestamp` | Event timestamp |
| `hostname` | Server hostname |
| `user` | User executing sudo |
| `tty` | Terminal identifier |
| `working_dir` | Current working directory |
| `target_user` | User being impersonated |
| `command` | Command being executed |

**Example Log:**
```
Nov 29 20:15:30 server1 sudo: john : TTY=/dev/pts/1 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/apt update
```

**Parsed Fields:**
```json
{
  "timestamp": "Nov 29 20:15:30",
  "hostname": "server1",
  "user": "john",
  "tty": "/dev/pts/1",
  "working_dir": "/home/john",
  "target_user": "root",
  "command": "/usr/bin/apt update"
}
```

**Use Cases:**
- Monitor privilege escalation
- Track root command execution
- Audit administrative actions
- Detect unauthorized sudo usage

---

### Generic Syslog

Fallback parser for standard RFC 3164 syslog format. This parser has the lowest priority (1000) and catches any logs that don't match specific parsers.

**Configuration:**
- **Name:** `Generic Syslog`
- **Description:** `Fallback parser for standard syslog format`
- **Parser Type:** `Regex`
- **Priority:** `1000`

**Pattern:**
```regex
^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+(?<process>\S+?)(?:\[(?<pid>\d+)\])?:\s+(?<message>.+)$
```

**Field Mappings (Named Groups):**
| Field Name | Description |
|------------|-------------|
| `timestamp` | Event timestamp |
| `hostname` | Server hostname |
| `process` | Process name |
| `pid` | Process ID (optional) |
| `message` | Log message |

**Example Log:**
```
Nov 29 20:30:45 server1 cron[9876]: (root) CMD (/usr/bin/backup.sh)
```

**Parsed Fields:**
```json
{
  "timestamp": "Nov 29 20:30:45",
  "hostname": "server1",
  "process": "cron",
  "pid": "9876",
  "message": "(root) CMD (/usr/bin/backup.sh)"
}
```

**Use Cases:**
- Catch-all for unmatched syslog messages
- General system log monitoring
- Baseline for creating specific parsers

---

### JSON Parser

Automatically parses logs that are already in JSON format. No field mappings required - all JSON fields are extracted automatically.

**Configuration:**
- **Name:** `JSON Parser`
- **Description:** `Parses logs already in JSON format`
- **Parser Type:** `JSON`
- **Priority:** `50`

**Example Log:**
```json
{"timestamp":"2025-11-29T20:45:00Z","level":"error","service":"api","message":"Database connection failed","user_id":123}
```

**Parsed Fields:**
All JSON fields are automatically extracted:
```json
{
  "timestamp": "2025-11-29T20:45:00Z",
  "level": "error",
  "service": "api",
  "message": "Database connection failed",
  "user_id": 123
}
```

**Use Cases:**
- Modern application logs
- Cloud service logs
- Container logs (Docker, Kubernetes)
- API gateway logs

---

## Community Parsers

## Ubiquiti UniFi

### UniFi Firewall

Parses Ubiquiti UniFi (UCG-Max) firewall rule logs.

**Configuration:**
- **Name:** `Ubiquiti UniFi Firewall`
- **Description:** `Parser for Ubiquiti UniFi router firewall logs`
- **Parser Type:** `Regex`
- **Priority:** `50`

**Pattern:**
```regex
\[([^\]]+)\].*?DESCR="([^"]+)".*?IN=(\S+).*?OUT=(\S*).*?SRC=([\d\.]+).*?DST=([\d\.]+).*?PROTO=(\w+)
```

**Field Mappings:**
| Group | Field Name | Description |
|-------|------------|-------------|
| 1 | `rule_name` | Firewall rule name |
| 2 | `rule_description` | Rule description |
| 3 | `in_interface` | Input network interface |
| 4 | `out_interface` | Output network interface |
| 5 | `source_ip` | Source IP address |
| 6 | `dest_ip` | Destination IP address |
| 7 | `protocol` | Network protocol (TCP/UDP/etc) |

**Example Log:**
```
<13>Nov 29 19:44:35 UCG-Max [LAN_LOCAL-RET-2147483647] DESCR="no rule description" IN=br0 OUT= MAC=01:00:5e:00:00:fb:5e:07:7d:96:02:d7:08:00 SRC=192.168.1.158 DST=224.0.0.251 LEN=473 TOS=00 PREC=0x00 TTL=255 ID=62191 PROTO=UDP SPT=5353 DPT=5353 LEN=453 MARK=1a0000
```

**Parsed Fields:**
```json
{
  "rule_name": "LAN_LOCAL-RET-2147483647",
  "rule_description": "no rule description",
  "in_interface": "br0",
  "out_interface": "",
  "source_ip": "192.168.1.158",
  "dest_ip": "224.0.0.251",
  "protocol": "UDP"
}
```

---

### UniFi IDS/IPS

Parses Ubiquiti UniFi IDS/IPS daemon event logs.

**Configuration:**
- **Name:** `Ubiquiti UniFi IDS/IPS`
- **Description:** `Parser for Ubiquiti UniFi IDS/IPS daemon logs`
- **Parser Type:** `Regex`
- **Priority:** `50`

**Pattern:**
```regex
ubnt-idsips-daemon\[\d+\]:\s+[\d-]+T[\d:.-]+\s+(\w+):\s+(.+?):\s+ipset\[(\w+)\]\s+(\w+)\s+failed\s+ip1:([\d.]+),\s+port1:(\d+),\s+ip2:([\d.]+),\s+port2:(\d+),\s+proto:(\w+)
```

**Field Mappings:**
| Group | Field Name | Description |
|-------|------------|-------------|
| 1 | `severity` | Log severity level (Warn/Error/Info) |
| 2 | `event_type` | Type of event |
| 3 | `action_type` | IPS action type |
| 4 | `action` | Action taken |
| 5 | `external_ip` | External/source IP address |
| 6 | `external_port` | External/source port |
| 7 | `internal_ip` | Internal/destination IP |
| 8 | `internal_port` | Internal/destination port |
| 9 | `protocol` | Network protocol |

**Example Log:**
```
<28>Nov 29 15:51:19 UCG-Max UCG-Max ubnt-idsips-daemon[2402]: 2025-11-29T15:51:19.543-0600 Warn: error handling event: ipset[ips] add failed ip1:156.218.17.179, port1:52686, ip2:192.168.1.194, port2:80, proto:tcp, err1:ipset v7.10: Element cannot be added to the set: it's already added
```

**Parsed Fields:**
```json
{
  "severity": "Warn",
  "event_type": "error handling event",
  "action_type": "ips",
  "action": "add",
  "external_ip": "156.218.17.179",
  "external_port": "52686",
  "internal_ip": "192.168.1.194",
  "internal_port": "80",
  "protocol": "tcp"
}
```

---

## Contributing Parsers

Have a parser to share? Please submit a pull request with:
1. Parser configuration (name, type, pattern, field mappings)
2. Example log samples
3. Expected parsed output
4. Any relevant detection rules

### Parser Guidelines
- Use descriptive names that include the vendor/product
- Set appropriate priority (lower = higher priority)
- Include comprehensive field mappings
- Test with multiple log samples
- Document any special considerations

---

## Detection Rules

Parsers work best when paired with detection rules. Check out the [Rules Documentation](./RULES.md) for examples of rules that work with these parsers.
