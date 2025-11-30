# SIEMBox Community Parsers

This document contains community-contributed log parsers for SIEMBox. These parsers can be imported into your SIEMBox instance to parse various types of logs.

## Table of Contents
- [Ubiquiti UniFi](#ubiquiti-unifi)
  - [Firewall Logs](#unifi-firewall)
  - [IDS/IPS Logs](#unifi-idsips)

---

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
