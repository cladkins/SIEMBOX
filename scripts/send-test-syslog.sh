#!/bin/bash
#
# Send synthetic events to SIEMBox to verify the pipeline end to end:
# syslog receive -> header strip -> parser match -> detection -> alert.
#
#   usage: scripts/send-test-syslog.sh <siembox-host> [port]
#   e.g.   scripts/send-test-syslog.sh 192.168.1.100
#
# Part 1 (framing) reproduces the wire shape that used to break ingest: a UniFi
# gateway sends CEF with NO <PRI> and a trailing newline, and JavaScript's `$`
# (without /m) does not match before a final newline — so one stray terminator
# defeated the RFC 3164 header regex and then every $-anchored catalog parser.
# It also sends two events in ONE datagram, which UDP ingest used to store as a
# single unparsed record.
#
# Part 2 (detections) exercises five parsers and eleven detection rules, from
# low to critical, so you can confirm the rules engine is firing and see the
# alert pipeline (and any notification channels) work.
#
# Every event uses a source address in 203.0.113.0/24 (TEST-NET-3, reserved for
# documentation and never real traffic), so the test data is trivially
# identifiable and the cleanup below cannot touch a real log.

set -u

HOST="${1:?usage: scripts/send-test-syslog.sh <siembox-host> [port]}"
PORT="${2:-514}"

command -v nc >/dev/null 2>&1 || { echo "error: nc (netcat) is required" >&2; exit 1; }

TS=$(date '+%b %e %H:%M:%S')        # RFC 3164 syslog header timestamp
CLF=$(date '+%d/%b/%Y:%H:%M:%S %z') # Common Log Format, for the bracketed web fields
TAG='SIEMBOX PIPELINE TEST'
send() { nc -u -w1 "$HOST" "$PORT"; }

# --- Part 1: ingest framing -------------------------------------------------

# $1 = label (lands in the signature name), $2 = source IP, $3 = act
unifi_ips() {
  printf '%s UCG-Max CEF:0|Ubiquiti|UniFi Network|10.4.57|201|Threat Detected and Blocked|7|UNIFIcategory=Security UNIFIhost=UCG Max proto=TCP spt=22536 dpt=80 act=%s app=HTTP UNIFIrisk=medium UNIFIpolicyName=%s UNIFIpolicyType=IDS/IPS UNIFIdirection=incoming UNIFIdeviceIp=192.168.1.1 src=%s dst=198.51.100.10 UNIFIsrcRegion=US UNIFIdstZone=Internal UNIFIipsSignature=%s %s UNIFIipsSignatureId=9999999 msg=Synthetic test event for SIEMBox pipeline verification.\n' \
    "$TS" "$3" "$TAG" "$2" "$TAG" "$1"
}

# one event per datagram — the shape that used to land unparsed
unifi_ips single 203.0.113.99 blocked | send
# two events in ONE datagram — used to be stored as a single unparsed record
{ unifi_ips packed-a 203.0.113.98 blocked; unifi_ips packed-b 203.0.113.97 blocked; } | send

# --- Part 2: parsers + detections -------------------------------------------
# Each line is annotated with the rule it is expected to fire.

# AUTH-008 Root SSH Login (critical) — ssh-authentication
printf '%s srv01 sshd[4242]: Accepted password for root from 203.0.113.51 port 51234 ssh2\n' "$TS" | send

# ACCESS-001 Sudo to Root by Non-Admin (high) — linux-sudo
printf '%s srv01 sudo:  bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash\n' "$TS" | send

# PROXY-001 SQL Injection (high). Percent-encoded and lowercase, i.e. what
# sqlmap actually emits — the rule used to miss exactly this shape.
printf '%s web01 nginx: 203.0.113.52 - - [%s] "GET /product?id=-1%%20union%%20select%%201,2,3 HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n' "$TS" "$CLF" | send

# PROXY-002 Command Injection (high) — also trips PROXY-001, the ";" matches both
printf '%s web01 nginx: 203.0.113.59 - - [%s] "GET /ping?host=127.0.0.1;cat+/etc/passwd HTTP/1.1" 200 128 "-" "Mozilla/5.0"\n' "$TS" "$CLF" | send

# PROXY-003 Path Traversal (medium)
printf '%s web01 nginx: 203.0.113.54 - - [%s] "GET /static/../../../../etc/passwd HTTP/1.1" 404 152 "-" "curl/8.5.0"\n' "$TS" "$CLF" | send

# PROXY-006 HTTP Method Abuse (medium)
printf '%s web01 nginx: 203.0.113.55 - - [%s] "TRACE /debug HTTP/1.1" 405 128 "-" "curl/8.5.0"\n' "$TS" "$CLF" | send

# ACCESS-002 Unauthorized Admin Access (medium)
printf '%s web01 nginx: 203.0.113.56 - - [%s] "GET /wp-admin/index.php HTTP/1.1" 200 300 "-" "Mozilla/5.0"\n' "$TS" "$CLF" | send

# PROXY-005 Malicious User-Agent (medium) — a plain nginx COMBINED line, which
# now routes to standard-nginx-access and so actually carries a user_agent.
printf '%s web01 nginx: 203.0.113.53 - - [%s] "GET /login HTTP/1.1" 200 512 "-" "sqlmap/1.7.2#stable (http://sqlmap.org)"\n' "$TS" "$CLF" | send

# UNIFI-IPS-002 Threat NOT Blocked (high) — same envelope, act=allowed
unifi_ips not-blocked 203.0.113.57 allowed | send

# UNIFI-AUDIT-001 Controller Admin Access (medium)
printf '%s UCG-Max CEF:0|Ubiquiti|UniFi Network|10.4.57|300|Admin Login|3|UNIFIcategory=Audit UNIFIadmin=siembox-test UNIFIhost=UCG Max UNIFIdeviceIp=192.168.1.1 src=203.0.113.58 msg=Administrator siembox-test signed in.\n' "$TS" | send

cat <<EOF
sent 13 test events to $HOST:$PORT over UDP
  3 framing checks (1 single datagram + 2 packed into one)
  10 detection triggers across ssh / sudo / nginx / UniFi

Expected: all 13 events parsed (no (UNPARSED) rows) and at least 12 alerts
spanning low -> critical. Counts can run slightly higher: PROXY-002's ";"
matches the SQL-injection regex as well, and correlation rules may add their
own alert if the window already holds related activity.

Verify — parsed events, no (UNPARSED) rows:

  docker compose exec -T postgres psql -U siembox -d siembox <<'SQL'
  SELECT COALESCE(p.name,'(UNPARSED)') AS parser, COUNT(*) AS events
  FROM parsed_logs pl
  JOIN raw_logs rl ON rl.id = pl.raw_log_id
  LEFT JOIN parsers p ON p.id = pl.parser_id
  WHERE rl.raw_message LIKE '%203.0.113.%'
  GROUP BY 1 ORDER BY 2 DESC;
  SQL

Verify — alerts raised:

  docker compose exec -T postgres psql -U siembox -d siembox <<'SQL'
  SELECT severity, title FROM alerts
  WHERE created_at > NOW() - INTERVAL '10 minutes'
  ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                         WHEN 'medium' THEN 3 ELSE 4 END, id;
  SQL

Clean up (203.0.113.0/24 is TEST-NET-3 — never real traffic; alerts and
parsed_logs cascade from raw_logs):

  docker compose exec -T postgres psql -U siembox -d siembox \\
    -c "DELETE FROM raw_logs WHERE raw_message LIKE '%203.0.113.%';"
EOF
