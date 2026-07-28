#!/bin/bash
#
# Send synthetic UniFi CEF events to SIEMBox to verify the ingest pipeline
# end to end: syslog receive -> header strip -> parser match -> detection.
#
# The events deliberately reproduce the wire shape that used to break: a UniFi
# gateway sends CEF with NO <PRI> and a trailing newline, and JavaScript's `$`
# (without /m) does not match before a final newline — so one stray terminator
# defeated the RFC 3164 header regex and then every $-anchored catalog parser,
# landing the event in the unparsed bucket. The second datagram carries two
# events at once, which UDP ingest used to store as a single unparsed record.
#
#   usage: scripts/send-test-syslog.sh <siembox-host> [port]
#   e.g.   scripts/send-test-syslog.sh 192.168.1.100
#
# Source addresses are in the documentation range (203.0.113.0/24) and every
# event is tagged UNIFIpolicyName=SIEMBOX PIPELINE TEST, so the test records are
# easy to find and to delete afterwards (see the cleanup hint printed below).

set -u

HOST="${1:?usage: scripts/send-test-syslog.sh <siembox-host> [port]}"
PORT="${2:-514}"

command -v nc >/dev/null 2>&1 || {
  echo "error: nc (netcat) is required" >&2
  exit 1
}

TS=$(date '+%b %e %H:%M:%S')
TAG='SIEMBOX PIPELINE TEST'

# $1 = label (ends up in the signature name), $2 = source IP
evt() {
  printf '%s UCG-Max CEF:0|Ubiquiti|UniFi Network|10.4.57|201|Threat Detected and Blocked|7|UNIFIcategory=Security UNIFIhost=UCG Max proto=TCP spt=22536 dpt=80 act=blocked app=HTTP UNIFIrisk=medium UNIFIpolicyName=%s UNIFIpolicyType=IDS/IPS UNIFIdirection=incoming UNIFIdeviceIp=192.168.1.1 src=%s dst=198.51.100.10 UNIFIsrcRegion=US UNIFIdstZone=Internal UNIFIipsSignature=%s %s UNIFIipsSignatureId=9999999 msg=Synthetic test event for SIEMBox pipeline verification.\n' \
    "$TS" "$TAG" "$2" "$TAG" "$1"
}

# 1. One event per datagram — the shape that used to land unparsed.
evt single 203.0.113.99 | nc -u -w1 "$HOST" "$PORT"

# 2. Two events in ONE datagram — used to be stored as a single unparsed record.
{ evt packed-a 203.0.113.98; evt packed-b 203.0.113.97; } | nc -u -w1 "$HOST" "$PORT"

cat <<EOF
sent 3 test events to $HOST:$PORT over UDP (1 single + 2 packed into one datagram)

Verify — all three must show ubiquiti-unifi-ids-ips / ids_ips_alert:

  docker compose exec -T postgres psql -U siembox -d siembox <<'SQL'
  SELECT COALESCE(p.name,'(UNPARSED)') AS parser, pl.event_type,
         pl.parsed_data->>'source_ip'      AS src,
         pl.parsed_data->>'event_outcome'  AS outcome,
         pl.parsed_data->>'signature_name' AS signature
  FROM parsed_logs pl LEFT JOIN parsers p ON p.id = pl.parser_id
  WHERE pl.parsed_data->>'rule_name' = '$TAG'
  ORDER BY pl.id;
  SQL

  Only the single one parsed  -> backend still on the pre-fix UDP path.
  All three unparsed          -> new image not deployed, or the UniFi parser
                                 is not installed from the catalog.

Clean up afterwards:

  docker compose exec -T postgres psql -U siembox -d siembox \\
    -c "DELETE FROM raw_logs WHERE raw_message LIKE '%$TAG%';"
EOF
