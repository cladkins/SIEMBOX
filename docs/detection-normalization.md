# Detection field normalization

Detection rules match against **parsed log fields**. Historically each parser
emitted its own spelling for the same concept — `src_ip` vs `client_ip` vs
`source_ip`, `username` vs `user`, `request_uri` vs `path` — while a rule
references exactly one name. The effect was that a rule only matched logs from
parsers that happened to use the same field name, so many rules silently never
fired.

To fix this structurally, fields are **normalized to a canonical schema at parse
time** (`backend/src/services/normalize/fieldNormalizer.ts`), before the log is
stored and before detection runs. Normalization is **non-destructive**: original
parser fields are preserved and canonical fields are added alongside them.

## Canonical fields

Write new rules (and parsers) against these names:

| Canonical | Meaning | Populated from (aliases) |
|---|---|---|
| `source_ip` | The actor / source address | `src_ip`, `client_ip`, `remote_addr`, `remote_ip`, `ip_address`, `source_address`, `caller_ip`; else the packet sender |
| `client_ip` | Mirror of `source_ip` | mirrored to/from `source_ip` |
| `source_port` | Source port | `src_port` |
| `dest_ip` | Destination address | `dst_ip`, `destination_ip`, `dest_address` |
| `dest_port` | Destination port | `dst_port` |
| `user` | Account / principal | `username`, `user_name`, `remote_user`, `account`, `src_user`, `login_email`, `user_email` |
| `target_user` | Target/effective user | `dst_user`, `effective_user` |
| `host` | Host the event occurred on | `hostname`, `syslog_host`, `host_name` |
| `service` | Producing service | `program`, `process`, `process_name`, `application`, `app`, `logger`; else derived from the matched parser (e.g. SSH parser → `sshd`) |
| `method` | HTTP method | `http_method`, `http_verb` |
| `path` | HTTP path | `request_uri`, `request_url`, `url`, `uri` |
| `status_code` | HTTP status | `status`, `http_status`, `response_code` |
| `event_type` | Categorized event type | the parser's event type (top-level column) |
| `observer_ip` | The forwarder/sender that shipped the log | the syslog packet source |

Key points:
- **`source_ip` is the actor.** When a parser extracts an in-message IP (e.g. the
  attacker IP in `Failed password ... from 1.2.3.4`), that wins. Only when no
  in-message IP exists does `source_ip` fall back to the **packet sender**. The
  sender is always available separately as `observer_ip` — important because for
  *forwarded* logs the sender is the log shipper, not the actor.
- `source_ip` and `client_ip` are mirrored, so rules using either name match.

## Supported rule operators

`equals`, `not_equals`, `contains`, `not_contains`, `regex`, `greater_than`,
`less_than`, `in`, `not_in`, `not_in_whitelist`, `exists`.

(`in` / `not_in` accept a YAML list or a comma-separated string.)

## Aggregation semantics

A rule's `aggregation` counts logs in the timeframe that share the aggregation
field value **and also satisfy the rule's `conditions`** — not merely any log
sharing the value. So "5 failed SSH logins from an IP in 5m" counts failed
logins, not all traffic from that IP. `distinct_count` counts distinct values of
its field among those condition-matching logs.

## Adding a parser or rule

- Parsers should map to canonical names where possible; if they emit an alias
  from the table above, normalization will fill the canonical field for you.
- Rules should reference canonical names (`source_ip`, `user`, `service`,
  `path`, …). Avoid parser-specific spellings.
