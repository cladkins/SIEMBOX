# Canonical field schema

The detection layer matches against a **canonical, flat field set** that every
parser normalizes to, regardless of the source log's own field names. This is the
contract shared by parsers, the normalizer, detection rules, enrichment, and the
(future) parser hub + AI builder. It is intentionally ECS-aligned but flat
(snake_case), so rules can reference `parsed_data->>'field'` directly.

Normalization happens in three layers (see `backend/src/services/`):
1. **parser `field_mappings`** — map a capture group / JSON key to a field.
2. **`derive` rules** (declarative, per parser) — set fields from conditions
   (e.g. `message contains "incorrect" → event=login_failure`).
3. **`fieldNormalizer`** — alias synonyms to the canonical names below, fill
   `source_ip`/`client_ip` mirror, merge `event_type`, derive `service`.

## Network / actor
| Field | Meaning | Filled from (aliases) |
|---|---|---|
| `source_ip` | actor / source address | `src_ip`, `client_ip`, `remote_addr`, `remote_ip`, `ip_address`, `src`; else packet sender |
| `client_ip` | mirror of `source_ip` | mirrored both ways |
| `source_port` | source port | `src_port`, `spt` |
| `dest_ip` | destination address | `dst_ip`, `destination_ip`, `dst` |
| `dest_port` | destination port | `dst_port`, `dpt` |
| `observer_ip` | the forwarder/sender that shipped the log | packet source |

## Identity / outcome
| Field | Meaning |
|---|---|
| `user` | account / principal (`username`, `remote_user`, `suser`, …) |
| `target_user` | target/effective user (`dst_user`, `duser`) |
| `event` | parser-specific event token (e.g. SSH `Failed password`, `login_failure`) |
| `auth_outcome` | canonical auth result: `success` \| `failure` (derived from `event` across all auth parsers) |
| `action` | a derived action (e.g. `vault_export`) |

## Host / service / HTTP
| Field | Meaning |
|---|---|
| `host` | host the event occurred on (`hostname`, `syslog_host`) |
| `service` | producing service (`program`, `process`, `app`; else derived from the parser) |
| `method` | HTTP method |
| `path` | HTTP path (`request_uri`, `url`, `uri`) |
| `status_code` | HTTP status (`status`, `http_status`) |
| `response_size` | bytes sent (`body_bytes_sent`, `bytes_sent`) |
| `request_size` | request size (`request_length`, `bytes_received`) |

## Categorization / enrichment
| Field | Meaning |
|---|---|
| `event_type` | parser's categorized type (top-level column, e.g. `http_request`, `cef_event`) |
| `country` / `country_code` | GeoIP country of `source_ip` (DB-IP lite) |
| `geo_foreign` | boolean: `source_ip` country not in `GEOIP_HOME_COUNTRIES` |
| `message` | the raw/cleaned log message |

New parsers should map to these names; new canonical fields should be added here
first, then to `fieldNormalizer` (alias) and this doc.
