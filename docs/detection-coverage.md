# Detection Coverage Matrix

## Audit progress (top-down)

Working down the priority-ordered parser list, verifying each parser emits what
its rules need (samples sourced from the parser pattern / public log formats) and
fixing gaps as found.

**Major structural fix (SSH/Apache pass): reversed `field_mappings`.** Many
seeded parsers wrote `field_mappings` as `{field: group}` while the engine read
`{group: field}`, so whenever the names differed the captured value was silently
dropped. `parserEngine.applyRegexParser` now accepts **both** directions. This
restored, among others:
- **SSH** → `source_ip`, `source_port` (the *attacker* IP; AUTH-001/002/003/004 were aggregating on the syslog sender before).
- **Apache/Nginx** → `status_code`, `response_size` (Web Path Scanning, Web Server Errors, PROXY-004, EXFIL-002).
- **nginx-komodo-timestamp-first** → `status_code`; **unifi-firewall / unifi-idsips** → source/dest IPs + ports; **vaultwarden** → `source_ip`.

Also: normalizer now aliases `response_size ← body_bytes_sent` (combined-format nginx), and `createAlert` no longer overwrites `{source_ip}` with the packet sender.

**Rule delivery (important):** `rules/` is a read-only **volume mount** (`./rules:/app/rules` in `compose.prod.yaml`), *not* baked into the image, and `importRules` used to **skip any rule whose name already existed** — so edits to existing rules never reached a running install. `importRules` now **upserts** a rule when its YAML changed (preserving the operator's enabled/disabled toggle). Applying rule changes therefore needs a host `git pull` (to refresh `./rules`) **plus** a backend restart; parser/engine fixes and `migrations/` ship in the image via `docker pull`.

| # | Parser | Verified | Notes / fixes |
|---|--------|----------|---------------|
| 1–2 | cef-syslog / cef-standard | ✅ | CEF extension extraction + UNIFI-* rules (earlier PRs) |
| 4 | SSH Authentication | ✅ | reversed mapping fixed → real `source_ip`; AUTH-001 `service=sshd` correct |
| 5 | Linux Sudo | ✅ | only `working_dir` was dropped (no rule uses it); ACCESS-001/003 OK |
| 6 | Apache/Nginx Access | ✅ | reversed mapping fixed → `status_code`/`response_size` emitted |
| 23 | Generic Syslog | ✅ | INFRA-003 aggregation `program`→`service` fixed |
| 7–9 | authentik / keycloak / authelia | ✅ | AUTH-007 fixed: uniform `event="authentication failed"` derived in postProcessFields (Authelia emits no event; Keycloak=`LOGIN_ERROR`; authentik=action+`success`) |
| 10 | pihole-query | ✅ | regex fixed (migration 003): matched none of the standard `query[A] domain from client` lines → now emits `query_type`/`domain`/`client_ip` (APP-003, EXFIL-003 live) |
| 11 | nextcloud-access | ⚠️ partial | APP-004 `status_code` condition removed (parser can't supply it). Parser regex targets a `[time] app.LEVEL: msg {json}` format, but default `nextcloud.log` is pure JSON — needs a real sample to confirm/rewrite the parser |
| 12–22 | vaultwarden, nginx variants, unifi native | ⏳ pending | next passes |

**Remaining known gaps:** PROXY-007 (`request_size` — no parser captures request-body size); APP-001/IOT-001/IOT-002 (no Home Assistant parser); APP-002 (no Plex/Jellyfin parser); PWDMGR-003 (`country` — no GeoIP). See **Gaps** below.

**Queued for next passes (parser-quality issues found in pass 2):**
- **pihole-query** regex doesn't match the standard dnsmasq `query[A] domain from client` format → APP-003/EXFIL-003 get no `query_type`/`domain`/`client_ip` (needs a parser-pattern migration).
- **keycloak-event** regex uses lazy `.*?` + optional groups, so `ipAddress` is frequently not captured → AUTH-007 aggregates on the syslog sender rather than the attacker.
- **nextcloud-access** emits no `status_code` → APP-004's status condition is unsatisfiable as written.
- **vaultwarden** PWDMGR-001/002 depend on "vault export" / "device registered" log messages that Vaultwarden may not emit by default (PWDMGR-004 `path` is derived from `module` and works).



> **How to read:** Each parser emits a set of `parsed_data` fields (the *values* in its `field_mappings`), which are then normalized (canonical fields filled from aliases, `service` from parser name, `event_type` from the parser column, `source_ip`↔`client_ip` mirrored — see `backend/src/services/normalize/fieldNormalizer.ts`). A rule is **satisfied** only if *every* field in *every* condition is emitted by ≥1 associated parser **after** alias normalization. "GAP" = at least one condition field that no parser can produce.
>
> Sources: parsers + seed rules from `backend/migrations/002_seed_data.sql`; file rules from `rules/**/*.yaml`. Parsers apply in **priority ASC**, first match wins (so the same log line is normally enriched by exactly one parser, except CEF where the CEF parser + extension extraction layer both contribute).

## Parsers

Canonical fields are written in **bold**. "+norm" = fields added by the normalizer regardless of mappings: `service` (from name), `event_type` (from column), `client_ip`↔`source_ip` mirror, `observer_ip`, plus any canonical alias-fills.

| # | name | prio | type | event_type | emits (key fields; **canonical** bold) | #rules | status |
|---|------|------|------|-----------|----------------------------------------|--------|--------|
| 1 | cef-syslog | 4 | regex | cef_event | cef_version, device_vendor, device_product, signature_id, event_name, severity, extension, **host**(←syslog_host), format; +all ext k=v: **src/source_ip**, **dst/dest_ip**, **spt/source_port**, **dpt/dest_port**, act, app, proto, UNIFI* keys; +norm | 4 | active |
| 2 | cef-standard | 5 | regex | cef_event | cef_version, device_vendor, device_product, signature_id, event_name, severity, extension, format; +all ext k=v: **src/source_ip**, **dst/dest_ip**, **spt/source_port**, **dpt/dest_port**, act, app, proto, UNIFI* keys; +norm | 4 | active |
| 3 | cef-extension-fields | 6 | regex | cef_event | **source_ip**(←src), **dest_ip**(←dst), **source_port**(←spt), **dest_port**(←dpt), action, message, **user**(←src_user), **target_user**(←dst_user), filename, request_url→**path**, outcome, reason | 0 | **DISABLED** |
| 4 | SSH Authentication | 10 | regex | ssh_auth | timestamp, **host**(←hostname), pid, event, **user**, **source_ip**(←src_ip), **source_port**(←src_port); +norm service=sshd | 6 | active |
| 5 | Linux Sudo | 15 | regex | sudo_command | timestamp, **host**, **user**, tty, working_dir, **target_user**, command; +norm service=sudo | 4 | active |
| 6 | Apache/Nginx Access Log | 20 | regex | http_request | **client_ip→source_ip**, timestamp, **method**, **path**, protocol, **status_code**(←status), response_size; +norm | 5 | active |
| 7 | authentik-audit | 24 | json | authentik_audit | timestamp, event, **user**, **client_ip→source_ip**, success, **service**(←app=authentik) | 1 | active |
| 8 | keycloak-event | 23 | regex | keycloak_event | timestamp, **service**(←logger), event, realm, user_id, **client_ip→source_ip**; +norm service=keycloak | 1 | active |
| 9 | authelia-access | 25 | regex | authelia_auth | timestamp, log_level, message, **method**, **path**, **client_ip→source_ip**, **status_code**; +norm service=authelia | 1 | active |
| 10 | pihole-query | 30 | regex | dns_query | timestamp, query_type, domain, result, **client_ip→source_ip**; +norm service=pihole | 2 | active |
| 11 | nextcloud-access | 35 | regex | nextcloud_access | timestamp, app, log_level, message, **user**, url→**path**, **method**, **client_ip→source_ip**; +norm service=nextcloud | 2 | active |
| 12 | standard-nginx-error | 39 | regex | nginx_error | timestamp, log_level, message, **service**=nginx | 0 | active |
| 13 | standard-nginx-access | 40 | regex | http_request | **client_ip→source_ip**, remote_user→**user**, timestamp, **method**, request_uri→**path**, http_version, **status_code**, body_bytes_sent, http_referer, user_agent, **service**=nginx | 5 | active |
| 14 | nginx-komodo-ip-only | 43 | regex | http_request | **client_ip→source_ip**, message, **service**=nginx-komodo | (proxy*) | active |
| 15 | nginx-komodo-error | 44 | regex | nginx_error | timestamp, log_level, pid, worker_id, connection_id, error_message, **service**=nginx-komodo | 0 | active |
| 16 | nginx-komodo-timestamp-first | 45 | regex | http_request | timestamp, **status_code**, upstream_status, **method**, protocol, request_uri→**path**, **service**=nginx-komodo | (proxy*) | active |
| 17 | nginx-proxy-manager-error | 49 | regex | nginx_error | timestamp, log_level, message, **service**=nginx-proxy-manager | 0 | active |
| 18 | nginx-proxy-manager-access | 50 | regex | http_request | **client_ip→source_ip**, remote_user→**user**, timestamp, **method**, request_uri→**path**, http_version, **status_code**, body_bytes_sent, http_referer, user_agent, **service**=npm | (proxy*) | active |
| 19 | JSON Parser | 50 | json | json_log | (passthrough; `{}` mappings — emits whatever JSON keys exist, canonical fields only via alias-fill) | 0 | active |
| 20 | unifi-firewall | 50 | regex | firewall_event | rule_name, rule_description, in/out_interface, **source_ip→client_ip**, **dest_ip**, protocol, **service**=unifi-firewall | 0 | active |
| 21 | unifi-idsips | 50 | regex | ids_alert | severity, event_type, action_type, action, external_ip→**source_ip/client_ip**, external_port→**source_port**, internal_ip→**dest_ip**, internal_port→**dest_port**, protocol, **service**=unifi-idsips | seed×4 | active |
| 22 | vaultwarden-access | 55 | regex | vaultwarden_event | timestamp, module, log_level, message, **client_ip→source_ip**, email→**user**, admin_email, admin_ip, device, **service**=vaultwarden, action(=message), event(=message) | 4 | active |
| 23 | Generic Syslog | 1000 | regex | generic | timestamp, **host**, **service**(←process), pid, message | seed (fallback) | active |

\* nginx-komodo-* and NPM access parsers serve the same `http_request` PROXY-rule family as the other HTTP parsers; rule counts are attributed to the canonical HTTP parsers (Apache/Nginx, standard-nginx-access) to avoid double counting.

## Rules

`agg` = aggregation.field (`+dc:` = distinct_count field). Satisfied = all condition fields producible by an associated parser after normalization.

| name | file | en | sev | tags | condition fields | agg | satisfied? |
|------|------|----|-----|------|------------------|-----|------------|
| SSH Brute Force Attempt | seed | y | high | ssh,brute-force,auth | event, source_ip | source_ip | yes |
| Direct Root SSH Login | seed | y | crit | ssh,root,privilege | event, user | – | yes |
| Sudo Privilege Escalation | seed | y | med | sudo,priv-esc | target_user, command | – | yes |
| Web Path Scanning | seed | y | med | web,scanning | status_code, client_ip | client_ip | yes |
| Web Server Errors | seed | y | low | web,errors | status_code, path | path | yes |
| Multiple Failed Authentication | seed | y | med | auth,failed-login | message | source_ip | yes (Generic Syslog) |
| UniFi IPS Repeated Attack Attempts | seed | y | high | unifi,ips | action_type, action | external_ip | yes (unifi-idsips) |
| UniFi IPS Internal System Under Attack | seed | y | crit | unifi,ips | action_type, action | internal_ip | yes (unifi-idsips) |
| UniFi IDS/IPS Error Events | seed | y | med | unifi,ips,ids | severity, event_type | – | yes (unifi-idsips) |
| UniFi IPS Port Scan Detection | seed | y | high | unifi,ips,port-scan | action_type, action | external_ip | yes (unifi-idsips) |
| AUTH-001 SSH Brute Force Detection | rules/authentication/AUTH-001 | y | high | ssh,brute-force,auth | event, service | source_ip | yes |
| AUTH-002 Successful Login After Failed Attempts | rules/authentication/AUTH-002 | y | crit | auth,brute-force,ssh | event, source_ip | source_ip | yes |
| AUTH-003 Distributed Brute Force Attack | rules/authentication/AUTH-003 | y | high | auth,brute-force,botnet | event, user | user +dc:source_ip | yes |
| AUTH-004 Account Enumeration Attempt | rules/authentication/AUTH-004 | y | med | auth,enumeration,ssh | event | source_ip +dc:user | yes |
| AUTH-005 Vaultwarden Master Password Failures | rules/authentication/AUTH-005 | y | crit | vaultwarden,auth | service, message | source_ip | yes (vaultwarden) |
| AUTH-006 Authentication Outside Normal Hours | rules/authentication/AUTH-006 | y | low | auth,after-hours | event, timestamp | – | yes |
| AUTH-007 Multiple Failed SSO Auth Attempts | rules/authentication/AUTH-007 | y | high | sso,authelia,authentik,keycloak | service, event | source_ip | **GAP** (event) |
| AUTH-008 Root SSH Login Attempt | rules/authentication/AUTH-008 | y | crit | ssh,root,priv-esc | event, user, service | – | yes |
| AUTH-009 API Authentication Failures | rules/authentication/AUTH-009 | y | med | api,auth,token-abuse | message, status_code | source_ip | yes (HTTP/syslog) |
| AUTH-010 Cross-Service Authentication Failures | rules/authentication/AUTH-010 | y | high | auth,cred-stuffing | message | source_ip +dc:service | yes |
| AUTH-011 Admin Interface Access from Unusual IP | rules/authentication/AUTH-011 | y | med | admin,web,auth | path, client_ip | – | yes¹ |
| ACCESS-001 Sudo to Root by Non-Admin User | rules/access-control/ACCESS-001 | y | high | sudo,priv-esc,root | target_user, user | – | yes (Sudo) |
| ACCESS-002 Unauthorized Administrative Access | rules/access-control/ACCESS-002 | y | med | admin-access,web | path | – | yes |
| ACCESS-003 Unusual Process Execution via Sudo | rules/access-control/ACCESS-003 | y | high | sudo,exploitation,malware | command | – | yes (Sudo) |
| ACCESS-004 Service Account Interactive Login | rules/access-control/ACCESS-004 | y | low | service-account,ssh | user, event | – | yes (SSH) |
| PROXY-001 SQL Injection Attempt | rules/reverse-proxy/PROXY-001 | y | high | web,sql-injection | path | – | yes |
| PROXY-002 Command Injection Attempt | rules/reverse-proxy/PROXY-002 | y | high | web,command-injection | path | – | yes |
| PROXY-003 Path Traversal Attempt | rules/reverse-proxy/PROXY-003 | y | med | web,path-traversal | path | – | yes |
| PROXY-004 Directory Enumeration Detection | rules/reverse-proxy/PROXY-004 | y | med | web,scanning | status_code | client_ip | yes |
| PROXY-005 Malicious User Agent Detection | rules/reverse-proxy/PROXY-005 | y | med | web,user-agent | user_agent | – | yes² |
| PROXY-006 HTTP Method Abuse | rules/reverse-proxy/PROXY-006 | y | med | web,http-methods | method | – | yes |
| PROXY-007 Large Request Body DoS | rules/reverse-proxy/PROXY-007 | y | med | web,dos,upload-abuse | request_size | – | **GAP** (request_size) |
| PROXY-008 High Request Rate DoS Attack | rules/reverse-proxy/PROXY-008 | y | high | web,dos,rate-limiting | client_ip | client_ip | yes |
| APP-001 Home Assistant Unauthorized Automation | rules/application/APP-001 | y | med | home-assistant,iot | event_type, user | – | **GAP** (no HA parser) |
| APP-002 Unusual Media Streaming Pattern | rules/application/APP-002 | y | low | plex,jellyfin,media | action | user | **GAP** (no Plex/Jellyfin parser) |
| APP-003 Pi-hole DNS Query Anomaly | rules/application/APP-003 | y | med | pihole,dns,c2 | query_type | client_ip | yes (pihole) |
| APP-004 Nextcloud Suspicious File Access | rules/application/APP-004 | y | high | nextcloud,file-access | path, status_code | client_ip | yes (nextcloud)³ |
| INFRA-001 Port Scan Detection | rules/infrastructure/INFRA-001 | y | med | port-scan,recon,network | message | source_ip | yes (syslog) |
| INFRA-002 Container Escape Attempt | rules/infrastructure/INFRA-002 | y | crit | container,docker,priv-esc | message | – | yes (syslog) |
| INFRA-003 Unusual Service Restart Pattern | rules/infrastructure/INFRA-003 | y | med | service-restart,systemd | message | program | yes (syslog)⁴ |
| INFRA-004 Cryptocurrency Mining Detection | rules/infrastructure/INFRA-004 | y | high | cryptomining,malware | message | – | yes (syslog) |
| EXFIL-001 Bulk File Download Detection | rules/data-exfiltration/EXFIL-001 | y | high | exfiltration,nextcloud | path, status_code | client_ip | yes (nextcloud/HTTP) |
| EXFIL-002 Large Data Transfer Detection | rules/data-exfiltration/EXFIL-002 | y | high | exfiltration,bandwidth | response_size, status_code | client_ip | **GAP** (response_size)⁵ |
| EXFIL-003 DNS Tunneling Detection | rules/data-exfiltration/EXFIL-003 | y | high | exfiltration,dns-tunnel | query_type | client_ip | yes (pihole) |
| IOT-001 Unusual Smart Device Automation Trigger | rules/iot/IOT-001 | y | med | iot,home-assistant | event_type, trigger_type, timestamp | – | **GAP** (trigger_type; no HA parser) |
| IOT-002 Smart Lock Repeated Failures | rules/iot/IOT-002 | y | low | iot,smart-lock | device_type, event | device_id | **GAP** (device_type, device_id; no HA parser) |
| PWDMGR-001 Vaultwarden Vault Export | rules/password-manager/PWDMGR-001 | y | crit | vaultwarden,exfiltration | service, action | – | yes (vaultwarden)⁶ |
| PWDMGR-002 Multiple Device Registrations | rules/password-manager/PWDMGR-002 | y | high | vaultwarden,device-reg | service, event | user | yes (vaultwarden)⁶ |
| PWDMGR-003 Unusual Vault Access Geolocation | rules/password-manager/PWDMGR-003 | y | high | vaultwarden,geolocation | service, event, country | – | **GAP** (country)⁶ |
| PWDMGR-004 API Token Abuse | rules/password-manager/PWDMGR-004 | y | high | vaultwarden,api,token | service, path | source_ip | yes (vaultwarden)⁷ |
| UNIFI-IPS-001 Threat Blocked | rules/network/UNIFI-IPS-001 | y | low | unifi,ids-ips,blocked | UNIFIpolicyType, act | – | yes (CEF)⁸ |
| UNIFI-IPS-002 Threat NOT Blocked | rules/network/UNIFI-IPS-002 | y | high | unifi,ids-ips,unblocked | UNIFIpolicyType, act | – | yes (CEF)⁸ |
| UNIFI-IPS-003 Sustained IDS/IPS Targeting | rules/network/UNIFI-IPS-003 | y | crit | unifi,ids-ips,scanning | UNIFIpolicyType | source_ip | yes (CEF)⁸ |
| UNIFI-AUDIT-001 Controller Admin Access | rules/network/UNIFI-AUDIT-001 | y | med | unifi,audit,admin | UNIFIcategory, UNIFIadmin | – | yes (CEF)⁸ |

**Footnotes**
1. AUTH-011 `client_ip` + `not_in_whitelist`: field is satisfiable; operator depends on external whitelist config (not a field gap).
2. PROXY-005/006/007 `user_agent`/`request_size` only come from the combined-format HTTP parsers. `user_agent` IS emitted (standard-nginx-access, NPM, traefik, caddy). `request_size` is NOT (see gap).
3. APP-004 `event` referenced in alias only via nextcloud `message`; condition fields path+status_code are satisfied. OK.
4. INFRA-003 aggregates on `program`, which is a `service` alias and IS emitted by Generic Syslog (as `process`→`service`; raw `program` not emitted but normalizer maps program→service, not the reverse). Aggregation keys on raw `program` — see gap notes (soft gap).
5. EXFIL-002 `response_size`: emitted by the **legacy** Apache/Nginx parser only (`response_size`), NOT by the combined-format nginx parsers (which emit `body_bytes_sent`). Partial — see gap.
6. PWDMGR / vaultwarden: parser emits `action`=message and `event`=message (both aliased to the raw message string), and `service`=vaultwarden. So `action`/`event`/`service` resolve, but their VALUES are the full log message, not enums like "vault_export"/"vault_unlock" — equals-comparisons will not match. Functional (soft) gap noted below. `country` is a hard gap (GeoIP enrichment not implemented).
7. PWDMGR-004 `path`: vaultwarden parser does not emit `path`/`request_uri`; `path` is unsatisfied for vaultwarden logs (soft/hard gap — see notes).
8. UNIFI-* rules rely on CEF extension extraction emitting `act` and vendor keys `UNIFIpolicyType`/`UNIFIcategory`/`UNIFIadmin`/`UNIFIipsSignature`/`UNIFIrisk`. Per the normalization spec, cef-standard/cef-syslog now extract ALL extension k=v pairs (including UNIFI* keys), so these fields ARE produced **when UniFi ships CEF**. The dedicated `unifi-firewall`/`unifi-idsips` regex parsers do NOT emit these keys (they emit `action`, `event_type`, etc.), so these rules only fire on the CEF path, not the native UniFi syslog path.

## Parser → rules map

- **cef-syslog / cef-standard** → UNIFI-IPS-001, UNIFI-IPS-002, UNIFI-IPS-003, UNIFI-AUDIT-001 (via extension key extraction). Also the generic vehicle for any CEF-sourced security product.
- **cef-extension-fields** → (none directly; **disabled**, superseded by full extension extraction in the CEF parsers).
- **SSH Authentication** → seed: SSH Brute Force, Direct Root SSH Login; AUTH-001, AUTH-002, AUTH-003, AUTH-004, AUTH-008, ACCESS-004, AUTH-006 (event/timestamp).
- **Linux Sudo** → seed: Sudo Privilege Escalation; ACCESS-001, ACCESS-003. (INFRA service-restart/process rules key on syslog message, not sudo.)
- **Apache/Nginx Access Log (legacy)** → seed: Web Path Scanning, Web Server Errors; PROXY-001/002/003/004/006/008, AUTH-009, AUTH-011, ACCESS-002, EXFIL-002 (only this parser emits `response_size`).
- **standard-nginx-access / nginx-proxy-manager-access / nginx-komodo-* / traefik / caddy** → PROXY-001..006, PROXY-008, EXFIL-001, AUTH-011, ACCESS-002 (combined-format parsers; supply `user_agent`, `path`, `method`, `status_code`).
- **authelia-access** → AUTH-007 (SSO).
- **authentik-audit** → AUTH-007 (SSO).
- **keycloak-event** → AUTH-007 (SSO).
- **pihole-query** → APP-003, EXFIL-003.
- **nextcloud-access** → APP-004, EXFIL-001.
- **vaultwarden-access** → AUTH-005, PWDMGR-001, PWDMGR-002, PWDMGR-003, PWDMGR-004.
- **unifi-idsips** → seed: UniFi IPS Repeated Attack Attempts, UniFi IPS Internal System Under Attack, UniFi IDS/IPS Error Events, UniFi IPS Port Scan Detection. (NOT the UNIFI-* yaml rules, which use CEF keys.)
- **unifi-firewall** → (none) — no rule references its `rule_name`/`rule_description`/firewall fields.
- **Generic Syslog** → seed: Multiple Failed Authentication; INFRA-001, INFRA-002, INFRA-003, INFRA-004 (message-regex on fallback syslog). Catch-all enrichment for everything else.
- **nginx error parsers** (standard-nginx-error, nginx-komodo-error, nginx-proxy-manager-error) → (none).
- **JSON Parser** → (none specifically) — generic passthrough; feeds whatever JSON keys exist into the normalizer.

## Gaps

### Dead / unsatisfiable rules (rule — missing field — intended parser)

- **AUTH-007 (Multiple Failed SSO Authentication Attempts)** — `event` — intended for authelia-access / authentik-audit / keycloak-event. **authelia-access does NOT emit `event`** (it emits `message`, `method`, `path`, `status_code`); only authentik-audit and keycloak-event emit `event`. So the rule cannot fire on Authelia logs (a tagged target), and the `event` values differ across the three IdPs. Partial dead spot: Authelia branch unsatisfiable.
- **PROXY-007 (Large Request Body DoS)** — `request_size` — intended for the reverse-proxy/HTTP parsers. **NO parser emits `request_size`.** HTTP parsers emit `body_bytes_sent` (response size) and the legacy parser emits `response_size`; neither is a request-body size, and neither is an alias of `request_size`. Rule never fires. Fix: add a request-size capture, or rename the condition to an emitted field.
- **EXFIL-002 (Large Data Transfer Detection)** — `response_size` — intended for nextcloud/HTTP exfil. Only the **legacy Apache/Nginx parser** emits `response_size`; the modern combined-format parsers (standard-nginx-access, NPM, komodo) and nextcloud emit `body_bytes_sent` instead, and `response_size` is not in the alias map. So on the parsers the tags actually target (nextcloud/immich via nginx), the field is absent → rule effectively dead for the intended sources.
- **APP-001 (Home Assistant Unauthorized Automation)** — `event_type`, `user` — intended for a Home Assistant parser. **No Home Assistant parser exists.** `event_type` is set by the normalizer to the parser's event_type *column value* (e.g. "generic", "http_request"), never "automation_triggered"; and HA logs would land in Generic Syslog, which emits neither a usable `event_type` enum nor `user`. Unsatisfiable.
- **APP-002 (Unusual Media Streaming Pattern)** — `action` (value "stream_start") — intended for a Plex/Jellyfin parser. **No Plex/Jellyfin parser exists.** Unsatisfiable.
- **IOT-001 (Unusual Smart Device Automation Trigger)** — `trigger_type` (and the "automation_triggered" `event_type`) — intended for a Home Assistant parser. **No HA parser; `trigger_type` is emitted by no parser and is not an alias.** Unsatisfiable.
- **IOT-002 (Smart Lock Repeated Failures)** — `device_type`, `device_id` — intended for a Home Assistant / smart-lock parser. **No parser emits `device_type` or `device_id`** (neither is an alias). Unsatisfiable.
- **PWDMGR-003 (Unusual Vault Access Geolocation)** — `country` — intended for vaultwarden + GeoIP enrichment. **No parser emits `country`; GeoIP enrichment is not implemented.** Hard gap. (`event`=vault_unlock is also a soft gap — see below.)

### Soft gaps (field present but value can never match the rule's literal)

These are not "no field" gaps, but the operator/value will not match what the parser actually puts in the field — worth flagging since they silently never fire:

- **PWDMGR-001 / 002 / 003 (`action`/`event` equals "vault_export"/"device_…"/"vault_unlock")** — the vaultwarden parser maps **both** `action` and `event` to the raw `message` string (`"action": "message", "event": "message"`). An `equals "vault_export"` test compares against the full log line, so it never matches. Needs message-substring (`contains`) logic or a real action/event extractor.
- **PWDMGR-004 (`path` equals an API route)** — vaultwarden-access emits no `path`/`request_uri`/`url`, so `path` is empty for vaultwarden logs → condition unsatisfied. (Hard gap for the vaultwarden source specifically.)
- **INFRA-003 (aggregation field `program`)** — the normalizer maps `program → service` (one-directional); Generic Syslog emits `process` (→`service`), not a literal `program` key. Aggregating on raw `program` will see nothing. Use `service` as the agg field.
- **AUTH-001 (`service` equals "ssh")** vs normalizer deriving **service = "sshd"** for the SSH parser — if AUTH-001 tests `service == "ssh"` (not "sshd"), it won't match. (Condition uses `contains`/`equals`; verify the literal — flagged for top-down review.)

### Parsers with NO associated rules

- **cef-extension-fields** (prio 6) — **disabled**; superseded by full extension extraction now done in cef-standard/cef-syslog.
- **standard-nginx-error** (prio 39) — error-log parser; no rule consumes `nginx_error`.
- **nginx-komodo-error** (prio 44) — same; emits `error_message`, no rule consumes it.
- **nginx-proxy-manager-error** (prio 49) — same; no rule.
- **unifi-firewall** (prio 50) — emits `rule_name`/`rule_description`/firewall fields that NO rule references (the UNIFI-* yaml rules key on CEF `UNIFIpolicyType`/`act`; the seed UniFi rules key on unifi-**idsips** fields). Firewall-event logs are uncovered.
- **JSON Parser** (prio 50) — generic passthrough; no rule targets `json_log` specifically (it only contributes alias-fillable canonical fields).
- **nginx error family generally** — no detections on any `nginx_error` event_type.

### Operator / data mismatches noted

- **PROXY-007 `greater_than "52428800"`** and **EXFIL-002 `response_size greater_than`** compare a numeric threshold against a *string* field value; relies on the engine coercing strings → numbers. Combined with the missing/legacy field, these are doubly fragile.
- **AUTH-011 `client_ip not_in_whitelist` / `value: true`** — non-standard operator requiring external whitelist config; field is fine but the rule is inert until a whitelist is wired up.
- **PWDMGR-001/002/003 `equals` on `action`/`event`** — mismatched to data (field holds full message; should be `contains`). See soft gaps.
