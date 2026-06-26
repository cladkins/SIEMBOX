# Parsers

A **parser** turns a raw log line into structured, canonical fields. In SIEMBox parsers are **portable data** (`siembox.parser/v1`) — no engine code to write. You can install them from the in-app **catalog**, generate them with **AI**, or write/import them as JSON.

## Portable parser format

```jsonc
{
  "schema": "siembox.parser/v1",
  "name": "ubiquiti-unifi-cef-audit",
  "description": "Parses UniFi Network CEF audit events",
  "parser_type": "regex",              // "regex" or "json"
  "priority": 200,                      // 1–1000, lower runs first
  "pattern": "^...(?<src_ip>\\S+)...",  // regex with NAMED groups (regex type)
  "field_mappings": {                   // { capture-group OR json key : canonical field }
    "src_ip": "source_ip",
    "unifi_admin": "user",
    "msg": "message"
  },
  "derivations": [ /* optional, see below */ ],
  "event_type": "unifi_audit",
  "enabled": true,
  "test_samples": [                     // self-tests, run against the real engine
    { "input": "<a real raw log line>",
      "expect": { "source_ip": "192.168.1.130", "user": "cladkins" } }
  ],
  "metadata": { "author": "ai", "log_source": "UniFi", "tags": ["unifi","cef"] }
}
```

- **`parser_type: regex`** — `pattern` is a JS regex with **named groups** `(?<name>...)`; groups are mapped by `field_mappings`.
- **`parser_type: json`** — for JSON logs; `field_mappings` keys are JSON keys, with **dotted paths** allowed (e.g. `request.client_ip`, `headers.User-Agent[0]`).

## Canonical fields & normalization

Map to canonical fields wherever possible so rules match across sources:

`source_ip`, `dest_ip`, `source_port`, `dest_port`, `user`, `target_user`, `host`, `service`, `method`, `path`, `status_code`, `message`, `event`

The engine fills **aliases** automatically (`src_ip` / `client_ip` / `remote_addr` → `source_ip`, `username` → `user`, `request_uri` → `path`, …) and mirrors `source_ip ⇄ client_ip`, so you usually only set one. Always capture the **actor IP** into a group mapped to `source_ip` when present.

### `message` vs the raw line

By default `message` is set to the **full raw log line**. If you explicitly map a group to `message` (e.g. a CEF `msg=` field), **that mapping wins** and `message` becomes your cleaned-up text — while the original line is still retained on the raw-log record. (Map `message` only when you want the narrowed text, and make your `test_samples` `expect` that exact value.)

## Derivations

Declarative post-processing, applied after mapping; they fill **empty** fields (unless `"overwrite": true`), first match wins:

```jsonc
// set a field when a condition holds (contains/equals/in/matches/exists; case-insensitive)
{ "when": { "message": { "contains": "accessed" } }, "set": { "event": "network_access" } }

// extract a sub-value with a regex capture group
{ "extract": { "user": { "from": "message", "pattern": "user=(\\w+)", "group": 1 } } }
```

Use derivations to set an `event` marker (e.g. `login_failure` / `login_success`) from message text — detection rules then key on `event`.

## Self-tests

`test_samples` are **mandatory for the catalog** and are run through the real `match → map → derive → normalize` pipeline. Each `expect` must equal what the parser actually produces. The catalog CI runs exactly this, so a parser that passes CI imports and behaves identically in your install.

## Installing from the catalog

**Parsers → Browse Catalog** lists community parsers (Nginx, Traefik, Caddy, Authelia, Keycloak, Nextcloud, Pi-hole, Vaultwarden, UniFi, Home Assistant, Plex, Jellyfin, and more). Every entry is validated and self-tested before install, with search, filters, and install/update status. Use **Install all** to grab the set. You can also **export/import** any parser as portable JSON.

## AI builder

**Parsers → Generate with AI.** Paste a log line (plus optional hints) and SIEMBox runs a **generate → validate → self-test → auto-refine** loop (up to 3 attempts) against the real engine, feeding failures back to the model, so you never save an invalid parser. Works with **Anthropic, OpenAI, or local Ollama** (bring your own key; stored encrypted — see [Configuration](Configuration#ai-builder-optional)).

- If a result isn't fully valid, you can still **Save anyway** and refine it with the Test/Edit tools instead of starting over.
- The model is told that `message` defaults to the raw line and only maps it for a cleaned value (see above).

## Seeing which parser matched

The **Logs → Parsed Logs** table shows a **Parser** column (which parser produced each event) and a **Parser** filter so you can slice the log view by parser. "Unknown" means the matching parser was since deleted.

## Deep reference

Full field-by-field reference and authoring guidance: [docs/reference/PARSERS.md](https://github.com/cladkins/SIEMBOX/blob/main/docs/reference/PARSERS.md) · [Canonical schema](https://github.com/cladkins/SIEMBOX/blob/main/docs/canonical-schema.md).
