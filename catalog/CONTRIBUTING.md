# Contributing a parser

Thanks for adding a log source to SIEMBox! A parser is **data, not code** — you
describe how to recognize a log line and what canonical fields it produces, and
ship `test_samples` that prove it. CI runs your self-tests through the real
engine, so if it passes here it works in SIEMBox.

## TL;DR

1. Add `catalog/parsers/<name>.parser.json` (kebab-case name).
2. Map captured fields to **canonical** names (`source_ip`, `user`, `status_code`, …).
3. Add at least one `test_sample` asserting the canonical fields, including a
   real-world log line.
4. Run `cd backend && npm ci && npm run build && npm run validate-parsers -- ../catalog/parsers`.
5. Open a PR. The **Validate Parser Catalog** check must be green.

Tip: if you already run SIEMBox, build the parser in the UI and export it
(`GET /api/parsers/:id/export`) as a starting point, then add `test_samples`.

## File format

Authoritative schema: [`schema/parser.schema.json`](./schema/parser.schema.json)
(point your editor at it for autocomplete). Shape:

```jsonc
{
  "schema": "siembox.parser/v1",
  "name": "my-app",                 // unique, kebab-case; also the import key
  "description": "What this parses and which events it surfaces.",
  "parser_type": "regex",           // "regex" | "json" | "grok"
  "priority": 60,                    // lower runs first; first match wins
  "pattern": "^...(?<source_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)...$",
  "field_mappings": { "source_ip": "source_ip", "msg": "message" },
  "derivations": [ /* see below */ ],
  "event_type": "myapp_event",
  "enabled": true,
  "test_samples": [
    { "input": "<a real raw log line>", "expect": { "source_ip": "203.0.113.5", "event": "login_failure" } }
  ],
  "metadata": { "author": "you", "log_source": "MyApp access log", "references": ["https://..."] }
}
```

### `field_mappings`
- **regex**: `{ captureGroupName: canonicalField }`. (Both directions are accepted,
  but write it group→field.)
- **json**: `{ jsonKey: canonicalField }`.

Map to canonical names so detection rules match regardless of the source. Common
ones: `source_ip`, `dest_ip`, `source_port`, `dest_port`, `user`, `target_user`,
`host`, `service`, `method`, `path`, `status_code`, `message`. The normalizer
also fills aliases (e.g. `client_ip`/`src_ip` → `source_ip`) and mirrors
`source_ip` ↔ `client_ip`, so you usually only set one.

### `derivations` (declarative post-processing)
An ordered list of rules applied after mapping. Each rule may have:
- `when`: `{ field: matcher }` — ALL matchers must pass (AND). Matchers:
  `equals`, `contains` (case-insensitive substring), `in` (array),
  `matches` (regex, **case-insensitive**), `exists` (bool).
- `set`: `{ field: value }` — literal values.
- `extract`: `{ field: { from, pattern, group } }` — pull capture `group`
  (default 1) of `pattern` from another field.
- `overwrite`: default `false` (only fill empty fields). Set `true` to replace an
  existing value. With the default, an ordered list behaves like if/else-if
  (first match wins).

Example — derive a uniform failure marker and pull the IP out of the message:
```jsonc
"derivations": [
  { "extract": { "source_ip": { "from": "message", "pattern": "from (\\d{1,3}(?:\\.\\d{1,3}){3})" } } },
  { "when": { "message": { "contains": "authentication failed" } }, "set": { "event": "login_failure" } }
]
```

## test_samples — your parser's contract

Every catalog parser must ship self-tests. Each sample is a raw `input` and the
canonical fields it must `expect`:

```jsonc
{ "input": "Jan 1 12:00:00 host app: login failed from 203.0.113.5",
  "expect": { "source_ip": "203.0.113.5", "event": "login_failure" },
  "packet_source_ip": "10.0.0.1"   // optional: simulate the syslog sender
}
```

How they're checked (`runSelfTests`):
- The `input` is run through the full pipeline (match → map → derive → normalize).
- Each field in `expect` is compared to the produced value (string-coerced).
- Use `null` to assert a field is **absent** (e.g. `"auth_outcome": null`).
- `expect` is a **subset** — extra produced fields are fine. Assert the fields
  your detections rely on.

Guidelines:
- Use **real** log lines (redact secrets/real IPs; `203.0.113.0/24`, `198.51.100.0/24`
  are documentation ranges).
- Cover each distinct event your parser surfaces (e.g. a failure AND a success).
- Don't assert environment-dependent fields (GeoIP `country`, timestamps you
  don't normalize).

## CI gate

The **Validate Parser Catalog** workflow runs on every PR touching `catalog/**`.
It builds the validator and runs, for each file, strict schema validation +
all self-tests:

```bash
cd backend
npm ci && npm run build
npm run validate-parsers -- ../catalog/parsers
```

Strict mode also requires a kebab-case `name` and at least one `test_sample`.
Reproduce failures locally with the same command before pushing.

## PR checklist

- [ ] `catalog/parsers/<name>.parser.json` with a kebab-case `name`.
- [ ] Fields mapped to canonical names where possible.
- [ ] ≥1 `test_sample` per distinct event, using real (redacted) log lines.
- [ ] `npm run validate-parsers -- ../catalog/parsers` passes locally.
- [ ] `priority` chosen to not collide with an existing parser for the same log.
