# Detection Rules

A **detection rule** evaluates parsed, normalized log fields and raises an **alert** when it matches. Rules are **portable data** — install them from the catalog, generate them with AI, or write/import them as JSON. Because rules run against the [canonical schema](Parsers#canonical-fields--normalization), a rule written once fires against logs from any source that maps the same fields.

## Portable rule format

```jsonc
{
  "name": "ssh-brute-force",
  "description": "Many failed SSH logins from one source IP",
  "severity": "high",                 // low | medium | high | critical
  "enabled": true,
  "tags": ["ssh", "brute-force"],
  "conditions": [                      // ANDed together
    { "field": "service", "operator": "equals", "value": "sshd" },
    { "field": "event",   "operator": "equals", "value": "login_failure" }
  ],
  "aggregation": {                     // optional — for rate / threshold detections
    "field": "source_ip",
    "timeframe": "5m",                 // N s|m|h|d
    "threshold": 5,
    "distinct_count": "user"           // optional: count DISTINCT values instead
  },
  "alert": {
    "title": "SSH brute force from {source_ip}",
    "description": "{count} failed logins from {source_ip} in 5m"
  }
}
```

## Conditions

Each condition is `{ field, operator, value }`, and all conditions are **ANDed**. Keep them satisfiable by real parser output (e.g. `event="login_failure"`, `service="sshd"`).

**Supported operators:**

| Operator | Value | Meaning |
|----------|-------|---------|
| `equals` / `not_equals` | string/number | Exact (in)equality. |
| `contains` / `not_contains` | string | Substring match. |
| `regex` | regex string | Field matches the pattern. |
| `greater_than` / `less_than` | number | Numeric comparison. |
| `in` / `not_in` | comma-separated string **or** array | Membership. |
| `exists` | `true` / `false` | Field is present / absent. |

Common fields: `source_ip`, `dest_ip`, `source_port`, `dest_port`, `user`, `target_user`, `host`, `service`, `method`, `path`, `status_code`, `message`, `event`, `event_type`, `country`, `auth_outcome`.

## Aggregation (rate / brute-force / repeat)

Include `aggregation` for "N events in a window" detections; omit it for single-event rules.

- `field` — what to group by (usually `source_ip`).
- `timeframe` — `5m`, `1h`, `30s`, `1d`, …
- `threshold` — fire when the count reaches this.
- `distinct_count` *(optional)* — count **distinct** values of this field instead of raw events (e.g. one IP hitting many distinct `user`s = spray).

## Alert templating

`alert.title` and `alert.description` may interpolate field placeholders — `{source_ip}`, `{user}`, `{count}`, etc. — filled from the matching event/aggregate. Alerts can be delivered via **Email / Slack / NTFY** (configure under *Settings → Notifications*).

## Installing from the catalog

**Detection Rules → Browse Catalog** lists community rules (48 in the default catalog), each validated against the engine's operators/shape before install, with search, filters, and install/update status. Use **Install all**, or export/import any rule as portable JSON.

> SIEMBox is **catalog-only by default** — a fresh install has no rules until you install them. (Set `SEED_BUNDLED_CONTENT=true` to opt into the legacy bundled rules; see [Configuration](Configuration#parser--detection-catalog).)

## Importing Sigma rules

**Detection Rules → Import Sigma.** Paste one or more [Sigma](https://sigmahq.io) rules (YAML, `---` separated for multiple) to convert the huge body of community Sigma content into SIEMBox detections. **Preview** first to see exactly what will be created; **Import** then upserts them. Imported rules are created **disabled** so you review them before they fire.

Because the engine evaluates a flat AND-list of conditions, the converter maps everything that fits that model — single selections, `a and b`, `all of them`, the `contains`/`startswith`/`endswith`/`re`/`|all` modifiers, list values (as `in`), and `*`/`?` wildcards (as regex) — and is **honest about the rest**: rules needing `or` / `not` / `1 of` / event-count are reported and skipped, never silently mistranslated into a rule that quietly never (or always) fires. Sigma field names often differ from your parser output, so the preview lists the fields each rule keys on — verify they match your parsed logs.

## AI builder

**Detection Rules → Generate with AI.** Describe the threat in plain language (plus optional context about available fields); SIEMBox runs a **generate → validate → auto-refine** loop against the engine contract (≤3 attempts), so the rule it returns uses only supported operators and a satisfiable shape. Same providers/keys as the parser builder — see [Configuration](Configuration#ai-builder-optional).

## Deep reference

Full rule reference, operator semantics, and the bundled rule set: [docs/reference/RULES.md](https://github.com/cladkins/SIEMBOX/blob/main/docs/reference/RULES.md) · [Detection normalization](https://github.com/cladkins/SIEMBOX/blob/main/docs/detection-normalization.md) · [Detection coverage](https://github.com/cladkins/SIEMBOX/blob/main/docs/detection-coverage.md).
