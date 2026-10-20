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

## Content Packs

**Content Packs** (sidebar → **Content Packs**) are curated, per-technology bundles that install the right parsers **and** detections in one click — e.g. *Auth & Identity*, *Reverse Proxy & Web*, *Media Servers*, *DNS & Network*, *Linux & Infrastructure*. Each pack card shows how many of its parsers/detections are already installed, plus setup hints (which container, where the logs are). Installing pulls the referenced content from the catalog: detections apply immediately (the rules engine reloads); newly installed parsers take effect after the next backend restart, same as a normal catalog install. Packs are the fastest way to go from empty to covered for the stack you actually run.

## Importing Sigma rules

**Detection Rules → Import Sigma.** Paste one or more [Sigma](https://sigmahq.io) rules (YAML, `---` separated for multiple) to convert the huge body of community Sigma content into SIEMBox detections. **Preview** first to see exactly what will be created; **Import** then upserts them. Imported rules are created **disabled** so you review them before they fire.

A SIEMBox rule is an AND-list of conditions plus optional `exclude` groups, so the converter maps single selections, `a and b`, `all of them`, the `contains`/`startswith`/`endswith`/`re`/`|all` modifiers (lists become one regex alternation), list values (as `in`), `*`/`?` wildcards (as regex) and **keyword searches** (a selection that's a list of strings → a case-insensitive regex against the raw `message`). **OR** (`or`, `1 of selection_*`, a list of mappings) imports as one rule per alternative (at most 10, named `Title (part 1 of N)`), and **NOT** (`selection and not filter`) becomes the rule's `exclude` groups, with Sigma's semantics: a log missing the filter's field is not filtered out. It stays **honest about the rest**: NOT inside NOT and event counts (`| count`) are reported and skipped, never silently mistranslated into a rule that quietly never (or always) fires. Sigma field names often differ from your parser output, so the preview lists the fields each rule keys on — verify they match your parsed logs.

## MITRE ATT&CK

**Tag a rule.** In the rule editor (**Detection Rules → Add Rule / Edit**), the **ATT&CK** field searches the bundled ATT&CK Enterprise techniques by ID or name (`T1110`, `brute force`) and adds the pick as an `attack.t1110.001`-style tag; the chips under it show each technique's name and remove it. A tag ATT&CK no longer accepts (unknown, revoked or deprecated) is refused at save with the reason and the replacement at the top of the editor. The rules list and **Browse Catalog** show technique chips (name on hover) and filter by technique or tactic; in the catalog, **Fills a gap** marks a not-installed rule tagged with a technique you have no rule for.

**See your coverage.** **SIEM → ATT&CK Coverage** draws the matrix (tactic columns, technique cells) coloured by how well you detect each technique, each level also marked with a symbol and named on hover: *No rule*, *Disabled*, *No data* (an enabled rule, but no recent log satisfies it), *Covered* (matching logs arrive) and *Proven* (it alerted in the last 30 days). The page shows the percentage per tactic and overall, the platforms in scope (inferred from your data, with what implied each; change them in the Platforms filter), a sub-technique toggle, a search, and an **Alerts (30 d)** heatmap. Click a technique for its rules and why each has its level, its sub-techniques, catalog rules that would cover it, recent alerts (→ the Alerts list filtered by technique), and **Mark not applicable** (analysts and admins; it leaves the percentages). **Export Navigator layer** downloads the coverage for [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Every role can open the page; viewers can read and export it. The Alerts list shows each alert's techniques and filters by technique or tactic.

## AI builder

**Detection Rules → Generate with AI.** Describe the threat in plain language (plus optional context about available fields); SIEMBox runs a **generate → validate → auto-refine** loop against the engine contract (≤3 attempts), so the rule it returns uses only supported operators and a satisfiable shape. Same providers/keys as the parser builder — see [Configuration](Configuration#ai-builder-optional).

## Deep reference

Full rule reference, operator semantics, and the bundled rule set: [docs/reference/RULES.md](https://github.com/cladkins/SIEMBOX/blob/main/docs/reference/RULES.md) · [Detection normalization](https://github.com/cladkins/SIEMBOX/blob/main/docs/detection-normalization.md) · [Detection coverage](https://github.com/cladkins/SIEMBOX/blob/main/docs/detection-coverage.md).
