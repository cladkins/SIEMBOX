# SIEMBox parser & detection catalog

Portable, community-shareable **parsers** and **detections** for SIEMBox. Each
parser is a self-contained `*.parser.json` file (a match pattern, field mappings
to the canonical schema, declarative `derivations`, and `test_samples` that
assert the canonical fields it must produce); each detection is a portable
`*.yaml` rule.

The promise: **content that passes CI here imports into SIEMBox and behaves
identically**, because CI runs the exact same parse → derive → normalize
pipeline the app uses (`backend/src/services/parser/runParser.ts`) plus the same
strict validators and — for parsers — a ReDoS scan.

> This catalog lives **in the main SIEMBOX repo** (under `catalog/`) and SIEMBox
> installs from it in-app by default (`SIEMBOX_CATALOG_REPO=cladkins/SIEMBOX`,
> `catalog/parsers` + `catalog/detections`). Because the app fetches content at
> **runtime** from GitHub — nothing is compiled into the image or seeded into the
> database — a merged parser/detection is installable within the catalog cache
> TTL (~5 min), no image rebuild required. To serve your own curated set, point
> `SIEMBOX_CATALOG_REPO` at a fork.

## Layout

```
catalog/
  parsers/         *.parser.json   — one portable parser per file
  detections/      <category>/*.yaml — portable detection rules, grouped by category
  schema/          parser.schema.json — JSON Schema (editor autocomplete + docs)
  README.md
  CONTRIBUTING.md  — how to add a parser or detection (read this before submitting)
```

## Install in-app

Parsers install from **Parsers → Browse Catalog**; detection rules from
**Detection Rules → Browse Catalog**. Both list the source repo's tree, pull each
file from `raw.githubusercontent`, **validate + (for parsers) run self-tests**,
and upsert — flagging each as installed / update-available via a content
signature. The source is configurable:

| env var | default | meaning |
|---------|---------|---------|
| `SIEMBOX_CATALOG_REPO` (or legacy `PARSER_CATALOG_REPO`) | `cladkins/SIEMBOX` | `owner/repo` to fetch from |
| `SIEMBOX_CATALOG_REF` (or `PARSER_CATALOG_REF`) | `main` | branch/tag/sha |
| `SIEMBOX_CATALOG_PARSERS_PATH` (or `PARSER_CATALOG_PATH`) | `catalog/parsers` | parser directory within the repo |
| `SIEMBOX_CATALOG_DETECTIONS_PATH` | `catalog/detections` | detection-rule directory within the repo |
| `SIEMBOX_CATALOG_TOKEN` / `GITHUB_TOKEN` | — | optional; raises GitHub API rate limit / private repos |

## Contribute (no local setup needed)

In the app, open a parser or rule → **Contribute to catalog**. SIEMBox exports it,
runs the full validator + self-test + ReDoS gate, and — only if clean — gives you
a one-click GitHub "propose new file" link pre-filled at
`catalog/parsers/<name>.parser.json` (or `catalog/detections/…`). You finish the
PR in your own browser; nothing is auto-committed and SIEMBox never holds a
credential. CI + maintainer review are the merge gate.

## Validate locally

The validator ships with the backend and needs no database:

```bash
cd backend
npm ci && npm run build
npm run validate-parsers   -- ../catalog/parsers      # strict schema + self-tests + ReDoS
npm run validate-detections -- ../catalog/detections  # strict structural validation
```

Each exits non-zero if any file fails. The same commands run in CI on every pull
request that touches `catalog/**` or the engine (`.github/workflows/validate-catalog.yml`).

See [CONTRIBUTING.md](./CONTRIBUTING.md) to add your own.
