#!/usr/bin/env bash
#
# Seed (or refresh) the standalone community catalog repo, cladkins/siembox-parsers,
# from this SIEMBox checkout's catalog/. The portable parsers + JSON Schema are
# copied verbatim; the repo's README / CONTRIBUTING / CI / LICENSE are generated
# here so this script is their single source of truth.
#
# Usage:
#   scripts/bootstrap-siembox-parsers.sh <target-dir>
#
# Then:
#   cd <target-dir> && git add -A && git commit -m "Seed parser catalog" && git push
#
# Note: the catalog CI checks out cladkins/SIEMBOX@main to build the validator, so
# merge the SIEMBox branch that adds backend/src/scripts/validate-parsers.ts to main
# first (otherwise the catalog repo's first CI run can't find the validator).
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:?usage: scripts/bootstrap-siembox-parsers.sh <target-dir>}"

mkdir -p "$TARGET/parsers" "$TARGET/schema" "$TARGET/.github/workflows"
cp "$HERE"/catalog/parsers/*.parser.json "$TARGET/parsers/"
cp "$HERE"/catalog/schema/parser.schema.json "$TARGET/schema/"
cp "$HERE"/LICENSE "$TARGET/LICENSE"

cat > "$TARGET/.github/workflows/validate.yml" <<'YML'
name: Validate parsers

# Gate every submission: each portable parser must pass strict schema validation
# AND its own self-tests, run through the real SIEMBox parse -> derive -> normalize
# pipeline. The validator lives in the SIEMBox repo (public), so we check it out
# and build it — a parser that passes here imports into SIEMBox and behaves
# identically.
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

# Pin the validator to a known-good SIEMBox ref; bump to upgrade the engine.
env:
  SIEMBOX_REF: main

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout catalog
        uses: actions/checkout@v5

      - name: Checkout validator (SIEMBox)
        uses: actions/checkout@v5
        with:
          repository: cladkins/SIEMBOX
          ref: ${{ env.SIEMBOX_REF }}
          path: .siembox

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
          cache-dependency-path: .siembox/backend/package-lock.json

      - name: Build validator
        working-directory: .siembox/backend
        run: npm ci && npm run build

      - name: Validate parsers (strict + self-tests)
        run: node .siembox/backend/dist/scripts/validate-parsers.js "$GITHUB_WORKSPACE/parsers"
YML

cat > "$TARGET/README.md" <<'MD'
# siembox-parsers

Community catalog of portable **parsers** (and, soon, detections) for
[SIEMBox](https://github.com/cladkins/SIEMBOX). Each parser is a self-contained
`*.parser.json` file: a match pattern, field mappings to SIEMBox's canonical
schema, declarative `derivations`, and `test_samples` that assert the canonical
fields it must produce.

The promise: **a parser that passes CI here installs into SIEMBox and behaves
identically**, because CI runs the exact same parse -> derive -> normalize pipeline
the app uses.

## Install in-app

In SIEMBox: **Parsers -> Browse Catalog**. SIEMBox lists this repo's tree, pulls
each `parsers/*.parser.json` from `raw.githubusercontent`, **validates + runs its
self-tests**, then upserts — flagging each as installed / update-available. Point
SIEMBox here with:

```
PARSER_CATALOG_REPO=cladkins/siembox-parsers
PARSER_CATALOG_REF=main
PARSER_CATALOG_PATH=parsers
```

(These are the defaults in current SIEMBox builds.)

## Layout

```
parsers/   *.parser.json   — one portable parser per file
schema/    parser.schema.json — JSON Schema (editor autocomplete + docs)
```

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md). In short: add
`parsers/<name>.parser.json` with canonical field mappings and at least one
`test_sample`, open a PR, and make the **Validate parsers** check green.

## License

MIT — see [LICENSE](./LICENSE).
MD

cat > "$TARGET/CONTRIBUTING.md" <<'MD'
# Contributing a parser

Thanks for adding a log source to SIEMBox! A parser is **data, not code** — you
describe how to recognize a log line and what canonical fields it produces, and
ship `test_samples` that prove it. CI runs your self-tests through the real
SIEMBox engine, so if it passes here it works in SIEMBox.

## TL;DR

1. Add `parsers/<name>.parser.json` (kebab-case name).
2. Map captured fields to **canonical** names (`source_ip`, `user`, `status_code`, ...).
3. Add at least one `test_sample` asserting the canonical fields, using a real
   (redacted) log line.
4. Open a PR. The **Validate parsers** check must be green.

Tip: if you already run SIEMBox, build the parser in the UI and export it
(Parsers -> Export) as a starting point.

## File format

Authoritative schema: [`schema/parser.schema.json`](./schema/parser.schema.json)
(point your editor at it for autocomplete).

- `parser_type`: `regex` | `json` | `grok`.
- `field_mappings`: regex `{ captureGroup: canonicalField }`, json `{ jsonKey: canonicalField }`.
  Map to canonical names so detections match regardless of source: `source_ip`,
  `dest_ip`, `source_port`, `dest_port`, `user`, `target_user`, `host`, `service`,
  `method`, `path`, `status_code`, `message`. The normalizer fills aliases
  (`client_ip`/`src_ip` -> `source_ip`) and mirrors `source_ip` <-> `client_ip`.
- `derivations`: ordered post-processing. Each rule may have `when`
  (`equals`/`contains`/`in`/`matches`/`exists`; `contains` & `matches` are
  case-insensitive), `set` (literals), `extract` (`{from, pattern, group}` — pull a
  regex capture from another field), and `overwrite` (default false = fill empty
  only; first match wins).

## test_samples — your parser's contract

Every parser must ship self-tests. Each is a raw `input` and the canonical fields
it must `expect`:

- The `input` runs through the full pipeline (match -> map -> derive -> normalize).
- Each `expect` field is compared to the produced value (string-coerced).
- Use `null` to assert a field is **absent** (e.g. `"auth_outcome": null`).
- `expect` is a **subset** — extra produced fields are fine.
- Use real log lines, redacted to documentation ranges (`203.0.113.0/24`,
  `198.51.100.0/24`). Cover each distinct event your parser surfaces.

## Validate locally

CI does this automatically. To reproduce locally, build the validator from SIEMBox:

```bash
git clone https://github.com/cladkins/SIEMBOX
cd SIEMBOX/backend && npm ci && npm run build
npm run validate-parsers -- /path/to/siembox-parsers/parsers
```

Strict mode requires a kebab-case `name` and >=1 `test_sample`. It exits non-zero
with precise per-field diffs on any failure.

## PR checklist

- [ ] `parsers/<name>.parser.json` with a kebab-case `name`.
- [ ] Fields mapped to canonical names where possible.
- [ ] >=1 `test_sample` per distinct event, using real (redacted) log lines.
- [ ] **Validate parsers** CI check is green.
MD

echo "Seeded $TARGET from $HERE/catalog"
echo
echo "Next:"
echo "  cd \"$TARGET\""
echo "  git add -A && git commit -m \"Seed parser catalog from SIEMBox\" && git push"
