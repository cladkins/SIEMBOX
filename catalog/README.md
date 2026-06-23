# SIEMBox parser & detection catalog

Portable, community-shareable **parsers** (and, later, detections) for SIEMBox.
Each parser is a self-contained `*.parser.json` file: a match pattern, field
mappings to the canonical schema, declarative `derivations`, and `test_samples`
that assert the canonical fields the parser must produce.

The promise: **a parser that passes CI here imports into SIEMBox and behaves
identically**, because the catalog's CI runs the exact same
parse → derive → normalize pipeline the app uses (`backend/src/services/parser/runParser.ts`).

> The canonical community catalog now lives in the standalone repo
> **[cladkins/siembox-parsers](https://github.com/cladkins/siembox-parsers)** —
> that's what SIEMBox installs from in-app (the default
> `PARSER_CATALOG_REPO=cladkins/siembox-parsers`). This `catalog/` directory is the
> **seed + engine test fixtures**: the main repo's CI validates these parsers on
> every engine change (regression guard), and `scripts/bootstrap-siembox-parsers.sh`
> seeds/refreshes the standalone repo from here.

## Layout

```
catalog/
  parsers/         *.parser.json   — one portable parser per file
  schema/          parser.schema.json — JSON Schema (editor autocomplete + docs)
  README.md
  CONTRIBUTING.md  — how to add a parser (read this before submitting)
```

## Install in-app

SIEMBox can browse and install these parsers directly (Parsers → **Browse Catalog**).
The backend lists the source repo's tree, pulls each `*.parser.json` from
`raw.githubusercontent`, **validates + runs its self-tests**, and only then upserts
it — flagging each as installed / update-available via a content signature. The
source is configurable:

| env var | default | meaning |
|---------|---------|---------|
| `PARSER_CATALOG_REPO` | `cladkins/siembox-parsers` | `owner/repo` to fetch from |
| `PARSER_CATALOG_REF`  | `main` | branch/tag/sha |
| `PARSER_CATALOG_PATH` | `parsers` | directory within the repo |
| `PARSER_CATALOG_TOKEN` / `GITHUB_TOKEN` | — | optional; raises GitHub API rate limit / private repos |

## Validate locally

The validator is shipped with the backend and needs no database:

```bash
cd backend
npm ci && npm run build
npm run validate-parsers -- ../catalog/parsers      # a dir, or specific files
```

It exits non-zero if any file fails strict schema validation or any self-test.
The same command runs in CI on every pull request (`.github/workflows/validate-catalog.yml`).

## What's here

| Parser | Source log | Demonstrates |
|--------|-----------|--------------|
| `jellyfin` | Jellyfin server log | `extract` (user+IP), `set` event, `service` pin |
| `plex` | Plex Media Server log | multi-`extract`, `in` matcher, `overwrite` |
| `home-assistant` | `home-assistant.log` | ordered `extract` fallbacks, `matches` |
| `authentik-audit` | Authentik audit JSON | `json` parser, `overwrite` on existing field |

See [CONTRIBUTING.md](./CONTRIBUTING.md) to add your own.
