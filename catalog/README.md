# SIEMBox parser & detection catalog

Portable, community-shareable **parsers** (and, later, detections) for SIEMBox.
Each parser is a self-contained `*.parser.json` file: a match pattern, field
mappings to the canonical schema, declarative `derivations`, and `test_samples`
that assert the canonical fields the parser must produce.

The promise: **a parser that passes CI here imports into SIEMBox and behaves
identically**, because the catalog's CI runs the exact same
parse → derive → normalize pipeline the app uses (`backend/src/services/parser/runParser.ts`).

> This directory is the staging home for the catalog while the platform is built.
> It is intended to graduate into a standalone `siembox-parsers` repository that
> SIEMBox fetches in-app (mirroring the Nuclei templates flow). The file format,
> validator, and CI here move over unchanged.

## Layout

```
catalog/
  parsers/         *.parser.json   — one portable parser per file
  schema/          parser.schema.json — JSON Schema (editor autocomplete + docs)
  README.md
  CONTRIBUTING.md  — how to add a parser (read this before submitting)
```

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
