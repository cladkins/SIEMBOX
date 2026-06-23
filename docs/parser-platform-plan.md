# Parser platform plan — declarative parsers, hub, AI builder, recommendations

Goal: let users onboard *their own* log sources without engine code, share
parsers/detections via a community hub, generate parsers from a log sample with
AI, and proactively recommend parsers for logs already arriving.

## Throughline
Everything depends on one keystone: **a parser is a self-contained, declarative,
portable artifact** — `match` (pattern) + `fields` (→ canonical) + `derive`
(data-driven, replacing hardcoded `postProcessFields`) + `test_samples`. Once a
parser is data, it can be created in-app, shared, AI-generated, and matched by a
recommender.

## What already exists (reused, not rebuilt)
- Parser CRUD + live testing: `POST /parsers/test` runs an ad-hoc parser via
  `parserEngine.testParser`; `parsers.test_samples` column exists.
- Hub fetch pattern: the Nuclei integration pulls a GitHub tarball
  (`templateService.ts`) — the mechanism a parser/detection hub needs.
- Detections are already portable YAML under `rules/` with an upserting importer.

## Phases
- **Phase 0 — canonical schema** (`docs/canonical-schema.md`). ✅
- **Phase 1 — declarative engine (keystone).** ✅ `derive` interpreter
  (`services/parser/derive.ts`: `when` matchers + `set` literals + `extract`
  regex-capture) + a `derivations` JSONB field on parsers; the engine applies
  them generically. ALL hardcoded `postProcessFields` per-parser logic is now data
  (Vaultwarden → migration 010; Authelia/authentik/Keycloak/Home Assistant/
  Jellyfin/Plex → migration 011). `parserEngine.postProcessFields` retains only
  the generic CEF-extension split, the `applyDerivations` call, and the shared
  `auth_outcome` marker — no per-parser branches remain. A faithfulness check
  confirmed the data path reproduces the deleted blocks byte-for-byte.
- **Phase 2 — in-app catalog/hub.** *(mostly done)*
  - ✅ Portable parser format (`siembox.parser/v1`) + shared validator + self-test
    runner (`parserPortable.ts`), reused by import AND the catalog CI.
  - ✅ Export/import endpoints + UI (`GET /parsers/:id/export`, `POST /parsers/{validate,import}`).
  - ✅ In-app **browse/install** from a GitHub repo (`catalogService.ts`,
    `GET /parsers/catalog`, `POST /parsers/catalog/install`) — lists the repo tree,
    pulls each `*.parser.json` from raw.githubusercontent, validates + self-tests
    before upsert, and flags installed / update-available via a content signature.
    Source is configurable (`PARSER_CATALOG_REPO/REF/PATH`), defaulting to this
    repo's `catalog/`.
  - ✅ CI gate for submissions (`validate-parsers` + `validate-detections` CLIs +
    `.github/workflows/validate-catalog.yml`).
  - ✅ Standalone catalog repo (`cladkins/siembox-parsers`, → rename to
    `siembox-catalog`) seeded by `scripts/bootstrap-siembox-parsers.sh`.
  - ✅ **Detections in the catalog**: rule validator (`rulePortable.ts`) + detection
    catalog hub (`detectionCatalog.ts`, `GET /rules/catalog`,
    `POST /rules/catalog/install`) + Browse Catalog on the Detection Rules page.
    One repo holds `parsers/` + `detections/`.
- **Phase 3 — AI builder (parsers AND detections).** Paste a log sample → LLM
  proposes a declarative parser → run through the validator + self-tests → auto-
  refine loop → save/export. Same for detections: describe the threat → LLM
  proposes a rule → validate against the engine contract → refine. Provider
  abstraction, bring-your-own-key (Anthropic default = latest Claude, + OpenAI +
  Ollama; key encrypted at rest or via env). *Backend done (`services/ai/aiService.ts`,
  `POST /parsers/ai/generate`, `POST /rules/ai/generate`, `GET/PUT /settings/ai`);
  frontend next.*
- **Phase 4 — recommendation engine.** Watch logs hitting the generic fallback
  (priority 1000 = unrecognized), fingerprint them, and either recommend an
  existing hub parser or kick off the AI builder from a snippet.

## Status
Phase 0 done. **Phase 1 done** — the engine is fully data-driven; onboarding a new
log source needs only parser data (pattern + field_mappings + derivations), no
engine code. **Phase 2 done** — portable parsers + detections, export/import, in-app
catalog browse/install for both, a standalone catalog repo, and the submission CI
gate all landed. The whole catalog (27 parsers + 48 detections) is installable
from a repo in-app. Next: Phase 3 (AI parser builder).

## Backlog / follow-ups
- ✅ **Catalog UX: filtering + sorting.** Both Browse Catalog dialogs now have a
  search box (name/tag/description), status (+ severity for detections) filters, a
  result count, and sortable Name/Severity columns.
- **Behavioral rule fixtures (optional).** Detections have structural validation;
  add optional fire/no-fire fixtures for non-aggregation rules.
