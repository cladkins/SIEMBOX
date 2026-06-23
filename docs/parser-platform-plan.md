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
- **Phase 2 — in-app catalog/hub.** A `siembox-parsers` GitHub repo of
  declarative parsers + detections; fetch/browse/install/update in-app (mirror
  the Nuclei tarball pattern); parser export/import.
- **Phase 3 — AI parser builder.** Paste a sample → LLM proposes a declarative
  parser → run through `testParser` against samples → refine loop → save/export.
  Provider abstraction, bring-your-own-key (Anthropic default = latest Claude,
  + OpenAI + Ollama).
- **Phase 4 — recommendation engine.** Watch logs hitting the generic fallback
  (priority 1000 = unrecognized), fingerprint them, and either recommend an
  existing hub parser or kick off the AI builder from a snippet.

## Status
Phase 0 done. **Phase 1 done** — the engine is fully data-driven; onboarding a new
log source needs only parser data (pattern + field_mappings + derivations), no
engine code. Next: Phase 2 (in-app catalog/hub).
