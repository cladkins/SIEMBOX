# SIEMBox

Self-hosted SIEM: Express/TypeScript backend (`backend/`), Vue 3 + Element Plus
frontend (`frontend/`), PostgreSQL with JSONB log storage, deployed via Docker
Compose (`compose.yaml` builds from source, `compose.prod.yaml` runs GHCR
images). Optional components: the log shipper (`log-shipper/`) and the Go
endpoint agent (separate repo, `cladkins/siembox-endpoint`). Web UI on 8420,
API on 8421, syslog ingestion on 514 UDP/TCP.

## Gotchas

**Don't run `docker compose` here.** The app is deployed and tested on a remote
Docker host; this environment is for code and git only.

**Migrations re-run on every startup.** `npm run migrate` executes every file
in `backend/migrations/` in sorted order with no tracking table, so every
migration must be idempotent (`CREATE TABLE IF NOT EXISTS`,
`ADD COLUMN IF NOT EXISTS`, guarded updates). Schema changes go in a new
numbered file — see `023_shipper_containers.sql` for the expected style.

**Parsers match only the extracted message.** Syslog handling is two-stage:
`backend/src/services/syslog/syslogParser.ts` strips the
`<PRI>TIMESTAMP HOSTNAME TAG:` header and stores just the message portion in
`raw_logs.raw_message`; the parser engine
(`backend/src/services/parser/parserEngine.ts`) matches parsers against that.
A pattern written for the full syslog line will never fire. Lower `priority`
numbers match first.

**Catalog content is authored here, not in siembox-catalog.** `catalog/parsers/`
and `rules/` in this repo are the source of truth; the published
`cladkins/siembox-catalog` repo is a mirror updated weekly by
`.github/workflows/sync-catalog.yml` (via PR). Fresh installs ship zero parsers
and detections — users install from the catalog — so new content belongs in the
catalog directories, never in migrations. Validate before pushing:

```bash
cd backend && npm run build
npm run validate-parsers -- ../catalog/parsers
npm run validate-detections -- ../rules
```

**Ghost shippers are intentional.** A shipper whose API key is revoked keeps
sending logs using its cached config and surfaces in the UI as an unknown
source — that is a designed remediation path, not a bug. See
`log-shipper/shipper-managed.sh` and `docs/operations/SHIPPER-DIAGNOSTICS.md`.

## Working here

- Backend: `cd backend && npm run dev` / `test` / `lint`. Frontend:
  `cd frontend && npm run dev` / `type-check` / `lint`.
- When behavior changes, update the matching doc: `docs/reference/API.md`,
  `PARSERS.md`, `RULES.md`, `DEPLOYMENT.md`, or
  `docs/operations/TROUBLESHOOTING.md`.
