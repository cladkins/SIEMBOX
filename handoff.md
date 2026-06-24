# SIEMBox — Session Handoff

> Working branch: **`claude/exciting-mccarthy-qrzfog`**. The parser platform + AI builder are merged to `main` via PRs (#55–#67). The **V2 stabilization punch list** (Issues 2/4/3 + security sweep + docs, commits `abacebf`..`5fb5be0`) is **pushed to the branch but not yet merged to `main`** — open a PR to land it. This file is the bridge to a fresh context.

## How to operate (important mechanics)
- **Direct `git push` to `main` is blocked** by the harness (HTTP 403). To land on main: commit+push to the branch, then **open a PR and merge it via the GitHub MCP tools** (`mcp__github__create_pull_request` + `mcp__github__merge_pull_request`, owner `cladkins`, repo `siembox`). That path works; direct push does not.
- After merging, **sync the branch**: `git fetch origin main && git merge origin/main --no-edit && git push origin <branch>`.
- **GitHub MCP scope = `cladkins/siembox` only.** Cannot push to `cladkins/siembox-parsers` (the catalog repo) — the user populates that themselves via `scripts/bootstrap-siembox-parsers.sh`.
- **Deploy model:** backend/frontend ship as images (`ghcr.io/cladkins/siembox-{backend,frontend}:latest`), built by `.github/workflows/build-containers.yml` on push to `main`. Migrations are COPIED into the backend image and run on startup (idempotent, no version table). `rules/` is a **volume mount** (`./rules:/app/rules`), so rule changes need a host `git pull`. Host update: `git pull && docker compose -f compose.prod.yaml pull && up -d`, then hard-refresh the browser.
- Commit trailer in use: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` + the `Claude-Session:` line. PR bodies end with the Claude Code generated-with footer.

## What's DONE and merged (the parser platform — V2 headline)
- **Phase 1 — declarative engine.** All per-parser logic is data: `services/parser/derive.ts` (`when`/`set`/`extract`), migrations `010`/`011`. The parse→derive→normalize pipeline is DB-free in **`services/parser/runParser.ts`**, shared by production AND the validator/CI. `parserEngine.ts` just orchestrates.
- **Phase 2 — portable catalog (parsers + detections).** `siembox.parser/v1` format + validator + self-tests (`parserPortable.ts`); rule validator (`rulePortable.ts`). Export/import + **in-app Browse Catalog** for both (`catalogService.ts`, `detectionCatalog.ts`; endpoints on `routes/parsers.ts` + `routes/rules.ts`). Catalog has **27 parsers + 48 detections** under `catalog/parsers/` and `rules/`. CLIs `validate-parsers` / `validate-detections` + `.github/workflows/validate-catalog.yml`. Standalone repo **`cladkins/siembox-parsers`** (user may rename → `siembox-catalog`; default works either way via GitHub redirect) seeded by `scripts/bootstrap-siembox-parsers.sh`. Browse Catalog dialogs have **search + filters + sorting** (PR #65).
- **Phase 3 — AI builder (parsers AND detections).** `services/ai/aiService.ts`: provider abstraction (Anthropic/OpenAI/Ollama, BYO key, key encrypted at rest via `CredentialEncryption` or env `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`). `generateParser`/`generateDetection` run a **generate→validate→auto-refine loop (≤3 attempts)** — never trusts the LLM blind. Endpoints `POST /parsers/ai/generate`, `POST /rules/ai/generate`, `GET/PUT /settings/ai`. UI: "Generate with AI" on Parsers + Detection Rules pages, "AI Builder" card in Settings. **Verified working by the user.**
- **Deploy plumbing:** `compose.prod.yaml` now passes `CREDENTIAL_ENCRYPTION_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `SIEMBOX_CATALOG_*`, `GITHUB_TOKEN`, and `extra_hosts: host.docker.internal:host-gateway` (for local Ollama). AI request timeouts: axios 240s (#62), nginx `/api` `proxy_read_timeout 300s` (#64), backend per-call 120s (#61).

## Status RIGHT NOW
- `1db04e5` (link fix 3a) is pushed and merged — handled in an earlier pass.
- **The entire V2 punch list below (Issues 2/4/3 + the security sweep + the docs refresh) is DONE and pushed** to `claude/exciting-mccarthy-qrzfog` (commits `abacebf`, `4477ad5`, `286c974`, `c1b553b`, `4b501be`, `5fb5be0`), **but not yet merged to `main`** — open a PR + merge via the GitHub MCP when ready. Working tree is clean.
- **Only remaining V2 action: publish the v2.0.0 GitHub Release (manual — item 7).**

---

## V2 SHIP CUT (recommended)
**V2 = stabilize + secure what's built.** The parser platform + AI builder are done; ship them with the vuln-UI/dashboard bugs fixed and the dependency vulns knocked down. Keep the bundled parsers/detections (good out-of-box). Net-new features → V3.

### V2 punch list — ✅ DONE (commits on the branch, awaiting merge to `main`)
1. ✅ **Vuln "results combining"** — `abacebf`. Assets keyed on each finding's `matched-at` host (not the scan target); migration `012` widens `cve_id` to VARCHAR(255) so `NUCLEI-*` findings persist; dropped findings surfaced via `ErrorLogService`; scan headline count reconciled to the persisted count.
2. ✅ **Dashboard zeros** — `4477ad5`. Cards read the real API fields (`active_assets`/`offline_assets`, `critical_count`/`total_vulnerabilities`); charts rebuild in a `watch(alertStats)` with destroy-before-recreate. 4e was a no-op in element-plus 2.x (`primary` is valid) — intentionally left.
3. ✅ **Dead/malformed links** — `286c974`. 3b/3d: references + CVE link only linkify real http(s) URLs / real `CVE-` ids via shared `safeHttpUrl`/`isCveId`; 3c: `Assets.vue` now consumes `?id=` and deep-links to the asset (resolves correctly given the Issue-2 per-host assets).
4. ✅ **Security sweep** — backend `c1b553b` (22 → **1 in the production image**; the rest are dev-only; key win was bcrypt 5→6 dropping node-pre-gyp/tar, musl+glibc prebuilts verified for alpine), frontend `4b501be` (29 → 11; **both criticals + all bundled-runtime highs cleared**; residual 11 are dev/build tooling needing vite@8/vue-tsc@3 majors — deferred, not forced blind).
5. ✅ (Decision) Kept bundled parsers/detections for V2.
6. ✅ **README + docs refresh** — `5fb5be0`. README/DEPLOYMENT/docs-README/API/SECURITY/.env.example + v2.0.0 notes brought to v2 (27 parsers + 48 detections, catalog, AI builder, normalization, GeoIP, new env vars; API.md gained a Catalog & AI Builder section; SECURITY.md gained credential-encryption/AI-data-flow/catalog-trust sections). Archived docs under `docs/archive/` left as historical snapshots.
7. ⏳ **Publish the v2.0.0 GitHub Release (manual — agent can't).** Notes drafted in **`docs/releases/v2.0.0.md`** (its "known issues" are now marked fixed). Tag/release pushes are **blocked by the harness (403)**, and the GitHub MCP has no create-release tool — so a human must publish it: GitHub → Releases → *Draft a new release* → create tag **`v2.0.0`** targeting `main` (after this branch merges) → title "SIEMBox v2.0.0 — The Parser Platform" → paste `docs/releases/v2.0.0.md` → Publish. Publishing triggers `build-containers` to push **semver-tagged** images (`v2.0.0`, `2.0`, `2`). (Or run `gh release create v2.0.0 --notes-file docs/releases/v2.0.0.md` from a machine with `gh`.)


### V3 backlog — ✅ DONE (commits on the branch; build/typecheck-verified, not live-tested)
- ✅ **GeoIP dashboard "map"** — `82a1558`. `AlertModel.getCountByCountry` + `GET /api/alerts/by-country` (no migration — country is already in `alerts.matched_data`); Dashboard "Alerts by Country" bar (foreign vs domestic). Built offline (bar/table, not a CDN choropleth) to keep the no-external-calls property; bundled-topojson choropleth is an optional later enhancement.
- ✅ **In-app AI assistant ("explain this")** — `de21119`. `aiService.explain()` (reuses the provider/key; `callProvider` gained a `json` flag for prose) + `POST /api/ai/explain` (any authed user) + reusable `<ExplainWithAI>` component wired into alert + vuln detail (renders as safe pre-wrapped text). Drops into logs/incidents next.
- ✅ **Expanded scheduled-scan options** — `9f3a32a`. Settings scheduled-scan form now has the one-off scan's all/cves/category/tags/custom template selection + severities (UI-only; the job already forwarded `templateSelection`). Clock-anchored cron/time-of-day still needs a migration — not done.
- ⚠️ **Remove bundled seeding + "Install all"** — `d884196`. "Install all" (both catalogs, bulk endpoints + buttons) is **full**. `SEED_BUNDLED_CONTENT=false` skips the **importRules** bundled-detection seed. **Partial:** the migration-seeded baseline (002's parsers + sample rules, 008/009 parsers) still seeds — those INSERTs are interleaved with schema + the admin user (002 = admin + content; 010 = ADD COLUMN + data) and the parser-fix migrations depend on seed-then-fix order, so a clean parser opt-out needs a **migration refactor best done against a live DB**.
- ✅ **Container vulnerability scanning (Trivy)** — `91e8ae7`. Migration 013 (container_scans/container_vulnerabilities), `TrivyScanner` (image scan, no Docker socket), `routes/containers.ts` at `/api/containers`, Trivy installed per-arch in the backend image, `ContainerScanning.vue` view + nav + a `trivy-cache` volume. **Needs a live scan to confirm** Trivy pulls/scans in the alpine image (and that `TRIVY_VERSION=0.58.1` is the desired pin).

---

## EXACT FIXES (from the read-only investigation, file:line verified)

### Issue 2 — Results "combining" (V2, do first) — `backend/src/services/scanner/nucleiScanner.ts`
Root causes:
- **Asset keyed on the scan target, not the host.** `processNucleiResult` (~`:461-477`) sets `target` = the scan target string (CIDR `192.168.1.1/24`); `storeVulnerability` (~`:533-544`) does `INSERT INTO assets (ip_address) VALUES (vuln.target)`. So every host in a `/24` collapses onto one synthetic asset. **Fix:** derive the asset IP from `result['matched-at']` (strip scheme/port), fall back to `target` only when absent.
- **`cve_id VARCHAR(20)` overflow.** `001_initial_schema.sql:245` is `cve_id VARCHAR(20) UNIQUE NOT NULL`, but non-CVE findings use `NUCLEI-<templateId>` (often >20 chars) stored in `cve_id` (`nucleiScanner.ts:493`). The insert throws "value too long", the `BEGIN…COMMIT` (`:489-564`) **rolls back**, and the finding is silently dropped (catch at `:565`). → "22 found, 1 stored." **Fix:** add a dedicated `template_id`/`finding_key` column (or widen `cve_id` to `VARCHAR(255)`) via migration + adjust the unique constraint; stop overloading `cve_id` for non-CVE.
- **Surface failures:** the catch at `:565-568` should report dropped findings (e.g. `ErrorLogService`), not just `console.error`.
- **Count mismatch:** per-scan "Vulns Found" = `results.length` (`:357`, raw Nuclei lines), Management counts `COUNT(DISTINCT av.id)` (`routes/vulnerabilities.ts:603-612`). Reconcile (set `vulnerabilities_found` to persisted count, or show "raw vs stored" distinctly).

### Issue 4 — Dashboard zeros (V2) — `frontend/src/views/Dashboard.vue`
- **4a** `:77` reads `assetStats?.total`, `:91` reads `assetStats?.online` — API (`GET /assets/statistics` → `autoDiscoveryService.getStatistics()`) returns `active_assets`/`offline_assets` (no `total`/`online`). → permanent 0. **Fix:** use `active_assets` and `active_assets + offline_assets`.
- **4b** `:105` reads `vulnStats?.critical`, `:119` reads `vulnStats?.total` — API (`GET /vulnerabilities/summary` → `vulnerabilityProcessor.getVulnerabilityStats()` `:432-471`) returns `critical_count`/`total_vulnerabilities`. → permanent 0. **Fix:** read `critical_count` / `total_vulnerabilities` (matches `VulnerabilityManagement.vue:19,64`).
- **4c** Charts: `createCharts()` runs once in `onMounted` after `loadData()`; if `alertStats` null it early-returns (`:268`) and never re-renders. **Fix:** build charts in a `watch(alertStats,…)`, `.destroy()` before recreate.
- **4e** (minor) `getSeverityType('medium')` returns `'primary'` (invalid `el-tag` type); use `''`/`warning`.

### Issue 3 — Links (V2) — `frontend/src/views/VulnerabilityManagement.vue`
- **3a Matched URL — FIXED** (commit `1db04e5`): added `matchedUrlHref(row)` that only linkifies `^https?://`, else plain text.
- **3b References (`~:191-198`)** — same scheme-less bug: `<el-link :href="ref">` for `row.references` straight from Nuclei templates; bare hosts resolve relative, and a `javascript:` ref would be clickable (XSS-on-click). **Fix:** reuse a `normalizeUrl()` helper (reject non-http(s), reject `javascript:`/`data:`); render plain text when not linkable.
- **3d CVE link (`~:127-129`)** builds a MITRE URL for `row.cve_id`; for `NUCLEI-*` placeholders that 404s but still shows (gated only on truthiness). **Fix:** only build the MITRE link when `/^CVE-/i.test(cve_id)`.
- **3c Asset link** lands on the bogus CIDR aggregate asset — resolves once Issue 2 is fixed; also verify the Assets route consumes `?id=`.

### Issue 1 — Scheduled scans too limited (V3, or cheap UI part in V2) — `frontend/src/views/Settings.vue`
- Interval is a fixed 5-value `<el-select>` (`:745-753`); template selection collapsed to 3 profiles (`:720-726`, builder `:1386-1399`) vs. the one-off form's category/tag/all/custom (`VulnerabilityScanning.vue:90-188`). Backend `scan_options` JSONB already carries richer config and the job forwards `templateSelection`/`timeout`/`rateLimit` (`jobs/scheduledScans.ts:30-34`), so **the cheap win is UI-only**: reuse the one-off template block in Settings. Clock-anchored scheduling (cron/time-of-day) needs a migration: `005_scheduled_scans.sql` has only `interval_minutes`, and `ScheduledScan.ts` computes `next_run` as `NOW() + make_interval` (a drifting timer).

### Issue 4f / data model note
`total_vulnerabilities` counts asset–vuln links (same CVE on N assets = N) — fine, but currently understated because of Issue 2's asset collapse. Re-check after the Issue 2 fix.

## Security sweep details (V2)
- `cd backend && npm audit` → 22 (15 high, 7 moderate) incl. `qs` DoS advisories. `cd frontend && npm audit` → 29 (2 critical, 18 high, 9 moderate).
- Approach: run `npm audit fix` (non-breaking) in each, **rebuild to verify** (`npm run build` both), commit. For `--force`/major bumps, review individually and test — do NOT force blind. Document anything that needs a breaking upgrade.

## Open decisions for the user
1. **Confirm the V2/V3 cut above** (esp. deferring "remove bundled parsers/detections" to V3, and whether the cheap Issue-1 UI improvement sneaks into V2).
2. **Catalog repo rename** `siembox-parsers` → `siembox-catalog` (optional; default works either way).
3. **Re-seed `siembox-parsers`** after any catalog change: rerun `scripts/bootstrap-siembox-parsers.sh ../siembox-parsers` (now seeds 27 parsers + 48 detections) and push.

## Suggested first moves for the fresh context
1. **Open a PR for `claude/exciting-mccarthy-qrzfog` and merge it to `main`** (GitHub MCP). It carries the whole V2 punch list (6 commits, `abacebf`..`5fb5be0`).
2. **Verify on a host** (these were verified by build/typecheck/smoke-test, not a live re-scan): re-scan a CIDR and confirm distinct hosts get distinct assets, non-CVE (`NUCLEI-*`) findings now persist, the scan "Vulns Found" matches the Management count, and the dashboard cards/charts populate. (Update path: `git pull && docker compose -f compose.prod.yaml pull && up -d`, then hard-refresh.)
3. **Publish the v2.0.0 GitHub Release** (item 7 above) once merged.
4. (Optional) V3 backlog below — none started.
