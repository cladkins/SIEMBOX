# SIEMBox — Session Handoff

> Working branch: **`claude/exciting-mccarthy-qrzfog`**. All finished work is merged to `main` via PRs (#55–#65). This file is the bridge to a fresh context.

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

## Uncommitted / unpushed RIGHT NOW
- Commit **`1db04e5`** ("vuln UI: don't render non-http matched-at as a broken relative link") is on the branch **but not yet pushed/merged**. It fixes Issue 3a below. **Push it + merge it** first thing.
- Nothing else uncommitted.

---

## V2 SHIP CUT (recommended)
**V2 = stabilize + secure what's built.** The parser platform + AI builder are done; ship them with the vuln-UI/dashboard bugs fixed and the dependency vulns knocked down. Keep the bundled parsers/detections (good out-of-box). Net-new features → V3.

### V2 punch list (all have exact fixes below)
1. **Vuln "results combining" — REAL data bug (highest priority).**
2. **Dashboard permanently shows zeros — REAL bug.**
3. **Dead/malformed links in vuln detail** — 3a fixed (commit `1db04e5`), 3b/3d remain.
4. **Security sweep** — Dependabot: backend **22** (15 high, 7 moderate), frontend **29** (2 critical, 18 high, 9 moderate). Knock down at least critical+high.
5. (Decision) Keep bundled parsers/detections for V2 — do NOT do the "remove bundled" work in V2.

### V3 backlog (net-new, deferred)
- **Remove bundled parsers/detections** + an "Install all" action in Browse Catalog (catalog-only first run). *User asked for this; deferring because it makes a fresh install empty without an install-all flow.*
- **GeoIP dashboard map** — alerts × country. Backend GeoIP enrichment already exists (`geoipService` adds `country`/`country_code`/`geo_foreign` to parsed logs/alerts); the work is a map widget + an aggregation endpoint (alerts grouped by country_code).
- **In-app AI assistant** — "explain this" on events/incidents/vulns/parsed+raw logs. **Reuses `services/ai/aiService.ts`** (provider + key already there); add an `explain(entity, context)` method + endpoint + a frontend panel/button.
- **Container vulnerability scanning** — integrate Trivy/Grype (image scan); new scanner alongside `nucleiScanner`.
- **Expanded scheduled-scan options** (Issue 1 below) — interval/cron/template selection. Could pull into V2 if cheap (the UI-only part is).

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
1. Push + PR-merge commit `1db04e5` (link fix 3a).
2. Issue 2 (asset key + `cve_id` width) — the load-bearing data bug; needs a migration. Verify with a re-scan that distinct hosts get distinct assets and stored count matches.
3. Dashboard 4a/4b (one-line field renames) + 4c chart watcher.
4. Links 3b/3d.
5. Security sweep (`npm audit fix` + rebuild + verify).
