# Catalog Repository Hardening Instructions

**Target repository:** `cladkins/siembox-catalog`
**Executing agent prerequisites:** Admin access to `cladkins/siembox-catalog` via `gh` CLI (authenticated) and/or GitHub REST API access with a token that has `repo` + `admin:repo_hook` scopes.
**Date authored:** 2026-06-26

---

## Table of Contents

1. [Pre-flight checks](#1-pre-flight-checks)
2. [Branch protection on `main`](#2-branch-protection-on-main)
3. [CI workflow — `validate-catalog.yml`](#3-ci-workflow--validate-catalogyml)
4. [CODEOWNERS](#4-codeowners)
5. [PR template](#5-pr-template)
6. [CONTRIBUTING.md](#6-contributingmd)
7. [Repo settings](#7-repo-settings)
8. [Dependabot](#8-dependabot)
9. [Verification checklist](#9-verification-checklist)
10. [Decisions requiring human confirmation](#10-decisions-requiring-human-confirmation)

---

## 1. Pre-flight checks

Run these before making any changes to establish a baseline.

```bash
# Confirm gh is authenticated and has admin on the target repo
gh auth status
gh repo view cladkins/siembox-catalog --json name,defaultBranchRef,visibility

# Capture the current branch-protection state (keep for rollback reference)
gh api repos/cladkins/siembox-catalog/branches/main/protection 2>/dev/null \
  || echo "No branch protection currently configured"

# Confirm you are NOT in the SIEMBOX main repo — this work is all against cladkins/siembox-catalog
echo "Working repo: cladkins/siembox-catalog"
```

---

## 2. Branch protection on `main`

### 2a. What we are configuring

| Setting | Value | Reason |
|---|---|---|
| Require PR before merging | Yes | No direct pushes |
| Required approving reviews | 1 | Human gate on community submissions |
| Dismiss stale reviews | Yes | New commit resets approval |
| Require code-owner review | Yes | Ties to CODEOWNERS for parser/detection dirs |
| Require last-push approval | Yes | Reviewer must see the final commit |
| Required status check: `validate-catalog` | Yes (strict) | CI must pass AND branch must be up-to-date. The workflow runs on **every** PR to main (no `paths:` filter) so this required check is never skipped — see Section 3c. |
| Enforce admins | Yes | Admins cannot bypass |
| Required conversation resolution | Yes | All review threads must be resolved |
| Required linear history | Yes | Forces squash or rebase; no merge commits |
| Allow force-pushes | No | |
| Allow deletions | No | |
| Restrictions (who can push) | Empty arrays (no direct-push bypass) | |

### 2b. `gh api` command (execute this)

> IMPORTANT: The `contexts` array in `required_status_checks` must exactly match the `name:` field of the job in the workflow (Section 3). The job is named `validate-catalog`. After the workflow has run at least once, GitHub will recognise the check by that name. If you run the API call before the first CI run, you may see a warning that the check context is unknown — this is expected; proceed anyway. The protection will activate the moment the first workflow run completes.
>
> Because this is a **required** check, the workflow in Section 3c deliberately has **no `paths:` filter** — it runs on every PR to main and decides relevance internally (a "Detect relevant changes" step gates the heavy work). A path-filtered required check would leave docs-only / `.github`-only PRs stuck on "Expected — waiting for status" and unable to merge.

```bash
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  /repos/cladkins/siembox-catalog/branches/main/protection \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [],
    "checks": [
      {
        "context": "validate-catalog"
      }
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1,
    "require_last_push_approval": true,
    "bypass_pull_request_allowances": {
      "users": [],
      "teams": [],
      "apps": []
    }
  },
  "restrictions": {
    "users": [],
    "teams": [],
    "apps": []
  },
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true,
  "block_creations": false
}
EOF
```

Expected HTTP response: `200 OK`. If you receive `422`, the `checks` array referencing an unknown context is the likely cause — also confirm the repo name and your token scope.

### 2c. Verify the protection was applied

```bash
gh api repos/cladkins/siembox-catalog/branches/main/protection \
  --jq '{
    enforce_admins: .enforce_admins.enabled,
    dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews,
    code_owner_reviews: .required_pull_request_reviews.require_code_owner_reviews,
    required_reviews: .required_pull_request_reviews.required_approving_review_count,
    require_up_to_date: .required_status_checks.strict,
    status_checks: [.required_status_checks.checks[].context],
    allow_force_push: .allow_force_pushes.enabled,
    allow_deletions: .allow_deletions.enabled,
    conversation_resolution: .required_conversation_resolution.enabled,
    linear_history: .required_linear_history.enabled
  }'
```

### 2d. Web UI equivalent (if API is unavailable)

1. Go to `https://github.com/cladkins/siembox-catalog/settings/branches`
2. Click **Add branch protection rule** (or edit the existing `main` rule)
3. Branch name pattern: `main`
4. Check **Require a pull request before merging**
   - Set **Required number of approvals** to `1`
   - Check **Dismiss stale pull request approvals when new commits are pushed**
   - Check **Require review from Code Owners**
   - Check **Require approval of the most recent reviewable push**
5. Check **Require status checks to pass before merging**
   - Check **Require branches to be up to date before merging**
   - In the search box, type `validate-catalog` and select it (it appears after the first CI run)
6. Check **Require conversation resolution before merging**
7. Check **Require linear history**
8. Check **Do not allow bypassing the above settings** (this enforces admins too)
9. Under **Rules applied to everyone**, check **Restrict who can push to matching branches** — leave the allowlist empty (this prevents any direct push)
10. Uncheck **Allow force pushes** (should be unchecked by default)
11. Uncheck **Allow deletions** (should be unchecked by default)
12. Click **Create** / **Save changes**

---

## 3. CI workflow — `validate-catalog.yml`

### 3a. Threat model decisions embedded in this workflow

- **`pull_request` trigger, NOT `pull_request_target`**: Fork PRs run in the fork's read-only context. The `GITHUB_TOKEN` has no write access to the base repo and cannot read repo secrets. Using `pull_request_target` would grant the fork access to secrets — do not change this.
- **Explicit `permissions: contents: read`**: Even if the organization default is `write`, this job only needs to clone the repo. Declared read-only at the workflow level so every job inherits it.
- **SHA-pinned actions**: Tags can be moved (the March 2025 tj-actions incident exfiltrated secrets this way). SHAs are immutable. Never change to a floating tag without Dependabot managing the update.
- **`ACTIONS_STEP_DEBUG` / `ACTIONS_RUNNER_DEBUG` are never set**: Avoids leaking structured output.
- **Validator from the trusted repo, not the fork**: the code that judges a submission is checked out from `cladkins/siembox` (Section 3b); the fork supplies only the data files. A malicious PR cannot alter its own validation.
- **ReDoS guard (active, changed files only)**: community-submitted `pattern` regexes run through Node/V8, which has no per-regex timeout. The workflow runs an **active [`recheck`](https://github.com/makenowjust-labs/recheck) ReDoS pre-scan over the parser files this PR adds or modifies** — it fails the PR on a regex `recheck` proves *vulnerable* and warns (does not fail) on *unknown* (analyzer timeout/unsupported). The scope is intentionally changed-files-only: an accurate scan finds **16 of the 23 parsers already in the catalog are ReDoS-vulnerable**, so a repo-wide gate would wedge every unrelated PR on pre-existing debt. Those legacy parsers are grandfathered and tracked for a dedicated cleanup PR (Section 11); new and modified parsers must be clean. The 15-minute job timeout (`timeout-minutes: 15`) is the backstop. (The older `safe-regex` heuristic is **not** used: it is so conservative it flags all 23 parsers, safe ones included.)

### 3b. How the validator is obtained (the catalog repo does NOT contain it)

The validator — `backend/src/scripts/validate-parsers.ts` / `validate-detections.ts` plus the `services/parser` + `services/rules` engines — lives in the **main app repo `cladkins/siembox`**, not in the catalog repo. So the workflow below checks out **two** repositories:

1. **`cladkins/siembox-catalog`** (the PR head) → supplies the submitted `parsers/` and `detections/` files. Fork-safe, read-only. Lands at `workspace/catalog`.
2. **`cladkins/siembox`** (pinned to `main`; public, so no token needed) → supplies the validator. It comes from the **trusted** app repo, never the fork, so a malicious PR cannot tamper with the code that judges it. Lands at `workspace/siembox`.

The validator builds once under `siembox/backend` and runs against `../../catalog/{parsers,detections}`. The npm scripts (in `cladkins/siembox`'s `backend/package.json`) are:

```
"validate-parsers":   "node dist/scripts/validate-parsers.js"
"validate-detections": "node dist/scripts/validate-detections.js"
```

Both take a directory argument and exit non-zero on any schema or self-test failure.

### 3c. Workflow file to create

**Path in `cladkins/siembox-catalog`:** `.github/workflows/validate-catalog.yml`

```yaml
# .github/workflows/validate-catalog.yml
#
# Validates community-submitted parsers and detection rules on every pull request.
#
# Security posture:
#   - Triggered by `pull_request`, never `pull_request_target`. Fork PRs run
#     in the fork's read-only context with no access to repo secrets or write
#     permissions. Changing this to pull_request_target would be a SECURITY
#     REGRESSION that allows secret exfiltration.
#   - Token is explicitly read-only (contents: read only).
#   - All third-party actions are pinned to immutable commit SHAs. Use
#     Dependabot (Section 8) to keep SHAs current.
#   - Job has a 15-minute hard timeout to bound ReDoS risk from submitted
#     regex patterns (community `pattern` fields run through Node/V8 with no
#     per-regex timeout), PLUS an active `recheck` ReDoS pre-scan that fails
#     the PR on any regex it proves vulnerable in the parser files this PR
#     adds or modifies (changed-files scope; see the pre-scan step below).
#   - Runs on EVERY pull request to main (no `paths:` filter) on purpose: this
#     job is a REQUIRED branch-protection check (Section 2b), and GitHub never
#     reports a required check whose path filter excludes the PR — the merge
#     blocks forever on "Expected — waiting for status." To stay both required
#     AND fast, the trigger is unconditional but the heavy steps (validator
#     checkout/build, ReDoS scan, validation) are gated on an internal "did
#     parsers/detections/schema actually change?" diff, so a docs-only or
#     .github-only PR no-ops to green in seconds.

name: Validate Catalog

on:
  # Run on every PR to main — do NOT add a `paths:` filter here. A path-filtered
  # workflow that is also a required status check leaves unrelated PRs stuck on
  # "Expected — waiting for status" forever. Relevance is decided inside the job
  # instead (see the "Detect relevant changes" step).
  pull_request:
    branches:
      - main

# Declare the minimum required permissions for this workflow.
# Fork PRs receive a read-only token by default; this declaration makes the
# intent explicit and overrides any org-level default that might be write.
permissions:
  contents: read

jobs:
  validate-catalog:
    name: validate-catalog
    runs-on: ubuntu-22.04
    timeout-minutes: 15

    steps:
      # 1. The submitted files (PR head — fork-safe, read-only).
      - name: Checkout catalog (PR)
        # actions/checkout v4.2.2
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          path: catalog
          # Full history so the ReDoS pre-scan can diff the PR head (the merge
          # commit) against its base commit and scan only the parser files this
          # PR adds or modifies. The default depth=1 omits the base parent.
          fetch-depth: 0

      # Decide whether this PR actually touches catalog content. Because the
      # workflow is a REQUIRED check it runs on every PR, but a docs-only or
      # .github-only PR has nothing to validate — gate the heavy steps below on
      # this so the job no-ops to green in seconds instead of building the whole
      # validator. (The git diff sits in an `if` condition, so its non-zero
      # "differences found" exit does not trip `set -e`; any unexpected error
      # falls through to relevant=true — fail safe by validating.)
      - name: Detect relevant changes
        id: changes
        working-directory: catalog
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: |
          set -euo pipefail
          if git diff --quiet "$BASE_SHA" HEAD -- parsers detections schema; then
            echo "relevant=false" >> "$GITHUB_OUTPUT"
            echo "No parser/detection/schema changes in this PR; validation will be skipped."
          else
            echo "relevant=true" >> "$GITHUB_OUTPUT"
            echo "Catalog content changed; running full validation."
          fi

      # 2. The validator, from the TRUSTED app repo — NOT the fork. The fork only
      #    supplies data files; the code that judges them comes from cladkins/siembox,
      #    so a malicious PR can't tamper with its own validation.
      - name: Checkout SIEMBox validator
        if: steps.changes.outputs.relevant == 'true'
        # actions/checkout v4.2.2
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          repository: cladkins/siembox
          ref: main
          path: siembox

      - name: Set up Node.js
        if: steps.changes.outputs.relevant == 'true'
        # actions/setup-node v4.1.0
        uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af
        with:
          node-version: "20"
          cache: "npm"
          cache-dependency-path: siembox/backend/package-lock.json

      - name: Install validator dependencies
        if: steps.changes.outputs.relevant == 'true'
        working-directory: siembox/backend
        run: npm ci

      - name: Build validator
        if: steps.changes.outputs.relevant == 'true'
        working-directory: siembox/backend
        run: npm run build

      # ReDoS pre-scan: reject catastrophically-backtracking regexes in the parser
      # files this PR ADDS or MODIFIES, before the validator runs them through V8
      # (which has no per-regex timeout). Uses `recheck` (accurate automaton+fuzz
      # ReDoS analysis) via its synchronous, in-process backend (`checkSync` does
      # not spawn an external CLI). The older `safe-regex` heuristic is NOT used:
      # it is so conservative it flags all 23 existing parsers, safe ones included.
      #
      # Scope is changed files ONLY, on purpose: 16 of the 23 parsers already in
      # the catalog are ReDoS-vulnerable, so a repo-wide gate would block every
      # unrelated PR on pre-existing debt. Those are grandfathered and fixed in a
      # dedicated cleanup PR (Section 11). New/modified parsers must be clean:
      # FAIL on a "vulnerable" verdict; WARN (don't fail) on "unknown" (recheck
      # timed out / unsupported syntax). The diff uses the PR base commit, which
      # the merge-ref parent makes reachable thanks to fetch-depth: 0 above.
      - name: ReDoS pre-scan (changed parser regexes)
        if: steps.changes.outputs.relevant == 'true'
        working-directory: catalog
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: |
          set -euo pipefail
          CHANGED="$(git diff --name-only --diff-filter=AM "$BASE_SHA" HEAD -- 'parsers/**.parser.json' || true)"
          if [ -z "$CHANGED" ]; then
            echo "No added/modified parser files in this PR; skipping ReDoS scan."
            exit 0
          fi
          echo "Scanning changed parser files:"; echo "$CHANGED"
          # recheck@4 resolves to the latest 4.x at install time. It is an
          # ad-hoc dev install (no manifest entry), so it stays current on its
          # own — Dependabot (Section 8) tracks the committed package files only.
          npm install recheck@4 --no-save
          CHANGED_FILES="$CHANGED" node -e '
            const fs = require("fs");
            const { checkSync } = require("recheck");
            const files = (process.env.CHANGED_FILES || "").split("\n").map((s) => s.trim()).filter(Boolean);
            let bad = 0;
            for (const f of files) {
              let p; try { p = JSON.parse(fs.readFileSync(f, "utf8")); } catch { continue; }
              if (typeof p.pattern !== "string" || !p.pattern) continue;
              let r; try { r = checkSync(p.pattern, ""); } catch (e) {
                console.error("WARN  could not analyze " + f + ": " + (e && e.message)); continue;
              }
              if (r.status === "vulnerable") {
                const kind = (r.complexity && r.complexity.type) || "backtracking";
                console.error("FAIL  ReDoS-vulnerable regex (" + kind + ") in " + f + ": " + p.pattern);
                bad++;
              } else if (r.status === "unknown") {
                const why = (r.error && r.error.kind) || "unknown";
                console.error("WARN  could not prove safe in " + f + " (" + why + "): " + p.pattern);
              }
            }
            if (bad) {
              console.error(bad + " ReDoS-vulnerable regex(es) in changed parsers — fix before merge.");
              process.exit(1);
            }
            console.log("ReDoS pre-scan passed (changed parsers only).");
          '

      # Validate parsers — strict: schema + every self-test must pass. The catalog
      # dirs sit one level up from siembox/ (workspace/catalog, workspace/siembox).
      - name: Validate parsers
        if: steps.changes.outputs.relevant == 'true'
        working-directory: siembox/backend
        run: npm run validate-parsers -- ../../catalog/parsers

      # Validate detections — skips cleanly until the first detection is submitted.
      - name: Validate detections
        if: ${{ steps.changes.outputs.relevant == 'true' && hashFiles('catalog/detections/**') != '' }}
        working-directory: siembox/backend
        run: npm run validate-detections -- ../../catalog/detections
```

### 3d. Commit the workflow

```bash
# From a local clone of cladkins/siembox-catalog
git checkout -b chore/harden-catalog-ci
mkdir -p .github/workflows
# Paste the YAML above into .github/workflows/validate-catalog.yml

git add .github/workflows/validate-catalog.yml
git commit -m "ci: add validate-catalog workflow with read-only token and SHA-pinned actions"
git push origin chore/harden-catalog-ci
# Open a PR — merge it to main (this also triggers the first CI run)
```

### 3e. Confirm the check name after first run

After the PR is merged and the workflow runs on a subsequent PR:

```bash
# List recent check runs to confirm the job name matches what branch protection expects
gh api repos/cladkins/siembox-catalog/commits/main/check-runs \
  --jq '.check_runs[] | {name: .name, status: .status, conclusion: .conclusion}'
```

The name reported should be `validate-catalog` (matching the `name:` key on the job). If it differs, update the `checks[].context` in the branch protection PUT call from Section 2b.

---

## 4. CODEOWNERS

### 4a. What this does

CODEOWNERS ties a filesystem path pattern to a GitHub user or team. When branch protection has `require_code_owner_reviews: true`, GitHub will request a review from the listed owner(s) automatically on any PR that touches those paths. An approval from a non-owner does NOT satisfy the code-owner review requirement.

### 4b. File to create

**Path in `cladkins/siembox-catalog`:** `.github/CODEOWNERS`

```
# .github/CODEOWNERS
#
# Code-owner assignments for cladkins/siembox-catalog.
# Any PR touching parsers/, detections/, or the schema requires a review
# from a listed maintainer before it can merge.
#
# Syntax: <path-pattern>  <@user-or-@org/team> [additional-owners...]
# Last matching pattern wins. Use gitignore glob syntax.
#
# Required: branch protection must have "Require review from Code Owners"
# enabled (already set in Section 2).

# Default owner for everything not matched below
*  @cladkins

# Parser submissions — every *.parser.json file must be reviewed by a maintainer
/parsers/  @cladkins

# Detection rule submissions
/detections/  @cladkins

# Schema changes require maintainer review (schema changes are breaking changes)
/schema/  @cladkins

# Workflow changes must be reviewed by a maintainer (prevent CI bypass)
/.github/  @cladkins
```

**Customisation:** Replace `@cladkins` with the real GitHub usernames or `@org/team-slug` of the maintainers. You can list multiple owners space-separated; all listed owners receive a review request, but only ONE approval from any listed owner is required to satisfy the check (unless `required_approving_review_count` is raised above 1).

### 4c. Validate CODEOWNERS syntax

```bash
# After pushing the file, GitHub validates syntax and shows errors
# in the repository's CODEOWNERS view:
# https://github.com/cladkins/siembox-catalog/blob/main/.github/CODEOWNERS
#
# You can also use the gh CLI to trigger an immediate check:
gh api repos/cladkins/siembox-catalog/contents/.github/CODEOWNERS \
  --jq '.content' | base64 --decode
```

---

## 5. PR template

### 5a. File to create

**Path in `cladkins/siembox-catalog`:** `.github/pull_request_template.md`

```markdown
<!-- .github/pull_request_template.md
     This template is shown to contributors when they open a PR.
     Do not remove the checklist — maintainers use it to gate review.
-->

## What does this PR add?

<!-- One sentence: what log source / detection rule does this contribute? -->

**Type of change:**
- [ ] New parser (`parsers/<name>.parser.json`)
- [ ] New detection rule (`detections/<name>.yaml`)
- [ ] Update to an existing parser or detection
- [ ] Schema / tooling change (requires maintainer approval)

---

## Parser / detection details

**Log source or detection name:**
**Parser type (regex / json / grok):** *(parsers only)*
**Sample log line (real data, IPs/secrets redacted using 203.0.113.x / 198.51.100.x):**

```
paste a real raw log line here
```

---

## Self-test attestation

> The CI workflow runs the exact same validator the SIEMBox app uses. A green
> `validate-catalog` check means the parser/detection imports correctly and all
> self-tests pass.

- [ ] I ran `cd backend && npm ci && npm run build && npm run validate-parsers -- ../parsers` locally and it exited 0
      *(for detection PRs, substitute `npm run validate-detections -- ../detections`)*
- [ ] Every distinct event type the parser surfaces has at least one `test_sample` with a real (redacted) log line
- [ ] All `expect` fields in `test_samples` use canonical names (`source_ip`, `user`, `status_code`, etc.) as documented in CONTRIBUTING.md
- [ ] The `name` field is kebab-case and does not collide with an existing parser name

---

## Regex safety (parsers only)

Regex patterns in `*.parser.json` run inside the SIEMBox parse pipeline. Please confirm:

- [ ] The `pattern` regex does not use unbounded quantifiers on variable-length groups in a way that could cause catastrophic backtracking (ReDoS). If uncertain, test with [regex101.com](https://regex101.com/) against pathological inputs (e.g., a 10 000-character string of repeated characters your pattern partially matches).

---

## Additional notes

<!-- Anything the reviewer should know: related parsers, ambiguous log formats,
     fields that were intentionally omitted, etc. -->
```

---

## 6. CONTRIBUTING.md

The catalog already has a `CONTRIBUTING.md` at the repo root (currently covering parsers). Update it so it also describes detection rules, the CI gate, and the security expectations. The full replacement content is below.

**Path in `cladkins/siembox-catalog`:** `CONTRIBUTING.md`

```markdown
# Contributing to the SIEMBox Catalog

Thank you for contributing a parser or detection rule! This guide explains
what CI enforces, how to test locally, and what maintainers check before
approving a PR.

## What the catalog contains

| Directory | File pattern | Content |
|-----------|-------------|---------|
| `parsers/` | `<name>.parser.json` | Portable JSON parsers (regex / json / grok) |
| `detections/` | `<name>.yaml` | Sigma-style YAML detection rules |
| `schema/` | `parser.schema.json` | JSON Schema (editor autocomplete + docs) |

## Quickstart

### Add a parser

1. Copy `parsers/apache-nginx-access-log.parser.json` as a starting template.
2. Rename it to `parsers/<your-log-source>.parser.json` (kebab-case only).
3. Fill in `name`, `description`, `parser_type`, `pattern`, `field_mappings`,
   `derivations` (optional), `event_type`, and at least one `test_sample`.
4. Run the validator locally (see below).
5. Open a PR from your fork against `main`.

### Add a detection rule

1. Add `detections/<rule-name>.yaml` following the Sigma-style schema.
2. Run `npm run validate-detections -- ../detections` locally.
3. Open a PR from your fork against `main`.

## Local validation

You need the SIEMBox backend validator (Node 20+):

```bash
cd backend
npm ci
npm run build

# Validate all parsers:
npm run validate-parsers -- ../parsers

# Validate all detections:
npm run validate-detections -- ../detections

# Validate a single file:
npm run validate-parsers -- ../parsers/my-app.parser.json
```

Both commands exit 0 on full success, 1 on any failure. The CI gate runs the
same commands — reproduce any CI failure locally with the same commands.

## What CI enforces

Every PR touching `parsers/**`, `detections/**`, or `schema/**` triggers the
**Validate Catalog** workflow (`.github/workflows/validate-catalog.yml`).
The PR cannot merge until:

1. **The `validate-catalog` status check is green** — all submitted files pass
   strict schema validation AND all `test_samples` pass.
2. **At least one maintainer has approved the PR** — the CODEOWNERS file
   automatically requests a review from a listed maintainer.
3. **All review conversations are resolved** — no open comments.
4. **The branch is up to date with `main`** — rebase before merging if main
   has moved on since you opened the PR.

Auto-merge is disabled. A maintainer merges manually after review.

## Parser format reference

See the authoritative schema at `schema/parser.schema.json`. The required fields are:

| Field | Type | Description |
|-------|------|-------------|
| `schema` | string | Must be `"siembox.parser/v1"` |
| `name` | string | Unique kebab-case name (also the import key in SIEMBox) |
| `parser_type` | enum | `"regex"` \| `"json"` \| `"grok"` |
| `pattern` | string | Regex with named capture groups (regex/grok); `""` for json |
| `field_mappings` | object | `{ captureGroup: canonicalField }` for regex; `{ jsonKey: canonicalField }` for json |
| `test_samples` | array | **Required in strict/CI mode.** At least one per distinct event type. |

Map captured fields to canonical names wherever possible:
`source_ip`, `dest_ip`, `source_port`, `dest_port`, `user`, `target_user`,
`host`, `service`, `method`, `path`, `status_code`, `message`, `event`.

## Security expectations

Submissions are **community data** executed by the SIEMBox parse pipeline.
Please follow these rules:

- **Use real log lines** in `test_samples` — redact real IPs (use
  `203.0.113.x` / `198.51.100.x`) and any secret or personal data.
- **Avoid catastrophic backtracking in regex patterns.** An unbounded
  quantifier over a variable-length group can cause a ReDoS that hangs the
  parse pipeline. Test your pattern at https://regex101.com/ with pathological
  inputs. If unsure, ask in the PR and a maintainer will review the regex.
- **Do not submit patterns that match other parsers' dedicated log lines.**
  Use `priority` and `test_samples` to demonstrate your parser is correctly
  scoped.
- **No executable code.** Parsers and detection rules are declarative data.
  `derivations` are a whitelist of `set` / `extract` operations — no
  arbitrary eval, no remote fetches.

## PR process

1. Fork the repo, create a feature branch (e.g. `add-parser-myapp`).
2. Add your file, run the local validator.
3. Open a PR against `main`. The PR template will guide you through the checklist.
4. CI runs automatically. Address any failures by pushing to your branch.
5. A maintainer reviews. Expect feedback on canonical field naming, test coverage,
   and regex safety.
6. After approval and all checks passing, a maintainer will squash-merge your PR.
   Your branch will be deleted automatically.

## Questions?

Open a GitHub Discussion or ask in the PR itself.
```

---

## 7. Repo settings

Execute the following `gh` commands to configure repository-level settings. These are separate from branch protection.

### 7a. Merge strategy — squash only, no merge commits, auto-delete branches

```bash
# Disable regular merge commits (keeps main history linear)
gh repo edit cladkins/siembox-catalog \
  --enable-merge-commit=false \
  --enable-rebase-merge=false \
  --enable-squash-merge=true \
  --squash-merge-commit-message=PR_TITLE \
  --delete-branch-on-merge=true \
  --allow-update-branch=true
```

**Rationale:**
- Squash-only: each parser/detection contribution becomes one clean commit on `main`, making `git log` readable.
- Auto-delete: reduces stale fork branches cluttering the repo.
- `--allow-update-branch`: contributors can click "Update branch" on their PR without needing a local rebase — reduces friction while keeping the "up-to-date" branch protection requirement workable.

Verify:

```bash
gh repo view cladkins/siembox-catalog \
  --json mergeCommitAllowed,squashMergeAllowed,rebaseMergeAllowed,deleteBranchOnMerge \
  | jq .
# Expected:
# {
#   "mergeCommitAllowed": false,
#   "squashMergeAllowed": true,
#   "rebaseMergeAllowed": false,
#   "deleteBranchOnMerge": true
# }
```

### 7b. Set repo-wide default workflow token to read-only

This controls what GITHUB_TOKEN receives by default for ALL workflows in the repo (the workflow-level `permissions:` block can only narrow further, never expand beyond this cap).

```bash
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  /repos/cladkins/siembox-catalog/actions/permissions/workflow \
  -f default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=false
```

Verify:

```bash
gh api repos/cladkins/siembox-catalog/actions/permissions/workflow \
  --jq '{default_workflow_permissions, can_approve_pull_request_reviews}'
# Expected: {"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}
```

### 7c. Restrict GitHub Actions to allowed actions only

This prevents a future maintainer accidentally running an unpinned third-party action:

```bash
# Allow GitHub-owned actions, and allow any action as long as it is
# pinned to a commit SHA (enforced policy as of 2025-08-15 Actions SHA policy update).
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  /repos/cladkins/siembox-catalog/actions/permissions \
  -f enabled=true \
  -f allowed_actions=selected

gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  /repos/cladkins/siembox-catalog/actions/permissions/selected-actions \
  -F github_owned_allowed=true \
  -F verified_allowed=false \
  -F patterns_allowed='[]'
```

> If the repo is under a GitHub organization, these permissions may need to be set at the org level first (org policy must permit per-repo overrides). If you receive `403`, escalate to the org admin.

### 7d. Signed commits (optional — confirm with human first)

Requiring signed commits provides non-repudiation: every merge commit on `main` is cryptographically tied to the committer's GPG/SSH key. The tradeoff is that it breaks contributors who have not yet set up commit signing, and it breaks squash-merges via the GitHub web UI for users without a verified signing key configured.

**Recommendation:** Do NOT enable signed commits on this repo initially. The contribution barrier for community users is already high (they must have Node, run the validator, and understand the schema). Adding a signing requirement will reduce submissions without significantly improving the security posture (maintainer review + CI provide the effective gate).

If you decide to enable it later:

```bash
# Web UI only — the API does not expose this setting directly
# Settings → Branches → Edit the main protection rule →
# check "Require signed commits"
# OR via the Rulesets API (GitHub Enterprise / newer free tier):
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  /repos/cladkins/siembox-catalog/rulesets \
  --input - <<'EOF'
{
  "name": "require-signed-commits",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/main"],
      "exclude": []
    }
  },
  "rules": [
    { "type": "required_signatures" }
  ]
}
EOF
```

---

## 8. Dependabot

Dependabot keeps the SHA-pinned actions in the workflow current. Without it, pinned actions drift away from security patches — the pins become outdated rather than immutable-and-up-to-date.

### 8a. File to create

**Path in `cladkins/siembox-catalog`:** `.github/dependabot.yml`

```yaml
# .github/dependabot.yml
#
# Dependabot version updates for:
#   - GitHub Actions (keeps SHA pins current when new action versions are released)
#   - npm (keeps the backend validator's dependencies patched)
#
# Dependabot opens PRs against main. Those PRs trigger the validate-catalog
# workflow. Merge strategy: squash (consistent with repo settings).

version: 2

updates:
  # --------------------------------------------------------------------------
  # GitHub Actions — updates SHA pins in workflow files
  # --------------------------------------------------------------------------
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "08:00"
      timezone: "America/New_York"
    labels:
      - "dependencies"
      - "github-actions"
    commit-message:
      prefix: "ci"
    open-pull-requests-limit: 5

  # --------------------------------------------------------------------------
  # npm — updates backend/package.json validator dependencies
  # This catches security advisories in js-yaml, ajv, and any other packages
  # the validate-parsers / validate-detections scripts depend on.
  # --------------------------------------------------------------------------
  - package-ecosystem: "npm"
    directory: "/backend"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "08:00"
      timezone: "America/New_York"
    labels:
      - "dependencies"
      - "npm"
    commit-message:
      prefix: "chore(deps)"
    open-pull-requests-limit: 5
    # Only update packages that have known security vulnerabilities
    # (comment out the line below to get all version bumps too)
    versioning-strategy: lockfile-only
```

### 8b. Enable Dependabot alerts via API

```bash
# Enable Dependabot vulnerability alerts
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  /repos/cladkins/siembox-catalog/vulnerability-alerts

# Enable automated Dependabot security updates (opens PRs for known CVEs)
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  /repos/cladkins/siembox-catalog/automated-security-fixes
```

---

## 9. Verification checklist

Run this checklist after all changes above are applied. The executing agent should go through each item in order.

### 9a. Branch protection smoke test — direct push rejection

```bash
# Attempt a direct push to main from the local clone.
# This MUST be rejected with "remote: error: GH006: Protected branch..."
echo "test" > /tmp/test-push-$$.txt
cd /path/to/local/clone/of/siembox-catalog
git add /tmp/test-push-$$.txt 2>/dev/null || true
# Actually create a file in the repo
date > .branch-protection-test
git add .branch-protection-test
git commit -m "test: direct push — this should be rejected"
git push origin main
# Expected output includes:
#   remote: error: GH006: Protected branch update failed for refs/heads/main.
# If the push succeeds, branch protection is NOT correctly configured — revisit Section 2.
git reset HEAD~1  # undo the local commit
rm .branch-protection-test
```

### 9b. Fork PR test — CI and review gate

1. From a secondary GitHub account (or ask a trusted community member), fork `cladkins/siembox-catalog`.
2. In the fork, add a minimal valid parser file at `parsers/test-hardening.parser.json`:

```json
{
  "schema": "siembox.parser/v1",
  "name": "test-hardening",
  "description": "Temporary test parser for branch-protection verification. Delete after test.",
  "parser_type": "regex",
  "priority": 500,
  "pattern": "^TEST (?<message>.+)$",
  "field_mappings": { "message": "message" },
  "test_samples": [
    {
      "input": "TEST hardening-check-ok",
      "expect": { "message": "hardening-check-ok" },
      "description": "Basic match for hardening verification"
    }
  ],
  "metadata": { "author": "hardening-test", "log_source": "hardening test" }
}
```

3. Open a PR from the fork's branch to `cladkins/siembox-catalog:main`.
4. Confirm:
   - [ ] The `validate-catalog` check runs automatically (triggered by `pull_request`)
   - [ ] The check passes (exits 0) for the valid parser file
   - [ ] The PR shows "Review required" from the CODEOWNERS (@cladkins)
   - [ ] The PR is NOT mergeable until: CI passes + codeowner approves + no open conversations
   - [ ] The fork PR cannot read any repo secrets (there are none to test, but verify no `secrets.*` are referenced in workflow output)
5. Approve the PR as the codeowner and confirm the merge button becomes available.
6. After confirming, **close the PR without merging** (or merge and immediately revert):

```bash
gh pr close <PR-NUMBER> --repo cladkins/siembox-catalog --comment "Hardening test complete."
```

### 9c. Invalid parser test — CI failure blocks merge

1. From the fork, open a second PR with an intentionally invalid parser (missing `test_samples`):

```json
{
  "schema": "siembox.parser/v1",
  "name": "test-invalid",
  "parser_type": "regex",
  "pattern": "^INVALID (?<message>.+)$",
  "field_mappings": { "message": "message" }
}
```

2. Confirm:
   - [ ] The `validate-catalog` check FAILS (strict mode requires `test_samples`)
   - [ ] The PR is marked as "Some checks were not successful" and cannot be merged even if reviewed

```bash
# Check the CI result via API
gh pr checks <PR-NUMBER> --repo cladkins/siembox-catalog
# The validate-catalog check should show: failure
```

3. Close the PR:

```bash
gh pr close <PR-NUMBER> --repo cladkins/siembox-catalog --comment "Hardening test — invalid parser correctly rejected."
```

### 9d. Settings verification

```bash
# Confirm squash-only
gh repo view cladkins/siembox-catalog \
  --json mergeCommitAllowed,squashMergeAllowed,rebaseMergeAllowed,deleteBranchOnMerge

# Confirm default workflow token is read-only
gh api repos/cladkins/siembox-catalog/actions/permissions/workflow

# Confirm Dependabot alerts are enabled
gh api repos/cladkins/siembox-catalog/vulnerability-alerts
# Expected: 204 No Content (means enabled)

# Confirm branch protection is fully applied
gh api repos/cladkins/siembox-catalog/branches/main/protection \
  --jq '{
    enforce_admins: .enforce_admins.enabled,
    dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews,
    code_owner_reviews: .required_pull_request_reviews.require_code_owner_reviews,
    up_to_date: .required_status_checks.strict,
    force_push_blocked: (.allow_force_pushes.enabled | not),
    deletions_blocked: (.allow_deletions.enabled | not),
    linear_history: .required_linear_history.enabled,
    conversation_resolution: .required_conversation_resolution.enabled
  }'
```

All boolean values should be `true` (or `false` for the blocked ones — note the `not`).

---

## 10. Decisions — confirmed by the owner

These were confirmed by the repo owner; the rest of this document already reflects them, so the executing agent needs no further input.

| # | Decision | Confirmed setting |
|---|----------|-------------------|
| 1 | Merge method | **Squash-only** (merge + rebase disabled) — Section 7a |
| 2 | Signed commits | **Disabled** — Section 7d (defer; high contributor friction) |
| 3 | Direct-push allowlist | **Empty** — nobody pushes `main` directly; everything via PR |
| 4 | `enforce_admins` | **Enabled** — protection applies to the owner too (no admin bypass) |
| 5 | ReDoS check | **Active `recheck` pre-scan on changed parser files** in CI (Section 3c) — fail on *vulnerable*, warn on *unknown*; the 16 ReDoS-vulnerable legacy parsers are grandfathered + fixed in a cleanup PR (Section 11); backed by the 15-min timeout. (`safe-regex` was rejected — it flags all 23 parsers.) |
| 6 | `detections/` directory | Handled by the `if: hashFiles(...)` guard — the step skips until the first detection exists |
| 7 | Validator location | **Resolved** — CI checks out `cladkins/siembox` for the validator (Sections 3b/3c); `backend/` is NOT in the catalog repo |
| 8 | Additional CODEOWNERS maintainers | **`@cladkins` only** for now — add a backup reviewer later if PRs stall |

> **Emergency escape hatch** (since `enforce_admins` is on): to land a hotfix, temporarily lift enforcement with
> `gh api --method DELETE /repos/cladkins/siembox-catalog/branches/main/protection/enforce_admins`, push, then immediately
> re-enable by re-running the Section 2b PUT.

---

## 11. Legacy parser ReDoS cleanup (follow-up)

The ReDoS pre-scan (Section 3c) deliberately scans **only the parser files a PR adds or modifies**, because an accurate `recheck` scan finds **16 of the 23 parsers already in the catalog are ReDoS-vulnerable**. Gating the whole tree would fail every unrelated PR on pre-existing debt, so those 16 are *grandfathered*: the gate ignores them until they are touched. This is a known, accepted gap — not an oversight — and it is closed by a separate work item:

1. Run `recheck` over all of `parsers/*.parser.json` and capture every file whose `status` is `"vulnerable"`. That list is authoritative — do not hand-pick.
2. For each, rewrite the `pattern` to remove the catastrophic construct (typically an unbounded quantifier over a variable-length group — e.g. `(.*)+`, `(\S+\s*)+`, or adjacent overlapping `.*`). Anchor where possible, restructure nested quantifiers, and bound character classes.
3. Re-run the parser self-tests (`npm run validate-parsers -- ../../catalog/parsers`) so every rewrite still matches its `test_samples`.
4. Land the fixes in one (or a few) dedicated **cleanup PR(s)** — e.g. `fix(parsers): remove ReDoS-vulnerable patterns`. Each passes the changed-files pre-scan because the rewrites are clean.

Once all 16 are clean, the scan scope **can optionally be widened** to the whole `parsers/` tree (change the diff step to enumerate every `*.parser.json` instead of only changed files) to catch any regression that bypasses the diff. That is a hardening *upgrade*, not a blocker for this pass.

---

## Files to create in `cladkins/siembox-catalog`

Summary of all files this document instructs the executing agent to create:

| File path | Section |
|-----------|---------|
| `.github/workflows/validate-catalog.yml` | 3c |
| `.github/CODEOWNERS` | 4b |
| `.github/pull_request_template.md` | 5a |
| `CONTRIBUTING.md` | 6 (replace existing) |
| `.github/dependabot.yml` | 8a |

---

## References

- [GitHub REST API: branch protection](https://docs.github.com/en/rest/branches/branch-protection)
- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Securely using pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [Keeping your actions up to date with Dependabot](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/keeping-your-actions-up-to-date-with-dependabot)
- [About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [Hardening GitHub Actions: Lessons from Recent Attacks (Wiz)](https://www.wiz.io/blog/github-actions-security-guide)
- [Pinning GitHub Actions for Enhanced Security (StepSecurity)](https://www.stepsecurity.io/blog/pinning-github-actions-for-enhanced-security-a-complete-guide)
- [GitHub Actions SHA pinning policy (GitHub Changelog, 2025-08-15)](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/)
- [gh repo edit documentation](https://cli.github.com/manual/gh_repo_edit)
