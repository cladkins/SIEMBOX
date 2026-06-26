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
| Required status check: `validate-catalog` | Yes (strict) | CI must pass AND branch must be up-to-date |
| Enforce admins | Yes | Admins cannot bypass |
| Required conversation resolution | Yes | All review threads must be resolved |
| Required linear history | Yes | Forces squash or rebase; no merge commits |
| Allow force-pushes | No | |
| Allow deletions | No | |
| Restrictions (who can push) | Empty arrays (no direct-push bypass) | |

### 2b. `gh api` command (execute this)

> IMPORTANT: The `contexts` array in `required_status_checks` must exactly match the `name:` field of the job in the workflow (Section 3). The job is named `validate-catalog`. After the workflow has run at least once, GitHub will recognise the check by that name. If you run the API call before the first CI run, you may see a warning that the check context is unknown — this is expected; proceed anyway. The protection will activate the moment the first workflow run completes.

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
- **ReDoS note**: The validator runs community-submitted regex patterns (the `pattern` field in `*.parser.json`) through Node.js's V8 engine. Node has no built-in regex timeout. If a catastrophically backtracking pattern is submitted, the CI job will time out at the workflow level (`timeout-minutes: 15`). This is the current guard. A stronger guard is to add a ReDoS linter (e.g., `safe-regex` npm package or `vuln-regex-detector`) as a pre-check step — see the commented-out placeholder in the workflow below.

### 3b. Confirm the exact validator commands from the backend

Before committing the workflow, confirm these two npm scripts exist in `backend/package.json` of the `cladkins/siembox-catalog` repo (or of the `cladkins/siembox` backend that is checked out). As of authoring they are:

```
"validate-parsers":   "node dist/scripts/validate-parsers.js"
"validate-detections": "node dist/scripts/validate-detections.js"
```

The validator accepts a directory argument:
- `npm run validate-parsers -- ../catalog/parsers` — validates all `*.parser.json` files in that directory
- `npm run validate-detections -- ../catalog/detections` — validates all `*.yaml` / `*.yml` files in that directory

If `cladkins/siembox-catalog` is a standalone repo (separate from the main SIEMBox backend), the executing agent must confirm how the backend is brought in. The workflow below assumes the catalog repo contains a `backend/` directory (or a git submodule). **If the backend lives in a separate repository**, replace the `Checkout backend` step with a separate `actions/checkout` of the backend repo into a `./backend` path, or use a pre-built Docker image that ships the validator. Adjust the step marked `# --- ADJUST IF NEEDED` accordingly.

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
#     per-regex timeout). A future improvement is to add safe-regex pre-scan.

name: Validate Catalog

on:
  pull_request:
    branches:
      - main
    paths:
      - "parsers/**"
      - "detections/**"
      - "schema/**"
      # Also re-validate if the validator script itself changes
      - "backend/src/scripts/validate-parsers.ts"
      - "backend/src/scripts/validate-detections.ts"
      - "backend/src/services/parser/**"
      - "backend/src/services/rules/**"
      - "backend/package.json"
      - "backend/package-lock.json"

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
      # -----------------------------------------------------------------------
      # 1. Checkout the catalog repo (PR head, read-only — fork-safe)
      # -----------------------------------------------------------------------
      - name: Checkout catalog
        # actions/checkout v4.2.2  SHA: 11bd71901bbe5b1630ceea73d27597364c9af683
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      # -----------------------------------------------------------------------
      # 2. Set up Node.js
      #    Pin to an LTS version matching the backend's target runtime.
      # -----------------------------------------------------------------------
      - name: Set up Node.js
        # actions/setup-node v4.1.0  SHA: 39370e3970a6d050c480ffad4ff0ed4d3fdee5af
        uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af
        with:
          node-version: "20"
          cache: "npm"
          cache-dependency-path: backend/package-lock.json

      # -----------------------------------------------------------------------
      # 3. Install backend dependencies
      #    `npm ci` is deterministic (uses package-lock.json exactly).
      # -----------------------------------------------------------------------
      - name: Install backend dependencies
        working-directory: backend
        run: npm ci

      # -----------------------------------------------------------------------
      # 4. Build the TypeScript validator
      #    The compiled scripts live at dist/scripts/validate-parsers.js and
      #    dist/scripts/validate-detections.js — these are what npm run
      #    validate-parsers / validate-detections invoke.
      # -----------------------------------------------------------------------
      - name: Build validator
        working-directory: backend
        run: npm run build

      # -----------------------------------------------------------------------
      # [OPTIONAL - future improvement] ReDoS pre-scan
      # Uncomment to add a lightweight regex safety check before running
      # community-submitted patterns through the full validator. This catches
      # catastrophically backtracking patterns before they time out the runner.
      #
      # - name: Install safe-regex scanner
      #   run: npm install -g safe-regex@1.1.0
      #
      # - name: ReDoS pre-scan (parsers)
      #   run: |
      #     grep -rh '"pattern"' parsers/ \
      #       | grep -oP '(?<="pattern":\s*")[^"]+' \
      #       | while read -r pat; do
      #           safe-regex "$pat" || { echo "UNSAFE REGEX: $pat"; exit 1; }
      #         done
      # -----------------------------------------------------------------------

      # -----------------------------------------------------------------------
      # 5. Validate parsers
      #    Strict mode: schema validation + all self-tests must pass.
      #    Exits non-zero on any failure; the workflow fails and the PR is blocked.
      # -----------------------------------------------------------------------
      - name: Validate parsers
        working-directory: backend
        run: npm run validate-parsers -- ../parsers
        # --- ADJUST IF NEEDED ------------------------------------------------
        # If parsers/ is at a different relative path from backend/, change the
        # argument above. E.g. if the repo layout is:
        #   catalog/parsers/   and backend/ is at the repo root → ../catalog/parsers
        # ---------------------------------------------------------------------

      # -----------------------------------------------------------------------
      # 6. Validate detections
      #    Same validator pattern; exits non-zero on schema or content errors.
      # -----------------------------------------------------------------------
      - name: Validate detections
        working-directory: backend
        run: npm run validate-detections -- ../detections
        # --- ADJUST IF NEEDED ------------------------------------------------
        # Change the path argument to match the actual detections/ directory
        # relative to backend/ in cladkins/siembox-catalog.
        # If the detections/ directory does not exist yet, add:
        #   if: ${{ hashFiles('detections/**') != '' }}
        # to skip the step until the first detection is submitted.
        # ---------------------------------------------------------------------
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

## 10. Decisions requiring human confirmation

The following items have tradeoffs that the human owner of `cladkins/siembox-catalog` must decide before the executing agent applies them.

| # | Decision | Default in this doc | Tradeoff |
|---|----------|---------------------|----------|
| 1 | **Squash-only merge** | Enabled | Simplifies history. Contributors lose their individual commit messages. Rebase merge is disabled. If you want to preserve contributor history, re-enable rebase merge (`--enable-rebase-merge=true`) and leave squash as the default. |
| 2 | **Signed commits requirement** | Disabled (Section 7d) | Raises the contribution barrier significantly. Most community users do not have GPG/SSH commit signing configured. Recommended: defer until the contributor base is established. |
| 3 | **`restrictions` (who can push)** | Empty arrays | The current config blocks ALL direct pushes, including org members. If you want a team to have direct-push access for emergency fixes, add their GitHub username or team slug to `restrictions.users` / `restrictions.teams` in the Section 2b JSON. |
| 4 | **`enforce_admins: true`** | Enabled | Admins cannot bypass branch protection. This is the correct posture for a community-facing repo. If you need an emergency escape hatch, temporarily disable enforcement via `gh api --method DELETE /repos/cladkins/siembox-catalog/branches/main/protection/enforce_admins` (re-enable immediately after). |
| 5 | **ReDoS linting in CI** | Commented-out placeholder | The 15-minute job timeout is the current guard. Adding `safe-regex` or `vuln-regex-detector` as a pre-check step provides a faster, more informative failure. Requires a decision on which scanner to use and whether to block or warn. |
| 6 | **`detections/` directory** | Assumed to exist | If `detections/` does not yet exist in `cladkins/siembox-catalog`, add `if: ${{ hashFiles('detections/**') != '' }}` to the "Validate detections" step in the workflow, or remove the step and add it when the first detection is submitted. |
| 7 | **Backend location** | Assumed `backend/` in same repo | If the validator (TypeScript scripts in `backend/src/scripts/`) lives in a separate repository, the workflow must check out that repo too. The executing agent must verify the exact repo layout of `cladkins/siembox-catalog` before committing the workflow. |
| 8 | **Additional maintainers in CODEOWNERS** | Only `@cladkins` | Single-maintainer CODEOWNERS creates a bottleneck. Consider adding one or two trusted contributors so PRs are not stalled if the primary maintainer is unavailable. |

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
