#!/usr/bin/env bash
# Mirror the published community catalog into this repo so the in-repo source, the
# validate-catalog CI, and what users actually install from "Browse Catalog" all
# agree. The published siembox-catalog repo is the source of truth:
#
#   published  parsers/           -> this repo  catalog/parsers/
#   published  detections/<cat>/  -> this repo  rules/<cat>/
#   published  packs/             -> this repo  catalog/packs/
#
# It is a true mirror: parser/detection/pack files that no longer exist upstream
# are removed locally. One exception, for the move of Content Packs into the
# catalog: while the published catalog has no packs/ at all, catalog/packs/ is
# left as it is (an older catalog is not "every pack deleted"). Run manually (`./scripts/sync-catalog.sh`) or on a schedule via
# .github/workflows/sync-catalog.yml.
#
# Env: CATALOG_REPO (default cladkins/siembox-catalog), CATALOG_REF (default main),
#      GITHUB_TOKEN (optional; lifts the API rate limit in CI).
set -euo pipefail

REPO="${CATALOG_REPO:-cladkins/siembox-catalog}"
REF="${CATALOG_REF:-main}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="https://api.github.com/repos/${REPO}/git/trees/${REF}?recursive=1"
RAW="https://raw.githubusercontent.com/${REPO}/${REF}"

AUTH=()
[ -n "${GITHUB_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")

echo "Syncing catalog from ${REPO}@${REF} ..."
tree="$(curl -fsSL "${AUTH[@]}" -H 'Accept: application/vnd.github+json' "$API")"
paths="$(printf '%s' "$tree" | python3 -c "import sys,json;[print(t['path']) for t in json.load(sys.stdin)['tree'] if t['type']=='blob' and (t['path'].startswith('parsers/') or t['path'].startswith('detections/') or t['path'].startswith('packs/'))]")"
[ -n "$paths" ] || { echo 'No parser/detection files found upstream — aborting (not wiping local).' >&2; exit 1; }

# Stage all downloads first; only swap into place if every file fetched cleanly,
# so a mid-sync network failure never leaves the repo half-wiped.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
while IFS= read -r p; do
  case "$p" in
    parsers/*)    dest="$stage/catalog/$p" ;;                 # parsers/x        -> catalog/parsers/x
    detections/*) dest="$stage/rules/${p#detections/}" ;;     # detections/cat/x -> rules/cat/x
    packs/*)      dest="$stage/catalog/$p" ;;                 # packs/x          -> catalog/packs/x
    *) continue ;;
  esac
  mkdir -p "$(dirname "$dest")"
  # No auth header on raw downloads: the catalog is public, and a non-GitHub token
  # (e.g. a proxy-injected placeholder) makes raw.githubusercontent.com return 404.
  curl -fsSL "$RAW/$p" -o "$dest"
done <<< "$paths"

[ -d "$stage/catalog/parsers" ] || { echo 'No parsers staged — aborting.' >&2; exit 1; }
[ -d "$stage/rules" ] || { echo 'No detections staged — aborting.' >&2; exit 1; }

rm -rf "$ROOT/catalog/parsers" "$ROOT/rules"
mkdir -p "$ROOT/catalog"
mv "$stage/catalog/parsers" "$ROOT/catalog/parsers"
mv "$stage/rules" "$ROOT/rules"
if [ -d "$stage/catalog/packs" ]; then
  rm -rf "$ROOT/catalog/packs"
  mv "$stage/catalog/packs" "$ROOT/catalog/packs"
else
  echo 'The published catalog has no packs/ yet: catalog/packs/ left as it is.'
fi

echo "Synced $(find "$ROOT/catalog/parsers" -name '*.parser.json' | wc -l | tr -d ' ') parsers, $(find "$ROOT/rules" -name '*.yaml' | wc -l | tr -d ' ') detections, $(find "$ROOT/catalog/packs" -name '*.pack.yaml' 2>/dev/null | wc -l | tr -d ' ') packs from ${REPO}@${REF}."
