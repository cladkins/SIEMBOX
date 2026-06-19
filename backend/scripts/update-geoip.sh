#!/usr/bin/env bash
#
# Download the latest DB-IP IP-to-Country Lite MMDB and install it at
# ${GEOIP_DB_PATH:-/app/data/dbip-country-lite.mmdb}.
#
# DB-IP lite is licensed CC BY 4.0 (attribution required) and refreshed monthly,
# so we fetch by current YYYY-MM and fall back to the previous month if the new
# file isn't published yet. The DB is NOT bundled in the image (license + size +
# staleness) — run this on the host (cron/systemd-timer), then restart the backend
# (or call the GeoIP reload) to pick it up.
#
# Usage:
#   GEOIP_DB_PATH=./data/geoip/dbip-country-lite.mmdb backend/scripts/update-geoip.sh
#
set -euo pipefail

DEST="${GEOIP_DB_PATH:-/app/data/dbip-country-lite.mmdb}"
BASE_URL="https://download.db-ip.com/free"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$(dirname "$DEST")"

download_month() {
  local ym="$1"
  local url="${BASE_URL}/dbip-country-lite-${ym}.mmdb.gz"
  echo "GeoIP: trying ${url}"
  if curl -fSL --retry 3 --connect-timeout 20 --max-time 300 \
       -o "${TMPDIR}/dbip.mmdb.gz" "${url}"; then
    gunzip -f "${TMPDIR}/dbip.mmdb.gz"
    return 0
  fi
  return 1
}

CUR_YM="$(date -u +%Y-%m)"
# Previous month (portable: try GNU date, then BSD/macOS date).
if PREV_YM="$(date -u -d "$(date -u +%Y-%m-15) -1 month" +%Y-%m 2>/dev/null)"; then
  :
else
  PREV_YM="$(date -u -v-1m +%Y-%m)"
fi

if download_month "$CUR_YM"; then
  echo "GeoIP: downloaded ${CUR_YM}"
elif download_month "$PREV_YM"; then
  echo "GeoIP: current month not available; downloaded ${PREV_YM}"
else
  echo "GeoIP: ERROR — could not download ${CUR_YM} or ${PREV_YM}" >&2
  exit 1
fi

# Atomic install.
mv -f "${TMPDIR}/dbip.mmdb" "$DEST"
echo "GeoIP: installed database at ${DEST} ($(wc -c < "$DEST") bytes)"
echo "GeoIP: attribution required — 'IP Geolocation by DB-IP' linking to https://db-ip.com"
