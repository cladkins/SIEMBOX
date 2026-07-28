# GeoIP Enrichment

SIEMBox enriches every parsed log with `country`, `country_code`, and a boolean
`geo_foreign` derived from the log's normalized `source_ip`, using an **offline**
[DB-IP IP-to-Country Lite](https://db-ip.com/db/lite.php) MMDB read by the pure-JS
[`mmdb-lib`](https://www.npmjs.com/package/mmdb-lib) (no native deps, no network
calls at lookup time).

## Attribution (required)

The DB-IP Lite database is licensed under
[Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
Any UI page that displays or uses GeoIP results **must** show:

> IP Geolocation by DB-IP — `<a href="https://db-ip.com">IP Geolocation by DB-IP</a>`

SIEMBox satisfies this with a persistent link in the global app footer
(`frontend/src/views/Layout.vue`), shown on every page.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `GEOIP_DB_PATH` | `/app/data/dbip-country-lite.mmdb` | Path to the decompressed MMDB. |
| `GEOIP_HOME_COUNTRIES` | (empty) | Comma-separated ISO-2 codes (e.g. `US,CA`). A country not in this list ⇒ `geo_foreign=true`. Empty ⇒ nothing is treated as foreign (foreign-country rules stay quiet). |
| `GEOIP_AUTO_UPDATE` | `true` | Whether the backend downloads and refreshes the MMDB itself. Set `false` for air-gapped installs. |

If the MMDB is absent, GeoIP logs **one** warning at startup and operates as a
no-op (lookups return `null`; `country`/`country_code`/`geo_foreign` are simply
not added). Private/loopback/link-local/CGNAT/invalid IPs are never looked up.

## Installing / updating the database

The DB is **not** bundled in the image (license, ~8 MB, monthly staleness).

**By default the backend fetches it for you.** A background job — *GeoIP database
update*, visible in Admin → Background Jobs — runs shortly after startup and every
12 hours, downloading the DB-IP Lite file when the local copy is missing or older
than 25 days, then reloading it in place (no restart needed). It tries the current
`YYYY-MM` and falls back to the previous month, since the new file is not
published on the 1st.

A download is only installed if the decompressed bytes actually parse as an MMDB,
so a captive portal or a truncated transfer cannot replace a working database with
a broken one. Failures are recorded against the job and in Recent Errors, deduped;
enrichment simply stays off until a fetch succeeds.

### Air-gapped or manual installs

Set `GEOIP_AUTO_UPDATE=false` and fetch it on the host into the mounted volume:

```bash
mkdir -p ./data/geoip
GEOIP_DB_PATH=./data/geoip/dbip-country-lite.mmdb backend/scripts/update-geoip.sh
```

Schedule the script (cron / systemd timer) and restart the backend afterward — the
service reads the MMDB once at construction, so a file dropped in while it is
running is not picked up unless the update job installs it.

## Troubleshooting: the map and country tables are empty

Enrichment happens at **parse time**, and the values are copied into
`alerts.matched_data` when an alert is raised. So:

- **Existing rows never backfill.** Installing the database only affects logs
  ingested afterwards. Give it live traffic before judging.
- **Reserved ranges never resolve.** `203.0.113.0/24` (TEST-NET-3),
  `198.51.100.0/24`, RFC1918 and loopback all return `null` by design, so
  synthetic test events will never appear on the map.
- **`geo_foreign` needs `GEOIP_HOME_COUNTRIES`.** With no home list nothing is
  foreign, so foreign-traffic counts stay at zero even once countries resolve.

## Fields added to `parsed_data`

| Field | Type | Example |
|---|---|---|
| `country` | string | `"United States"` |
| `country_code` | string (ISO-2) | `"US"` |
| `geo_foreign` | boolean | `true` |

These power `GEO-001` (Authentication From Foreign Country) and `PWDMGR-003`
(Foreign Vault Login). Both stay quiet until `GEOIP_HOME_COUNTRIES` is set and the
DB is installed.
