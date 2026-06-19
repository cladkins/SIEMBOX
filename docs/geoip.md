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

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `GEOIP_DB_PATH` | `/app/data/dbip-country-lite.mmdb` | Path to the decompressed MMDB. |
| `GEOIP_HOME_COUNTRIES` | (empty) | Comma-separated ISO-2 codes (e.g. `US,CA`). A country not in this list ⇒ `geo_foreign=true`. Empty ⇒ nothing is treated as foreign (foreign-country rules stay quiet). |

If the MMDB is absent, GeoIP logs **one** warning at startup and operates as a
no-op (lookups return `null`; `country`/`country_code`/`geo_foreign` are simply
not added). Private/loopback/link-local/CGNAT/invalid IPs are never looked up.

## Installing / updating the database

The DB is **not** bundled in the image (license, ~8 MB, monthly staleness). Fetch
it on the host into the mounted volume:

```bash
mkdir -p ./data/geoip
GEOIP_DB_PATH=./data/geoip/dbip-country-lite.mmdb backend/scripts/update-geoip.sh
```

The DB-IP Lite file is refreshed monthly. Schedule the script (cron / systemd
timer) and restart the backend afterward. The script computes the current
`YYYY-MM` and falls back to the previous month if the new file isn't published yet.

## Fields added to `parsed_data`

| Field | Type | Example |
|---|---|---|
| `country` | string | `"United States"` |
| `country_code` | string (ISO-2) | `"US"` |
| `geo_foreign` | boolean | `true` |

These power `GEO-001` (Authentication From Foreign Country) and `PWDMGR-003`
(Foreign Vault Login). Both stay quiet until `GEOIP_HOME_COUNTRIES` is set and the
DB is installed.
