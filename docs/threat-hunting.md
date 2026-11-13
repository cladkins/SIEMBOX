# Threat Hunting

Threat Hunting turns a threat report into a hunt through your logs.

1. You give SIEMBox a report: a URL (a vendor blog post, an advisory, a news
   article), pasted text, a STIX 2.x bundle or a MISP event. Or you add a
   source for SIEMBox to watch: an RSS/Atom feed, a MISP feed or a page.
2. SIEMBox extracts the indicators of compromise (IPs, domains, URLs, email
   addresses, MD5/SHA-1/SHA-256 hashes, CVEs) and the ATT&CK techniques the
   report names. With an AI model configured (Settings → AI, the AI Builder
   model), it also writes hunt hypotheses with log search terms.
3. It searches the raw logs of the last N days (1 to 90, default 14) for every
   indicator and search term, keeps sample matching lines, and raises an alert
   when the hunt asks for one.
4. Every hunt is a STIX 2.1 bundle (download it from the hunt) and part of a
   read-only TAXII 2.1 collection other tools can poll.

Open it from **Threat Hunting** in the sidebar. Every role reads hunts.
Analysts, operators and admins start, edit, run and delete hunts and sources.
Admins create TAXII client tokens.

## Starting a hunt

**New hunt** takes one of:

- **Report URL**: `https://` only, on a public host (see [Fetching](#fetching)).
  A URL that returns a STIX bundle or a MISP event (`<uuid>.json`) is read as
  one; a URL that returns an RSS/Atom feed or a MISP feed directory is refused
  with a hint to add it as a source.
- **Paste text**: 20 characters to 1 MB. An IOC list, an email, a report.
- **STIX or MISP file**: a `.json` STIX bundle or MISP event. See
  [Importing STIX](#importing-stix) and [MISP](#misp).

Options: the lookback window, **Raise an alert on a match**, and **Hypotheses
with AI**.

The hunt runs in the background: `pending` → `extracting` → `ready` →
`running` → `completed` (or `failed`, with the reason). The detail view
refreshes itself while the hunt works. One hunt runs at a time; a restart
resumes unfinished hunts.

## What gets extracted

Indicators are found by pattern matching, after refanging (`hxxps://`,
`evil[.]com`, `1.2.3[.]4`, `user[@]host` and similar). SIEMBox drops:

- private, reserved and documentation IP addresses;
- version strings such as `1.2.3.4.5`;
- names whose last label is not a real top-level domain (`ntds.dit`) or is a
  file extension (`payload.exe`, `config.yaml`);
- the report site's own domain, and sites reports cite as references
  (social media, GitHub, sandboxes such as urlscan.io and tria.ge, news sites).
  A full URL on one of those hosts is kept.

For HTML pages, SIEMBox reads the article text and skips navigation, sidebars
and footers.

With an AI model, the model reads up to 40,000 characters of the report and
returns a title, a summary, hypotheses (each with ATT&CK techniques and up to 8
log search terms), and the values in the report that are references, not
indicators. SIEMBox keeps an indicator the model names only when it passes the
same validation and appears in the report's text, so a made-up value never
gets in. Values the model calls references are kept but switched off. Without
a model, or when the call fails, the hunt keeps the pattern-matched indicators
and a hypothesis built from the ATT&CK techniques the report names, and says
so on the hunt.

## Tuning a hunt

In the hunt's detail view:

- **Indicators**: switch any one off (it is no longer searched or exported), or
  add your own.
- **Hypotheses**: edit the title, reasoning, ATT&CK techniques and search terms
  (3 to 200 characters each, up to 20). A search term matches anywhere in a log
  line, case-insensitively. Add your own hypotheses too. A hypothesis you wrote
  or edited survives **Re-read report**.
- **Run hunt** searches again with the current settings.

## How the search works

SIEMBox searches `raw_logs` for lines that contain any term
(`lower(raw_message) LIKE ANY`, 100 terms per statement). It searches the
lookback window in time slices, newest first, so a busy SIEM's 30 days never
has to fit in one statement:

- each slice is one statement per 100 terms, under `HUNT_STATEMENT_TIMEOUT_MS`
  (default 120 s);
- the first slice is 6 hours; a fast slice doubles the next one (up to 7 days),
  and a slice that times out is split into quarters and retried, down to 15
  minutes;
- the whole run stops at `HUNT_MAX_RUNTIME_MS` (default 30 minutes) or after
  20,000 matching lines. It then keeps what it found and says how far back it
  got ("Searched the newest 12 of 30 days"), so the counts cover part of the
  window.

While a hunt runs, its progress shows on the hunt and in the list. On 3
million log lines over 30 days, a 100-term hunt took about 16 s in testing.

Each candidate line is then checked so an indicator only matches as a whole token:
`1.2.3.4` does not match `11.2.3.45`, `evil.com` matches `sub.evil.com` but not
`notevil.com`, a hash does not match inside a longer hex string.

Parsers match only the extracted syslog message, and so does the hunt: it reads
`raw_logs.raw_message`, the message without the syslog header.

Up to 25 sample lines per indicator or search term are stored with the hunt.
They are a snapshot: retention can delete the raw logs later.

A hunt with **Raise an alert on a match** creates one alert (source
`threat-hunt`): severity high when an indicator matched, medium when only
hypothesis terms did. Re-running a hunt that finds the same lines raises no
second alert.

## Monitored sources

**Monitored sources → Add source** takes a URL, a kind (Detect, Feed, Page or MISP feed),
a check interval (30 minutes to 7 days, default 6 hours) and the defaults for
the hunts it creates (lookback, alert on match, AI).

- **Feed** (RSS 2.0, RSS 1.0 or Atom): each new item becomes a hunt for the
  article it links to, named after the item. The first check hunts only the
  newest 3 items; later checks take up to 10 new items each. When the article
  can't be fetched, the hunt uses the item's own content.
- **MISP feed**: the directory of a MISP feed (with `manifest.json` and one
  `<uuid>.json` per event), such as CIRCL's OSINT feed at
  `https://www.circl.lu/doc/misp/feed-osint/`. Each check reads
  `manifest.json`; each new event becomes a hunt named after the event. The
  first check hunts only the newest 3 events and marks the rest seen; later
  checks take up to 10 new events each. Detect recognises a MISP feed from a
  `manifest.json` URL, the manifest itself, or a directory listing that links
  to it. See [MISP](#misp).
- **Page**: SIEMBox extracts the page's indicators on each check and starts a
  new hunt when the set of indicators changes. A page that returns a STIX
  bundle starts a new hunt when the bundle changes.

A source is checked as soon as it is added, re-enabled, or its URL or kind
changes. After that, the `hunt-sources` background job (listed on the Admin
Dashboard with the other background jobs) looks for due sources every 5
minutes, and each source is checked again once its interval has passed. The
Sources tab shows each source's last and next check. **Check now** runs a
check at once; a second check of a source that is already being checked
waits for the first. A failed check shows its error on the source and in
Recent Errors.

"First check" means the first check that succeeds: a source whose first
check failed (a wrong kind, a site that was down) still hunts only the newest
items once it works, not its whole backlog.

Hunts run one at a time. A hunt waiting its turn shows its place in the
queue ("waiting: 3rd in queue"). The page refreshes itself, every 5 seconds
while anything is running and every 30 seconds otherwise.

## STIX 2.1

STIX 2.1 has no hunt object, so a hunt uses standard ones:

| STIX object      | What it holds |
|------------------|---------------|
| `report`         | The hunt: the report's title, summary and URL, and the hunt's state in `x_siembox_hunt` |
| `indicator`      | One per enabled indicator, with a STIX pattern such as `[ipv4-addr:value = '45.142.212.100']` |
| `vulnerability`  | One per CVE |
| `attack-pattern` | One per ATT&CK technique a hypothesis names |
| `note`           | One per enabled hypothesis; search terms in `x_siembox_search_terms` |
| `sighting`       | One per indicator, CVE or hypothesis the last run found: count, first and last seen, sighted by the SIEMBox `identity` |

Object IDs are stable: a re-export or a TAXII poll returns the same IDs with a
newer `modified`. Bundles pass the OASIS `stix2-validator`.

### Importing STIX

**New hunt → STIX bundle**, or `POST /api/hunts/import`, accepts a bundle, a
TAXII envelope or an array of objects (up to 10,000). SIEMBox reads:

- indicator patterns made of simple equality comparisons (`[domain-name:value = '...']`,
  `[file:hashes.'SHA-256' = '...']`, joined by `OR`/`AND`); other patterns and
  non-STIX pattern types are counted and skipped;
- cyber observables (`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`,
  `email-addr`, `file` hashes) and `vulnerability` objects;
- `note` objects as hypotheses (a SIEMBox bundle round-trips with its search
  terms), and the ATT&CK IDs of `attack-pattern` objects;
- the first `report` (else `grouping`, `campaign`, `intrusion-set`, `malware`
  or `threat-actor`) for the title, summary and source URL.

## MISP

A MISP event (from a MISP feed source, a `<uuid>.json` URL, or an uploaded
file) is read as MISP data, not as text:

- **Indicators** come from the attributes MISP marks for detection
  (`to_ids`), on the event and inside its objects. When an event marks none,
  every huntable attribute is used, and the hunt says so. Deleted attributes
  are skipped. At most 500 indicators per event.
- **Types**: `ip-src`, `ip-dst` (and `|port`), `domain`, `hostname`
  (and `|port`), `domain|ip`, `url`, `email`, `email-src`, `email-dst`,
  `email-reply-to`, `md5`, `sha1`, `sha256`, `filename|md5`,
  `filename|sha1`, `filename|sha256`, `vulnerability`. Other types (file names
  alone, registry keys, mutexes, links) are not hunted. Values go through the
  same validation as extracted ones, so private addresses are dropped.
- **Context**: each indicator keeps the attribute's category, comment and
  object name. Its STIX id is the MISP attribute UUID.
- **Techniques**: ATT&CK IDs from the event's `mitre-attack-pattern` galaxies
  and tags (event, object and attribute level) become a hypothesis.
- **Summary**: the creating organisation, date and tags; the first `link`
  attribute is the report URL.

MISP hunts don't use the AI step. Add hypotheses with search terms by hand.

## TAXII 2.1

SIEMBox serves one read-only collection, **SIEMBox Threat Hunts**, with every
hunt's objects.

| | |
|---|---|
| Discovery | `https://<siembox>/api/taxii2/` |
| API root | `https://<siembox>/api/taxii2/hunts/` |
| Collection | `/api/taxii2/hunts/collections/<id>/` (the id is on the STIX / TAXII tab; `threat-hunts` also works) |

Endpoints: discovery, API root, collections, collection, objects, object,
object versions, manifest. Filters: `added_after`, `limit` (default 100, max
1000), `next`, `match[id]`, `match[type]`, `match[version]`,
`match[spec_version]`. A hunt's objects are dated by when the hunt last
changed, so `added_after` returns hunts that changed since the client's last
poll. Up to the 1,000 most recently changed hunts are served.

**Sign-in.** An admin creates a TAXII client token on the **STIX / TAXII** tab.
The token is shown once; SIEMBox stores only its SHA-256 hash. Clients send it
as the HTTP Basic password (any user name) or as `Authorization: Bearer
<token>`. A token reads the TAXII routes and nothing else. A signed-in user's
session works too. SIEMBox never accepts a user's password over Basic auth.

Example (Python `taxii2-client`):

```python
from taxii2client.v21 import Server
server = Server("https://siembox.example/api/taxii2/", user="opencti", password="sbx_taxii_...")
collection = server.default.collections[0]
print(collection.get_objects(type="indicator"))
```

In OpenCTI, add a TAXII2 feed with the API root, the collection, and Basic
auth with the token as the password.

## Fetching

Report URLs, source URLs and redirects are fetched with the same guard the
domain monitor uses:

- `https://` on port 443 only, no user name or password in the URL;
- no IP-address hosts, single-label names, or internal-only names (`.lan`,
  `.local`, `.internal`, `.home.arpa` and similar);
- every address the host resolves to must be public; the connection goes only
  to those addresses, checked at connect time (no DNS rebinding);
- up to 5 redirects, each checked the same way; 20 s per request; 16 MB per
  response (large vendor feeds such as CISA's advisories feed run past 3 MB).

A report on an internal wiki or an `http://` site can't be fetched: paste its
text instead.

## Troubleshooting

- **A source doesn't seem to create hunts.** Open Monitored sources and look
  at Last check and Next check. "error" with a message means the check
  failed; fix the URL or kind (the source is checked again at once). A
  feed only makes a hunt when it publishes a new item, and a page only when
  its indicators change, so a quiet source makes none. New hunts that say
  "waiting: Nth in queue" are queued behind other hunts.
- **A hunt failed with "Could not fetch".** The backend container has no route
  out, or the site refused the request. Paste the text instead, or check
  outbound HTTPS from the backend.
- **"Searching even 15 minutes of logs took longer than 120 s".** Even the
  smallest slice was too slow: switch off short or common search terms, or
  raise `HUNT_STATEMENT_TIMEOUT_MS`.
- **"Searched the newest N of M days".** The run hit `HUNT_MAX_RUNTIME_MS` or
  20,000 matching lines before the end of the window. Switch off noisy terms,
  shorten the window, or raise `HUNT_MAX_RUNTIME_MS`.
- **Few or no hypotheses.** Configure the AI Builder model (Settings → AI), or
  add hypotheses by hand.
- **An indicator is a false positive.** Switch it off in the hunt and run it
  again. The switch survives **Re-read report**.
