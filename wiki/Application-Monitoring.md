# Application Monitoring

**Assets & Vulns → Application Monitoring** lists the software running on your
network — servers, containers, operating systems, browsers, SaaS, remote-access
tools — built from evidence SIEMBox already has. There is nothing to install
and no new agent: a background job matches what SIEMBox sees against the
catalog's **application signatures** every two minutes.

It is an inventory only: it raises no alerts.

## Where the evidence comes from

| Evidence | Read from | What it yields |
|----------|-----------|----------------|
| **Log program** | `raw_logs.app_name`, the syslog TAG (`sshd`, `postfix/smtpd`, `dockerd`, a shipper's tag or container name) | the product on the **logging host** |
| **Parser** | which catalog parser matched the log (`plex`, `traefik-access`, `pihole-query`) | the product on the logging host |
| **Service scan** | `asset_services` from nmap scans (service name; a banner/version when a scanner reports one) | the product on an **asset** (`postgresql`, `ms-wbt-server` → RDP, `vnc`) |
| **Container** | the images log shippers report (`lscr.io/linuxserver/plex:1.40.0`) | product **and version** (from the tag) on the shipper's host |
| **Endpoint package** | SIEMBox Endpoint vulnerability findings (`package=… installed=…`) | package **and installed version** on the endpoint (vulnerable packages only, until the endpoint agent reports a full software list) |
| **Endpoint OS** | the endpoint agent's OS (`Ubuntu 22.04.4 LTS`) | the operating system and version |
| **User agent** | `user_agent` in parsed web/proxy logs (nginx, Traefik, Caddy, NPM, authentik) | client software and version, per **client IP** |
| **DNS** | queried names in DNS logs (Pi-hole) | apps and SaaS in use, per client IP (`*.zoom.us` → Zoom) |

A location is a logging host (its syslog host name, or its address), an asset,
a log shipper's host, or a network client. Hosts are matched to assets by IP
address and host name, so the detail drawer links to *Assets* where it can.

## The page

- **Inventory** — every application seen, with its category, versions (amber
  = behind the newest one seen), where it runs (hosts, clients), which evidence
  showed it, open vulnerabilities and when it was last seen. Click a row for
  the detail: each location with its current version, evidence samples (with a
  link to the matching logs) and the vulnerabilities.
- **Version drift** — applications seen at more than one version across
  locations (each location counts at the newest version it was seen with),
  the most locations behind first.
- **Vulnerabilities** — open findings linked to an application. *Exact*: an
  endpoint finding for one of the signature's packages. *Best effort*: an open
  finding on an asset where the application was seen whose title or Nuclei
  template names the product. Each links to *Vulnerability Management*
  (operators and admins).
- **Unmanaged** — seen on the network, not inventoried: applications that only
  show up in clients' DNS queries or user agents, with no host, container,
  scan or endpoint evidence of yours (a SaaS your users rely on, a
  remote-access tool such as AnyDesk).
- **Not identified** — the most frequent program names, container images and
  user-agent products no signature matches, each with **Suggest signature**,
  which opens a pre-filled signature file in the catalog.

Filters: category, evidence source, host (name, IP or shipper) and search.
Every role can read the page; **Refresh now** (re-read the catalog and run the
job) is for analysts and up.

## Signatures

Signatures live in the catalog,
[`cladkins/siembox-catalog`](https://github.com/cladkins/siembox-catalog), as
`applications/<id>.app.yaml`, next to parsers, detections and content packs:

```yaml
schema: siembox.app/v1
id: plex
name: Plex Media Server
vendor: Plex
category: media-server
cpe: { vendor: plex, product: media_server }
match:
  syslog_program: [plex, plexmediaserver]
  parser: [plex]
  container_image: [plexinc/pms-docker, linuxserver/plex, '*/linuxserver/plex']
  package: [plexmediaserver]
  user_agent:
    - '^PlexMediaServer/(\d+(?:\.\d+)+)'
  dns: [plex.tv, plex.direct]
tests:
  - source: container_image
    input: 'lscr.io/linuxserver/plex:1.40.0.7998-c29d4c0c8-ls210'
    version: '1.40.0.7998'
  - source: user_agent
    input: PlexMediaServer/1.40.0.7998-c29d4c0c8
    version: '1.40.0.7998'
  # ... one or more tests per matcher kind
```

- `syslog_program` — exact program names, case-insensitive; `postfix/*` also
  matches `postfix/smtpd`.
- `parser` — catalog parser names.
- `service` — `names` (nmap service names) and `banner` (regexes; the one
  group is the version).
- `container_image` — image name globs, no tag (`*` matches any characters);
  `docker.io/library/` is folded away. The tag is the version when it starts
  with a number.
- `package` — package names in endpoint findings.
- `user_agent` — regexes on the user agent; the one group is the version.
- `dns` — `zoom.us` matches zoom.us and every subdomain; `*.plex.direct` only
  subdomains.
- `os` — `family` (linux, windows, darwin) and an optional `pretty_name` regex.
- `supersedes` — when two signatures match the same evidence, the listed ones
  are dropped (Edge's user agent also says Chrome).

Every regex is plain JavaScript, at most one capture group (the version), and
must pass the same ReDoS check parsers and detection rules do. Validate with
`npm run validate-applications` (see the catalog's CONTRIBUTING); the catalog's
CI runs it on every pull request.

SIEMBox reads the catalog's signatures at most every five minutes. If the
catalog cannot be reached it keeps using the last set it read (also stored in
the database, so a restart keeps it), and falls back to a small built-in
starter set only when it has never read one.

## In the Context Graph

Every application in the inventory is also a node of the **Context Graph**
(a green pentagon marked **P**). **Open in Context Graph** in an
application's detail drawer centres the graph on it; search the graph by an
application's name, vendor or id. The links are solid (they come from the
inventory, not from what a single log said) and current, like the page:

- **asset / host / IP / log shipper → runs → application** — where it runs,
  with the versions and evidence sources on the link. An asset collects every
  location that is it (its id from scans and endpoint findings, its IP and
  host name from logs, a shipper at its address); a log shipper's link is its
  host's containers.
- **client IP → uses → application** — seen only on the network (user agents,
  DNS queries), marked *network evidence*. That is not "runs": expanding the
  asset at that IP doesn't list it, its IP does. An application seen only
  this way is flagged *seen only on the network* (the Unmanaged tab).
- **application → has → vulnerability** — the linked open findings: an
  *exact* match is a solid link, a *best-effort* one (the finding names the
  product) a dotted one.

Expanding an asset, host, IP or shipper lists its applications; expanding a
vulnerability lists the applications it is linked to. An application on
hundreds of clients shows as one *very common* group with a handful of them,
like any other busy relation; **Table** pages through all of them. The
details panel links back to the application here. Every role that can read
this page sees the same in the graph.

## Settings

*Settings → Application Monitoring* (admins): switch the inventory off, how
many days an application, version or location stays listed after it was last
seen (30 by default), and the backfill on upgrade (7 days of existing logs).
Scan, container and endpoint evidence follows its source at once: an upgraded
image or a patched package replaces the old version immediately.

## Limits

- nmap scans run through node-nmap, which records the service name but not the
  product or version, so a service scan names a product only for
  product-specific services (PostgreSQL, Redis, RDP, VNC...). `ssh` alone could
  be OpenSSH or Dropbear and is not claimed.
- The endpoint agent reports vulnerable packages only; its full software list
  (SBOM) is a later phase.
- A new signature applies to logs from when it is loaded on; scan, container
  and endpoint evidence is re-matched every run.
