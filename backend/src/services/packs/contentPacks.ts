/**
 * Content Packs — curated, per-technology bundles of parsers + detections that
 * install in one click. A pack is a manifest that REFERENCES existing catalog
 * content (by parser name and by detection category/tag); installing a pack just
 * runs the normal catalog install for each referenced item. Packs are bundled in
 * the app (no extra catalog round-trip to discover them) and resolved against the
 * live catalog at install time, so they track catalog updates automatically.
 *
 * Parser names below are the catalog parsers' canonical `name` fields; detection
 * selectors match the catalog's detection categories (the rules/<category>/ dirs)
 * and/or tags, which is robust to individual rule renames.
 */

export interface ContentPack {
  id: string;
  name: string;
  description: string;
  /** Element Plus icon name the frontend maps to a component. */
  icon: string;
  /** Exact catalog parser names this pack installs. */
  parsers: string[];
  /** Install catalog detections whose path is under any of these category dirs. */
  detectionCategories?: string[];
  /** Also install catalog detections carrying any of these tags. */
  detectionTags?: string[];
  /** Short, practical setup hints (which container, where the logs are). */
  setup: string[];
}

export const CONTENT_PACKS: ContentPack[] = [
  {
    id: 'auth-identity',
    name: 'Auth & Identity',
    description:
      'SSO / login platforms and the brute-force, impossible-travel, and account-abuse detections that watch them.',
    icon: 'Key',
    parsers: ['authelia-access', 'authentik-audit', 'keycloak-event', 'ssh-authentication', 'vaultwarden-access'],
    detectionCategories: ['authentication', 'access-control', 'password-manager'],
    setup: [
      'Forward your identity provider logs (Authelia, Authentik, Keycloak) to SIEMBox over syslog.',
      'For SSH, ship /var/log/auth.log (or the systemd journal) from each host.',
      'Vaultwarden: forward the container logs; failed-unlock and export events are detected.',
    ],
  },
  {
    id: 'reverse-proxy',
    name: 'Reverse Proxy & Web',
    description:
      'nginx / Traefik / Caddy access + error logs with path-traversal, enumeration, bad-bot, and method-abuse rules.',
    icon: 'Connection',
    parsers: [
      'standard-nginx-access',
      'standard-nginx-error',
      'traefik-access',
      'caddy-access',
      'apache-nginx-access-log',
      'nginx-komodo-ip-only',
      'nginx-komodo-timestamp-first',
      'nginx-komodo-error',
    ],
    detectionCategories: ['reverse-proxy'],
    setup: [
      'Point your reverse proxy access + error logs at SIEMBox (syslog or a log shipper).',
      'Make sure the real client IP is logged (e.g. nginx $remote_addr, Traefik ClientHost) so geo + threat-feed enrichment works.',
    ],
  },
  {
    id: 'media',
    name: 'Media Servers',
    description: 'Plex and Jellyfin access parsing so playback, login, and admin activity become searchable events.',
    icon: 'VideoPlay',
    parsers: ['plex', 'jellyfin'],
    detectionCategories: [],
    setup: [
      'Forward Plex / Jellyfin server logs to SIEMBox.',
      'No media-specific detections ship yet — this pack gives you parsed, searchable media events to build rules on.',
    ],
  },
  {
    id: 'documents',
    name: 'Document & File Sharing',
    description: 'Nextcloud access parsing plus the data-exfiltration detections (bulk download / unusual access).',
    icon: 'Files',
    parsers: ['nextcloud-access'],
    detectionCategories: ['data-exfiltration'],
    setup: [
      'Forward Nextcloud access logs to SIEMBox.',
      'Paperless-ngx does not have a parser yet — request or contribute one in the catalog repo.',
    ],
  },
  {
    id: 'dns-network',
    name: 'DNS & Network',
    description: 'Pi-hole queries / ad-block and UniFi firewall-audit + IDS-IPS logs with the network-anomaly detections.',
    icon: 'Share',
    parsers: ['pihole-query', 'pihole-dns-adblock', 'ubiquiti-unifi-cef-audit', 'ubiquiti-unifi-ids-ips'],
    detectionCategories: ['network'],
    setup: [
      'Pi-hole: enable remote syslog (or ship the query log) to SIEMBox.',
      'UniFi: enable remote logging for the gateway firewall + IDS/IPS and point it at SIEMBox.',
    ],
  },
  {
    id: 'home-iot',
    name: 'Home & IoT',
    description: 'Home Assistant parsing plus the IoT detections for suspicious automation and device activity.',
    icon: 'House',
    parsers: ['home-assistant'],
    detectionCategories: ['iot'],
    setup: ['Forward the Home Assistant log (or container stdout) to SIEMBox over syslog.'],
  },
  {
    id: 'infrastructure',
    name: 'Linux & Infrastructure',
    description: 'Host-level coverage: sudo, SSH, fail2ban, and generic syslog with the infrastructure detections.',
    icon: 'Monitor',
    parsers: ['linux-sudo', 'ssh-authentication', 'generic-syslog', 'fail2ban'],
    detectionCategories: ['infrastructure'],
    setup: [
      'Ship /var/log/auth.log and /var/log/syslog (or the journal) from each Linux host.',
      'Generic Syslog is the catch-all fallback so nothing is dropped before you add a specific parser.',
    ],
  },
  {
    id: 'siem-standard',
    name: 'CEF / Standard SIEM',
    description: 'CEF and JSON ingestion for appliances and apps that already emit structured security events.',
    icon: 'DataLine',
    parsers: ['cef-standard', 'cef-syslog', 'json-parser'],
    detectionCategories: ['application'],
    setup: [
      'Point CEF-capable appliances (firewalls, WAFs, security tools) at SIEMBox over syslog.',
      'JSON Parser ingests any app already logging structured JSON.',
    ],
  },
];

export function getContentPack(id: string): ContentPack | undefined {
  return CONTENT_PACKS.find((p) => p.id === id);
}

/** True if a detection catalog entry (by path + tags) belongs to a pack. */
export function detectionMatchesPack(
  entry: { path?: string; tags?: string[] },
  pack: ContentPack
): boolean {
  const cats = pack.detectionCategories || [];
  const tags = pack.detectionTags || [];
  if (cats.length) {
    const path = String(entry.path || '');
    if (cats.some((c) => new RegExp(`(^|/)${c}/`).test(path))) return true;
  }
  if (tags.length && Array.isArray(entry.tags)) {
    if (entry.tags.some((t) => tags.includes(t))) return true;
  }
  return false;
}
