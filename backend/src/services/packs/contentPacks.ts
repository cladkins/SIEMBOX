/**
 * The bundled Content Packs: the fallback set, used only when the catalog has
 * no packs/ (a catalog from before packs moved there) or cannot be reached
 * and nothing is cached yet. The catalog (cladkins/siembox-catalog,
 * packs/<id>.pack.yaml) is the source of truth; packCatalog.ts reads it.
 *
 * These are the eight packs SIEMBox shipped before packs moved to the
 * catalog, in the siembox.pack/v1 shape (packFormat.ts), so nothing regresses
 * on an install that cannot see the catalog's packs: the same parsers and
 * detection selectors, version 1, no Sigma rules, and the short setup hints as
 * guide steps. The catalog's versions start at 2 (they add Sigma rules and
 * fuller guides), so an install made from these shows the catalog's additions
 * as "What's new" once the catalog packs are reachable.
 *
 * Parser names are the catalog parsers' canonical `name` fields; detection
 * selectors match the catalog's detection categories (detections/<category>/)
 * and/or tags, which is robust to individual rule renames.
 */
import type { ContentPack, PackSetupStep } from './packFormat';

export type { ContentPack } from './packFormat';
export { detectionMatchesPack } from './packFormat';

const steps = (...lines: Array<[string, string]>): PackSetupStep[] => lines.map(([title, text]) => ({ title, text }));
const sel = (categories: string[]) => ({ categories, tags: [], names: [] });

export const CONTENT_PACKS: ContentPack[] = [
  {
    id: 'auth-identity',
    name: 'Auth & Identity',
    description:
      'SSO / login platforms and the brute-force, impossible-travel, and account-abuse detections that watch them.',
    icon: 'Key',
    version: 1,
    parsers: ['authelia-access', 'authentik-audit', 'keycloak-event', 'ssh-authentication', 'vaultwarden-access'],
    detections: sel(['authentication', 'access-control', 'password-manager']),
    sigma: [],
    setup: steps(
      ['Identity provider', 'Forward your identity provider logs (Authelia, Authentik, Keycloak) to SIEMBox over syslog.'],
      ['SSH', 'For SSH, ship /var/log/auth.log (or the systemd journal) from each host.'],
      ['Vaultwarden', 'Vaultwarden: forward the container logs; failed-unlock and export events are detected.']
    ),
  },
  {
    id: 'reverse-proxy',
    name: 'Reverse Proxy & Web',
    description:
      'nginx / Traefik / Caddy access + error logs with path-traversal, enumeration, bad-bot, and method-abuse rules.',
    icon: 'Connection',
    version: 1,
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
    detections: sel(['reverse-proxy']),
    sigma: [],
    setup: steps(
      ['Ship the logs', 'Point your reverse proxy access + error logs at SIEMBox (syslog or a log shipper).'],
      [
        'Log the real client IP',
        'Make sure the real client IP is logged (e.g. nginx $remote_addr, Traefik ClientHost) so geo + threat-feed enrichment works.',
      ]
    ),
  },
  {
    id: 'media',
    name: 'Media Servers',
    description: 'Plex and Jellyfin access parsing so playback, login, and admin activity become searchable events.',
    icon: 'VideoPlay',
    version: 1,
    parsers: ['plex', 'jellyfin'],
    detections: sel([]),
    sigma: [],
    setup: steps(
      ['Ship the logs', 'Forward Plex / Jellyfin server logs to SIEMBox.'],
      [
        'Detections',
        'No media-specific detections ship yet — this pack gives you parsed, searchable media events to build rules on.',
      ]
    ),
  },
  {
    id: 'documents',
    name: 'Document & File Sharing',
    description: 'Nextcloud access parsing plus the data-exfiltration detections (bulk download / unusual access).',
    icon: 'Files',
    version: 1,
    parsers: ['nextcloud-access'],
    detections: sel(['data-exfiltration']),
    sigma: [],
    setup: steps(
      ['Nextcloud', 'Forward Nextcloud access logs to SIEMBox.'],
      ['Paperless-ngx', 'Paperless-ngx does not have a parser yet — request or contribute one in the catalog repo.']
    ),
  },
  {
    id: 'dns-network',
    name: 'DNS & Network',
    description: 'Pi-hole queries / ad-block and UniFi firewall-audit + IDS-IPS logs with the network-anomaly detections.',
    icon: 'Share',
    version: 1,
    parsers: ['pihole-query', 'pihole-dns-adblock', 'ubiquiti-unifi-cef-audit', 'ubiquiti-unifi-ids-ips'],
    detections: sel(['network']),
    sigma: [],
    setup: steps(
      ['Pi-hole', 'Pi-hole: enable remote syslog (or ship the query log) to SIEMBox.'],
      ['UniFi', 'UniFi: enable remote logging for the gateway firewall + IDS/IPS and point it at SIEMBox.']
    ),
  },
  {
    id: 'home-iot',
    name: 'Home & IoT',
    description: 'Home Assistant parsing plus the IoT detections for suspicious automation and device activity.',
    icon: 'House',
    version: 1,
    parsers: ['home-assistant'],
    detections: sel(['iot']),
    sigma: [],
    setup: steps(['Home Assistant', 'Forward the Home Assistant log (or container stdout) to SIEMBox over syslog.']),
  },
  {
    id: 'infrastructure',
    name: 'Linux & Infrastructure',
    description: 'Host-level coverage: sudo, SSH, fail2ban, and generic syslog with the infrastructure detections.',
    icon: 'Monitor',
    version: 1,
    parsers: ['linux-sudo', 'ssh-authentication', 'generic-syslog', 'fail2ban'],
    detections: sel(['infrastructure']),
    sigma: [],
    setup: steps(
      ['Ship host logs', 'Ship /var/log/auth.log and /var/log/syslog (or the journal) from each Linux host.'],
      [
        'Generic Syslog',
        'Generic Syslog is the catch-all fallback so nothing is dropped before you add a specific parser.',
      ]
    ),
  },
  {
    id: 'siem-standard',
    name: 'CEF / Standard SIEM',
    description: 'CEF and JSON ingestion for appliances and apps that already emit structured security events.',
    icon: 'DataLine',
    version: 1,
    parsers: ['cef-standard', 'cef-syslog', 'json-parser'],
    detections: sel(['application']),
    sigma: [],
    setup: steps(
      ['CEF appliances', 'Point CEF-capable appliances (firewalls, WAFs, security tools) at SIEMBox over syslog.'],
      ['JSON', 'JSON Parser ingests any app already logging structured JSON.']
    ),
  },
];

export function getBundledPack(id: string): ContentPack | undefined {
  return CONTENT_PACKS.find((p) => p.id === id);
}
