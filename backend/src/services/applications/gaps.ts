/**
 * The "Not identified" list's pure parts: what an unmatched value is keyed by
 * for each evidence kind (a service's product, a domain's registrable name),
 * which values are noise (operating-system packages, CDN domains, generic nmap
 * names), and the starting signature the editor opens for one. DB-free;
 * rollup.ts stores the values, inventory.ts lists them, the routes hand the
 * drafts to the page.
 *
 * Kinds (application_unmatched.source):
 *   syslog_program  a log program name            -> match.syslog_program
 *   parser          a parser that matched logs    -> match.parser
 *   container       an image name (no tag)        -> match.container_image
 *   package         an installed package name     -> match.package
 *                   (endpoint agents' package lists and EDR findings)
 *   service         an nmap product ("Apache httpd") or bare service name -> match.service
 *   user_agent      a user-agent product token    -> match.user_agent
 *   dns             a registrable domain          -> match.dns
 */
import { APP_SCHEMA, normalizeImageName } from './appFormat';
import { cleanVersion } from './matchers';

export const UNMATCHED_KINDS = ['syslog_program', 'parser', 'container', 'package', 'service', 'user_agent', 'dns'] as const;
export type UnmatchedKind = (typeof UNMATCHED_KINDS)[number];
/** Kinds rebuilt from a snapshot each refresh (the rest add up from logs). */
export const SNAPSHOT_UNMATCHED_KINDS: UnmatchedKind[] = ['container', 'package', 'service'];

export function isUnmatchedKind(v: unknown): v is UnmatchedKind {
  return typeof v === 'string' && (UNMATCHED_KINDS as readonly string[]).includes(v);
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

/** nmap service names that say nothing about the software. */
const GENERIC_SERVICES = new Set([
  'unknown', 'tcpwrapped', 'http', 'https', 'http-proxy', 'http-alt', 'ssl', 'ssl/http', 'ssl/https', 'ssl/unknown', 'domain', 'upnp',
  'rpcbind', 'msrpc', 'netbios-ssn', 'microsoft-ds', 'ident', 'filtered', 'closed',
]);

/**
 * The product an nmap service names: the words of service_version before the
 * first one that starts with a digit or a parenthesis ("Apache httpd 2.4.41
 * ((Ubuntu))" -> "Apache httpd", "OpenSSH 8.9p1 Ubuntu 3ubuntu0.6" ->
 * "OpenSSH"); null when the scan reported no product.
 */
export function serviceProduct(serviceVersion: string | null | undefined): string | null {
  const s = (serviceVersion ?? '').trim().slice(0, 200);
  if (!s) return null;
  const words: string[] = [];
  for (const w of s.split(/\s+/)) {
    if (/^[\d(]/.test(w)) break;
    words.push(w);
    if (words.length >= 6) break;
  }
  const p = words.join(' ').trim();
  return p.length >= 2 ? p.slice(0, 100) : null;
}

/** An unmatched service's key: its product, else its service name (lower case). */
export function serviceKey(s: { service_name?: string | null; service_version?: string | null }): string | null {
  const product = serviceProduct(s.service_version);
  if (product) return product;
  const name = (s.service_name ?? '').trim().toLowerCase();
  return name ? name.slice(0, 64) : null;
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

/** Two-label public suffixes common enough to matter (a short list, not the PSL). */
const TWO_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'com.br',
  'com.cn', 'com.mx', 'com.tr', 'co.in', 'co.za', 'com.sg', 'com.hk', 'com.tw', 'co.il', 'github.io', 'herokuapp.com', 'azurewebsites.net',
  'cloudfront.net', 'amazonaws.com', 'appspot.com', 'blogspot.com', 'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app', 'duckdns.org',
  'ts.net', 'plex.direct',
]);
/** Names that are never a public application: reverse lookups, local zones. */
const LOCAL_SUFFIXES = ['arpa', 'local', 'lan', 'home', 'internal', 'localdomain', 'localhost', 'intranet', 'corp', 'home.arpa', 'test', 'invalid', 'example'];

/**
 * The registrable domain of a queried name ("us04web.zoom.us" -> "zoom.us",
 * "www.bbc.co.uk" -> "bbc.co.uk"), or null for a local or reverse name.
 */
export function registrableDomain(domain: string): string | null {
  const d = domain.trim().toLowerCase().replace(/\.+$/, '');
  if (!d || d.length > 253 || !/^[a-z0-9_.-]+$/.test(d)) return null;
  const labels = d.split('.').filter(Boolean);
  if (labels.length < 2) return null;
  for (const s of LOCAL_SUFFIXES) if (d === s || d.endsWith(`.${s}`)) return null;
  if (/^\d+$/.test(labels[labels.length - 1])) return null; // an IP address
  const two = labels.slice(-2).join('.');
  if (TWO_LABEL_SUFFIXES.has(two)) return labels.length >= 3 ? labels.slice(-3).join('.') : null;
  return two;
}

/** Infrastructure domains every network queries (CDNs, ad and telemetry endpoints): listed, but noise. */
const NOISE_DOMAINS = new Set([
  'akamai.net', 'akamaiedge.net', 'akamaihd.net', 'akadns.net', 'edgekey.net', 'edgesuite.net', 'cloudfront.net', 'amazonaws.com',
  'cloudflare.com', 'cloudflare.net', 'fastly.net', 'fastly.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'gvt1.com',
  'gvt2.com', 'doubleclick.net', 'googlesyndication.com', 'google-analytics.com', 'googletagmanager.com', 'msftncsi.com', 'msedge.net',
  'trafficmanager.net', 'azureedge.net', 'windowsupdate.com', 'ntp.org', 'pool.ntp.org', 'apple-dns.net', 'aaplimg.com', 'cdn77.org',
  'jsdelivr.net', 'unpkg.com', 'digicert.com', 'letsencrypt.org', 'lencr.org', 'sectigo.com', 'ocsp.apple.com', 'root-servers.net',
]);

// ---------------------------------------------------------------------------
// Packages
// ---------------------------------------------------------------------------

/** Raw prefixes: a name that starts with one is part of the OS or a library. */
const SYSTEM_PREFIXES = [
  'lib', 'linux-', 'python3', 'python-', 'perl-', 'ruby-', 'golang-', 'node-', 'php-', 'r-cran-', 'fonts-', 'font-', 'xfonts-', 'gir1.2-',
  'xserver-', 'x11-', 'xorg-', 'texlive-', 'firmware-', 'gstreamer', 'gnome-', 'kde-', 'plasma-', 'qt5', 'qt6', 'qml-', 'language-pack-',
  'hunspell-', 'hyphen-', 'mythes-', 'ubuntu-', 'debian-', 'base-', 'cloud-', 'xz-', 'lsb-', 'console-', 'keyboard-', 'xkb-', 'sgml-',
  'xml-', 'docbook', 'dh-', 'gsettings-', 'adwaita-', 'hicolor-', 'humanity-', 'yaru-', 'alsa-', 'mesa-', 'printer-driver-',
  'microsoft visual c++', 'microsoft .net', 'update for ', 'security update for ', 'windows sdk', 'windows software development kit',
  'com.apple.',
];
/** Applications whose names start like a library (lib...). */
const NOT_SYSTEM = ['libreoffice', 'librewolf', 'libvirt', 'librenms', 'librespeed', 'libation', 'librecad'];
/** Families: the name itself, or it followed by "-", a digit or ".": gcc, gcc-12, cpp-12, systemd-timesyncd. */
const SYSTEM_FAMILIES = [
  'kernel', 'apt', 'dpkg', 'systemd', 'util-linux', 'bsdutils', 'coreutils', 'glibc', 'gcc', 'cpp', 'g++', 'binutils', 'locales', 'tzdata',
  'ca-certificates', 'mime-support', 'netbase', 'adduser', 'login', 'passwd', 'ncurses', 'readline', 'e2fsprogs', 'procps', 'iproute2',
  'iputils', 'initramfs-tools', 'grub', 'grub2', 'shim', 'snapd', 'dbus', 'udev', 'kmod', 'pam', 'zlib', 'zlib1g', 'bzip2', 'gzip', 'tar',
  'sed', 'grep', 'gawk', 'mawk', 'findutils', 'diffutils', 'debconf', 'debianutils', 'sensible-utils', 'debhelper', 'make', 'patch',
  'manpages', 'man-db', 'info', 'install-info', 'publicsuffix', 'shared-mime-info', 'dconf', 'glib', 'glib2', 'gtk', 'gtk2', 'gtk3', 'gtk4',
  'pulseaudio', 'pipewire', 'wireplumber', 'vulkan', 'cups', 'hplip', 'foomatic', 'poppler', 'ghostscript', 'gsfonts', 'bash', 'dash',
  'zsh', 'sudo', 'less', 'nano', 'vim', 'ed', 'hostname', 'mount', 'ucf', 'perl', 'python', 'xdg-utils', 'xdg-user-dirs', 'desktop-file-utils',
  'gpgv', 'gnupg', 'gpg', 'openssl', 'krb5', 'keyutils', 'acl', 'attr', 'libc', 'busybox', 'musl', 'alpine-baselayout', 'alpine-keys',
  'apk-tools', 'rpm', 'dnf', 'yum', 'filesystem', 'setup', 'chkconfig', 'shadow-utils', 'selinux-policy', 'audit', 'which', 'file',
];
const SYSTEM_SUFFIXES = ['-dev', '-devel', '-doc', '-docs', '-common', '-data', '-dbg', '-dbgsym', '-locale', '-l10n', '-i18n', '-headers', '-libs', '-utils-common', '-perl', '-python'];
/** Language-ecosystem packages are libraries, not applications. */
const LIBRARY_TYPES = new Set(['npm', 'pypi', 'python', 'gem', 'go', 'go-module', 'cargo', 'rust', 'maven', 'java-archive', 'nuget', 'composer', 'php-composer', 'pub', 'hex', 'cocoapods', 'conan', 'r-package', 'dotnet']);

/**
 * A package that is part of the operating system or a library rather than an
 * application of its own: shown only with "Show system packages".
 */
export function isSystemPackage(name: string, type?: string | null): boolean {
  const n = name.trim().toLowerCase();
  if (!n) return true;
  if (type && LIBRARY_TYPES.has(type.trim().toLowerCase())) return true;
  if (/^kb\d{5,}$/.test(n)) return true;
  if (NOT_SYSTEM.some((a) => n.startsWith(a))) return false;
  for (const p of SYSTEM_PREFIXES) if (n.startsWith(p)) return true;
  for (const f of SYSTEM_FAMILIES) if (n === f || (n.startsWith(f) && /^[-.\d:]/.test(n.slice(f.length)))) return true;
  for (const s of SYSTEM_SUFFIXES) if (n.endsWith(s)) return true;
  return false;
}

/** Is this unmatched value noise (hidden unless asked for)? */
export function isNoise(kind: string, value: string, detail?: Record<string, unknown> | null): boolean {
  switch (kind) {
    case 'package':
      return isSystemPackage(value, typeof detail?.type === 'string' ? detail.type : null);
    case 'service':
      return !serviceProduct(typeof detail?.service_version === 'string' ? detail.service_version : null) && GENERIC_SERVICES.has(value.toLowerCase());
    case 'dns':
      return NOISE_DOMAINS.has(value.toLowerCase());
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Drafts
// ---------------------------------------------------------------------------

export interface GapItem {
  source: string;
  value: string;
  sample?: string | null;
  detail?: Record<string, unknown> | null;
}

export function slugify(s: string): string {
  return (
    s
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60)
      .replace(/-+$/g, '') || 'new-application'
  );
}

const titleCase = (s: string) =>
  s
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((w) => (w.length <= 3 && /^[a-z]+$/.test(w) && w !== 'app' ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)))
    .join(' ');

export const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/** A guess at the application's name and vendor from the value. */
export function guessNames(item: GapItem): { name: string; vendor: string } {
  const v = item.value.trim();
  switch (item.source) {
    case 'container': {
      const parts = normalizeImageName(v).split('/');
      const last = parts[parts.length - 1] ?? v;
      const owner = parts.length >= 2 ? parts[parts.length - 2] : '';
      const vendor = owner && !owner.includes('.') && owner !== 'library' ? titleCase(owner) : '';
      return { name: titleCase(last), vendor };
    }
    case 'dns': {
      const first = v.split('.')[0] ?? v;
      return { name: titleCase(first), vendor: titleCase(first) };
    }
    case 'service':
    case 'user_agent':
      return { name: v, vendor: '' };
    default:
      return { name: titleCase(v.replace(/[/.]/g, ' ')), vendor: '' };
  }
}

/** The regex a service's banner/version should match: its product, then the version as group 1. */
export function productVersionRegex(product: string): string {
  return `^${escapeRegex(product)} (\\d[\\w.~+-]*)`;
}

/**
 * The signature the editor opens for an unmatched value: one matcher of the
 * value's kind, one test from its sample, name and vendor guessed, category
 * left for the author (guessed only for DNS and user agents). A document in
 * the catalog format (not yet valid: the category may be empty).
 */
export function draftForGap(item: GapItem): Record<string, unknown> {
  const { name, vendor } = guessNames(item);
  const value = item.value.trim();
  const sample = item.sample ?? null;
  const d = item.detail ?? {};
  let match: Record<string, unknown>;
  const tests: Array<Record<string, unknown>> = [];
  let category = '';
  switch (item.source) {
    case 'syslog_program':
      match = { syslog_program: [value.toLowerCase()] };
      tests.push({ source: 'syslog_program', input: value });
      break;
    case 'parser':
      match = { parser: [value] };
      tests.push({ source: 'parser', input: value });
      break;
    case 'container': {
      match = { container_image: [normalizeImageName(value)] };
      const t: Record<string, unknown> = { source: 'container_image', input: sample ?? value };
      tests.push(t);
      break;
    }
    case 'package': {
      match = { package: [value.toLowerCase()] };
      tests.push({ source: 'package', input: value.toLowerCase() });
      break;
    }
    case 'service': {
      const serviceName = typeof d.service_name === 'string' ? d.service_name.toLowerCase() : '';
      const serviceVersion = typeof d.service_version === 'string' ? d.service_version : '';
      const product = serviceProduct(serviceVersion);
      if (product) {
        match = { service: { banner: [productVersionRegex(product)] } };
        const t: Record<string, unknown> = { source: 'service', input: { name: serviceName || 'unknown', version: serviceVersion } };
        const m = new RegExp(productVersionRegex(product)).exec(serviceVersion);
        if (m && cleanVersion(m[1])) t.version = cleanVersion(m[1]);
        tests.push(t);
      } else {
        match = { service: { names: [value.toLowerCase()] } };
        tests.push({ source: 'service', input: { name: value.toLowerCase() } });
      }
      break;
    }
    case 'user_agent': {
      category = 'http-client';
      match = { user_agent: [`\\b${escapeRegex(value)}/(\\d+(?:\\.\\d+)*)`] };
      const input = sample ?? `${value}/1.0`;
      const t: Record<string, unknown> = { source: 'user_agent', input };
      const m = new RegExp(`\\b${escapeRegex(value)}/(\\d+(?:\\.\\d+)*)`).exec(input);
      if (m && cleanVersion(m[1])) t.version = cleanVersion(m[1]);
      tests.push(t);
      break;
    }
    case 'dns':
    default:
      category = 'saas';
      match = { dns: [value.toLowerCase()] };
      tests.push({ source: 'dns', input: sample && sample !== value ? sample : value.toLowerCase() });
      break;
  }
  return {
    schema: APP_SCHEMA,
    id: slugify(item.source === 'dns' ? value.split('.')[0] ?? value : name || value),
    name: name || value,
    vendor,
    category,
    description: '',
    match,
    tests,
  };
}
