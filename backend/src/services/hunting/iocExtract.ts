/**
 * Indicator-of-compromise extraction for Threat Hunting.
 *
 * Pure and deterministic: no network, no database, no AI. Takes the text of a
 * threat report (already stripped of HTML) and returns the indicators it
 * names, refanged ("hxxp://evil[.]com" becomes "http://evil.com") and
 * filtered, plus the ATT&CK technique IDs it mentions.
 *
 * Every regex here runs in linear time on its input (no nested quantifiers
 * over overlapping classes), and the input is capped at MAX_TEXT_CHARS.
 */
import { isIP } from 'net';
import { isPublicAddress } from '../exposure/domainMonitor/netSafety';
import { IANA_TLDS } from './tlds';

export type IocType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'email' | 'md5' | 'sha1' | 'sha256' | 'cve';

export const IOC_TYPES: readonly IocType[] = ['ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'cve'];

export interface ExtractedIoc {
  type: IocType;
  value: string;
  /** The sentence around the first mention, for the analyst. */
  context: string;
}

export interface ExtractionResult {
  indicators: ExtractedIoc[];
  /** ATT&CK technique IDs (T1059, T1059.001) the text names. */
  techniques: string[];
}

export const MAX_TEXT_CHARS = 1_000_000;
export const MAX_INDICATORS = 500;
const MAX_CONTEXT = 240;

/**
 * Top-level "domains" that are really file names (payload.exe, config.yaml).
 * A few are also real TLDs (.zip, .sh, .py, .app), but in a threat report a
 * name ending in them is a file far more often than a host.
 */
const FILE_EXTENSIONS = new Set(
  (
    'exe dll sys bat cmd ps1 psm1 psd1 vbs vbe js jse wsf hta scr cpl ocx drv msi msp lnk reg inf ' +
    'php html htm aspx asp jsp cgi pl py rb sh bash zsh go rs java class jar war ear so ko dylib elf bin ' +
    'png jpg jpeg gif bmp ico svg webp tiff mp3 mp4 avi mov wav txt log json xml yaml yml toml ini cfg conf ' +
    'md csv tsv doc docx docm xls xlsx xlsm ppt pptx pdf rtf odt eml msg pst ost chm one ' +
    'zip rar 7z gz tgz bz2 xz tar cab iso img vhd vhdx vmdk dmg pkg deb rpm apk ipa app ' +
    'tmp dat db sqlite bak old lock env pem crt cer der key pfx p12 sig asc gpg css scss less map ' +
    'ts tsx jsx vue sql plist sln csproj pdb obj lib dmp evtx etl pcap pcapng'
  ).split(' ')
);

/**
 * Hosts a report links to as references, not as indicators. A domain equal to
 * one of these, or a subdomain of one, is dropped (a URL on it is kept: a
 * specific path on github.com can be a payload).
 */
const REFERENCE_DOMAINS = [
  'twitter.com', 'x.com', 't.co', 'facebook.com', 'instagram.com', 'linkedin.com', 'youtube.com',
  'reddit.com', 'medium.com', 'bsky.app', 'github.com', 'gitlab.com', 'google.com', 'gmail.com',
  'googleapis.com', 'gstatic.com', 'googletagmanager.com', 'google-analytics.com', 'doubleclick.net',
  'microsoft.com', 'outlook.com', 'apple.com', 'amazon.com', 'cloudflare.com', 'mitre.org',
  'virustotal.com', 'w3.org', 'schema.org', 'gravatar.com', 'wordpress.com', 'wikipedia.org',
  'cisa.gov', 'nist.gov', 'cve.org', 'first.org', 'jquery.com', 'bootstrapcdn.com', 'example.com',
  'example.org', 'example.net',
  // Sandboxes, scanners and research sites a report cites as evidence.
  'urlscan.io', 'tria.ge', 'any.run', 'joesandbox.com', 'hybrid-analysis.com', 'abuse.ch', 'shodan.io',
  'censys.io', 'alienvault.com', 'malpedia.caad.fkie.fraunhofer.de', 'detection.fyi', 'sigmahq.io',
  'sigmasearchengine.com', 'unprotect.it', 'lolbas-project.github.io', 'bleepingcomputer.com',
  'thehackernews.com', 'securityweek.com', 'darkreading.com',
];

// ---- Refanging ---------------------------------------------------------------

/**
 * Undo the usual defanging: hxxp(s), [.] (.) {.} [dot] (dot), [:], [@] [at],
 * [/]. Applied to the whole text before extraction, so the context shown to
 * the analyst is refanged too.
 */
export function refang(text: string): string {
  return text
    .replace(/\bh(?:xx|\*\*|XX)p(s?)(\[?:\]?)\/\//g, 'http$1://')
    .replace(/\bfxp:\/\//gi, 'ftp://')
    .replace(/\s?[[({]\s?(?:\.|dot)\s?[\])}]\s?/gi, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[\/\]/g, '/')
    .replace(/\s?[[({]\s?(?:@|at)\s?[\])}]\s?/gi, '@');
}

// ---- Validators (shared with the AI merge and STIX import) --------------------

const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** A host name SIEMBox will hunt for: lower case, dotted, a letter TLD that isn't a file extension. */
export function isHuntableDomain(raw: string): boolean {
  const host = raw.toLowerCase();
  if (host.length > 253 || !host.includes('.')) return false;
  const labels = host.split('.');
  if (labels.some((l) => !DOMAIN_LABEL.test(l))) return false;
  const tld = labels[labels.length - 1];
  if (!/^[a-z][a-z0-9-]{1,23}$/.test(tld)) return false;
  if (!IANA_TLDS.has(tld) || FILE_EXTENSIONS.has(tld)) return false;
  return true;
}

function isReferenceDomain(host: string, extra: string[]): boolean {
  return [...REFERENCE_DOMAINS, ...extra].some((d) => host === d || host.endsWith(`.${d}`));
}

/** Normalize one indicator of a given type, or null when it isn't a valid one. */
export function normalizeIoc(type: IocType, raw: string): string | null {
  const v = refang(String(raw ?? '').trim());
  if (!v || v.length > 2048) return null;
  switch (type) {
    case 'ipv4':
      return isIP(v) === 4 && isPublicAddress(v) ? v : null;
    case 'ipv6': {
      const lower = v.toLowerCase();
      return isIP(lower) === 6 && isPublicAddress(lower) ? lower : null;
    }
    case 'domain': {
      const host = v.toLowerCase().replace(/\.$/, '');
      return isHuntableDomain(host) ? host : null;
    }
    case 'url': {
      try {
        const u = new URL(v);
        if (!['http:', 'https:', 'ftp:'].includes(u.protocol)) return null;
        return v;
      } catch {
        return null;
      }
    }
    case 'email': {
      const m = /^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{1,253})$/.exec(v);
      return m && isHuntableDomain(m[1]) ? v.toLowerCase() : null;
    }
    case 'md5':
      return /^[a-f0-9]{32}$/i.test(v) && !/^(.)\1+$/.test(v) ? v.toLowerCase() : null;
    case 'sha1':
      return /^[a-f0-9]{40}$/i.test(v) && !/^(.)\1+$/.test(v) ? v.toLowerCase() : null;
    case 'sha256':
      return /^[a-f0-9]{64}$/i.test(v) && !/^(.)\1+$/.test(v) ? v.toLowerCase() : null;
    case 'cve':
      return /^CVE-\d{4}-\d{4,7}$/i.test(v) ? v.toUpperCase() : null;
    default:
      return null;
  }
}

// ---- Extraction --------------------------------------------------------------

/** The sentence-ish window around index `at`, on one line. */
function contextAt(text: string, at: number, length: number): string {
  const start = Math.max(0, at - MAX_CONTEXT / 2);
  const end = Math.min(text.length, at + length + MAX_CONTEXT / 2);
  let s = text.slice(start, end).replace(/\s+/g, ' ').trim();
  if (start > 0) s = `…${s}`;
  if (end < text.length) s = `${s}…`;
  return s;
}

/** Trailing punctuation a URL picks up from prose ("see http://x.com/a)."). */
function trimUrl(url: string): string {
  let end = url.length;
  while (end > 0 && '.,;:!?\'")]}>'.includes(url[end - 1])) end--;
  return url.slice(0, end);
}

const PATTERNS: Array<{ type: IocType; re: RegExp }> = [
  { type: 'url', re: /\b(?:https?|ftp):\/\/[^\s<>"'`]{1,2048}/gi },
  { type: 'email', re: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}\b/g },
  { type: 'sha256', re: /\b[a-fA-F0-9]{64}\b/g },
  { type: 'sha1', re: /\b[a-fA-F0-9]{40}\b/g },
  { type: 'md5', re: /\b[a-fA-F0-9]{32}\b/g },
  { type: 'cve', re: /\bCVE-\d{4}-\d{4,7}\b/gi },
  { type: 'ipv4', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
  { type: 'ipv6', re: /(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])/g },
  {
    type: 'domain',
    re: /\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,10}[A-Za-z][A-Za-z0-9-]{1,23}\b/g,
  },
];

export interface ExtractOptions {
  /** Domains to treat as references (the article's own site, say). */
  referenceDomains?: string[];
  /** Decides which T-numbers are real ATT&CK techniques. Default: accept any well-formed ID. */
  isTechnique?: (id: string) => boolean;
}

/** The registrable-ish part of a host: its last two labels (good enough to skip the article's own site). */
export function siteDomain(host: string): string {
  const labels = host.toLowerCase().split('.').filter(Boolean);
  return labels.slice(-2).join('.');
}

export function extractIocs(input: string, opts: ExtractOptions = {}): ExtractionResult {
  const text = refang(input.slice(0, MAX_TEXT_CHARS));
  const extraRefs = (opts.referenceDomains ?? []).map((d) => d.toLowerCase());
  const seen = new Set<string>();
  const indicators: ExtractedIoc[] = [];

  const add = (type: IocType, value: string, at: number, length: number) => {
    const key = `${type}:${value}`;
    if (seen.has(key) || indicators.length >= MAX_INDICATORS) return;
    seen.add(key);
    indicators.push({ type, value, context: contextAt(text, at, length) });
  };

  for (const { type, re } of PATTERNS) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const at = m.index ?? 0;
      let candidate = m[0];
      if (type === 'url') candidate = trimUrl(candidate);
      if (type === 'ipv4') {
        // A version string (1.2.3.4.5) or the tail of a longer dotted run is not an address.
        const before = text[at - 1];
        const after = text.slice(at + candidate.length, at + candidate.length + 2);
        if (before === '.' || /^\.\d/.test(after)) continue;
      }
      if (type === 'domain') {
        // The local part of an email address (first.last@...) is no host;
        // the part after the @ is, and is kept.
        if (text[at + candidate.length] === '@') continue;
        const host = candidate.toLowerCase();
        if (isReferenceDomain(host, extraRefs)) continue;
      }
      const value = normalizeIoc(type, candidate);
      if (!value) continue;
      if (type === 'url') {
        try {
          const host = new URL(value).hostname.toLowerCase();
          if (extraRefs.some((d) => host === d || host.endsWith(`.${d}`))) continue;
        } catch {
          continue;
        }
      }
      add(type, value, at, candidate.length);
    }
  }

  const isTechnique = opts.isTechnique ?? (() => true);
  const techniques = [...new Set([...text.matchAll(/\bT\d{4}(?:\.\d{3})?\b/g)].map((m) => m[0]))].filter(isTechnique);

  return { indicators, techniques };
}

// ---- Matching log lines --------------------------------------------------------

const isDigit = (c: string | undefined) => c !== undefined && c >= '0' && c <= '9';
const isHex = (c: string | undefined) => c !== undefined && /[0-9a-f]/.test(c);
const isHostChar = (c: string | undefined) => c !== undefined && /[a-z0-9_-]/.test(c);

/**
 * Whether `needle` occurs in `haystack` as the indicator itself, not inside a
 * longer token: 1.2.3.4 is not found in 11.2.3.45, evil.com is not found in
 * notevil.com (but is in sub.evil.com), a hash is not found inside a longer
 * hex string. URLs and keywords match as plain substrings. Both arguments
 * must already be lower case. No regex: the needle comes from a report.
 */
export function occursIn(haystack: string, needle: string, kind: IocType | 'keyword'): boolean {
  if (!needle) return false;
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(needle, from);
    if (at < 0) return false;
    const before = haystack[at - 1];
    const after = haystack[at + needle.length];
    const after2 = haystack[at + needle.length + 1];
    let ok: boolean;
    switch (kind) {
      case 'ipv4':
        ok = !isDigit(before) && before !== '.' && !isDigit(after) && !(after === '.' && isDigit(after2));
        break;
      case 'ipv6':
        ok = !isHex(before) && before !== ':' && !isHex(after) && after !== ':';
        break;
      case 'domain':
      case 'email':
        ok = !isHostChar(before) && !isHostChar(after) && !(after === '.' && isHostChar(after2));
        break;
      case 'md5':
      case 'sha1':
      case 'sha256':
        ok = !isHex(before) && !isHex(after);
        break;
      case 'cve':
        ok = !isDigit(after);
        break;
      default:
        ok = true;
    }
    if (ok) return true;
    from = at + 1;
  }
}
