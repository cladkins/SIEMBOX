/**
 * Domain-name helpers shared by the domain-monitor collectors.
 *
 * registrableDomain() finds the name a registrant actually buys
 * ("example.co.uk" for "mail.example.co.uk") without shipping the whole Public
 * Suffix List: the last label is the public suffix, unless the last two labels
 * form one of the common second-level registries below. That is all RDAP (which
 * must be asked about the registered name) and the lookalike engine (which
 * permutes the label in front of the suffix) need; an unlisted multi-label
 * suffix only means those two collectors work on one label too many.
 */

// Common second-level registries, grouped by region (whitespace-separated).
const MULTI_LABEL_SUFFIXES = new Set(
  `
  ac.uk co.uk gov.uk ltd.uk me.uk net.uk org.uk plc.uk sch.uk
  asn.au com.au edu.au gov.au id.au net.au org.au
  ac.nz co.nz geek.nz govt.nz net.nz org.nz school.nz
  ac.jp co.jp ed.jp go.jp gr.jp ne.jp or.jp
  ac.kr co.kr go.kr ne.kr or.kr re.kr
  com.cn edu.cn gov.cn net.cn org.cn com.hk org.hk com.tw org.tw
  com.sg org.sg com.my com.ph com.vn com.pk co.id or.id ac.id co.th in.th
  ac.in co.in firm.in gen.in gov.in ind.in net.in org.in co.il org.il com.tr
  com.br edu.br gov.br net.br org.br com.mx org.mx com.ar com.co com.pe com.ve com.ec
  com.es com.pl com.ua ac.za co.za gov.za net.za org.za com.ng com.eg co.ke
  `
    .trim()
    .split(/\s+/)
);

const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_HOSTNAME_LENGTH = 253;

export interface SplitDomain {
  /** The label a registrant chose ("example"). */
  label: string;
  /** The public suffix it was registered under ("com", "co.uk"). */
  suffix: string;
  /** label + "." + suffix. */
  registrable: string;
}

/** Split an already-validated, lowercase domain into label and public suffix. */
export function splitRegistrable(domain: string): SplitDomain {
  const labels = domain.split('.');
  const lastTwo = labels.slice(-2).join('.');
  if (labels.length >= 3 && MULTI_LABEL_SUFFIXES.has(lastTwo)) {
    const label = labels[labels.length - 3];
    return { label, suffix: lastTwo, registrable: `${label}.${lastTwo}` };
  }
  const label = labels[labels.length - 2] ?? labels[0];
  const suffix = labels[labels.length - 1];
  return { label, suffix, registrable: `${label}.${suffix}` };
}

export function registrableDomain(domain: string): string {
  return splitRegistrable(domain).registrable;
}

/**
 * A label a registry would accept: LDH, 1-63 characters, no hyphen at either
 * end, and no "--" in positions 3-4 unless it is an IDNA "xn--" label.
 */
export function isValidLabel(label: string): boolean {
  if (!LABEL_RE.test(label)) return false;
  return label.slice(2, 4) !== '--' || label.startsWith('xn--');
}

export function isValidHostname(name: string): boolean {
  if (name.length === 0 || name.length > MAX_HOSTNAME_LENGTH) return false;
  const labels = name.split('.');
  return (
    labels.length >= 2 && labels.every(isValidLabel) && !/^\d+$/.test(labels[labels.length - 1])
  );
}

/**
 * True when `name` is `domain` itself, one of its subdomains, or a wildcard
 * ("*.example.com") under it. Inputs are compared case-insensitively.
 */
export function isWithinDomain(name: string, domain: string): boolean {
  const n = name.toLowerCase().replace(/\.$/, '');
  const d = domain.toLowerCase();
  const bare = n.startsWith('*.') ? n.slice(2) : n;
  return bare === d || bare.endsWith(`.${d}`);
}

/** Lowercase, drop a trailing root dot. */
export function normalizeName(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, '');
}
