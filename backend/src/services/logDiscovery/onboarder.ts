// Module 5: onboarder, manual mode. The only module that writes -- and even
// then, manual mode writes nothing: it fills the fingerprint's onboard_template
// with source detail and hands back copy-paste text for the user to apply
// themselves. Push mode (write config to a collector + restart it) is a later
// build-order step; never onboard without the user confirming first (see route).
import * as fs from 'fs';
import * as path from 'path';
import { FingerprintEntry, LogAccessMethod, RuntimeSource } from './types';

const SERVICE_DIR = __dirname;

const WEB_PORT_PRIORITY = [443, 8443, 9443, 80, 8080, 9000, 81];

/**
 * Minimal `{{ var }}` substitution. Every template here is authored in-repo
 * (not user-supplied), so a full templating engine would be pure overhead --
 * this covers exactly what the three onboard templates need.
 */
export function renderTemplate(templateSource: string, vars: Record<string, string | number | undefined>): string {
  return templateSource.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_match, key) => {
    const value = vars[key];
    return value === undefined || value === null ? '' : String(value);
  });
}

/** onboard_template in a fingerprint is a path like "templates/file_tail.j2", relative to this service directory. */
export function loadTemplate(onboardTemplatePath: string): string {
  const resolved = path.join(SERVICE_DIR, onboardTemplatePath);
  if (!resolved.startsWith(SERVICE_DIR)) {
    throw new Error(`refusing to load onboard_template outside the service directory: ${onboardTemplatePath}`);
  }
  return fs.readFileSync(resolved, 'utf8');
}

export interface SiemboxSyslogSettings {
  host: string;
  port: number;
}

export function buildTemplateVars(
  fingerprint: FingerprintEntry,
  source: RuntimeSource,
  logAccess: LogAccessMethod,
  siembox: SiemboxSyslogSettings
): Record<string, string | number | undefined> {
  const webPort = WEB_PORT_PRIORITY.find((p) => source.open_ports.includes(p)) ?? source.open_ports[0];
  // Highest-weight declared signal port for this fingerprint, if any. This is
  // the authoritative port the service is known to run on, independent of what
  // a given scan happened to observe.
  const signalPort = fingerprint.signals.ports
    .slice()
    .sort((a, b) => b.weight - a.weight)[0]?.port;
  // Resolve a port with a robust fallback chain. A source matched via mDNS with
  // no port scan has empty open_ports, which used to leave `port` undefined and
  // render a broken URL like "https://ip:/path". Prefer the access method's own
  // authoritative port, then the fingerprint's primary signal port, then the
  // scan's best-guess web port, and finally a visible placeholder so the recipe
  // is never silently blank.
  const port = logAccess.target_port ?? signalPort ?? webPort ?? 'PORT';
  return {
    id: fingerprint.id,
    name: fingerprint.name,
    ip: source.ip,
    // Fall back to a visible placeholder when the admin hasn't set the syslog
    // host under Settings -> Syslog, so `logger -n <host>` is an obviously
    // fill-in-able command rather than a silently broken `logger -n  -P 514`.
    siembox_host: siembox.host || 'SIEMBOX_HOST',
    siembox_port: siembox.port,
    log_path: logAccess.path,
    api_endpoint: logAccess.endpoint,
    port,
  };
}

/**
 * Fill the fingerprint's onboard_template with this source's detail. Pure
 * given its inputs -- no I/O beyond reading the (bundled, trusted) template
 * file -- so onboarding never has a side effect of its own.
 */
export function renderOnboardInstructions(
  fingerprint: FingerprintEntry,
  source: RuntimeSource,
  logAccess: LogAccessMethod,
  siembox: SiemboxSyslogSettings
): string {
  const template = loadTemplate(fingerprint.onboard_template);
  const vars = buildTemplateVars(fingerprint, source, logAccess, siembox);
  return renderTemplate(template, vars);
}
