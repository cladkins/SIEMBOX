// Module 2, active phase: scoped probing of passive candidates. Targeted port
// scan limited to ports declared in the fingerprint library (no full 65k
// sweep), HTTP probe of declared paths, TLS cert probe, and a banner grab on
// whatever's left open. This never touches hosts outside the candidate list
// scope() and the passive phase produced.
import * as net from 'net';
import * as http from 'http';
import * as https from 'https';
import * as tls from 'tls';
import { DiscoveredSignals, BannerResult, FingerprintEntry, HttpProbeResult, TlsProbeResult } from './types';

const MAX_BODY_BYTES = 8192;
const MAX_BANNER_BYTES = 512;

export interface ActiveProbeOptions {
  portTimeoutMs?: number;
  httpTimeoutMs?: number;
  tlsTimeoutMs?: number;
  bannerTimeoutMs?: number;
  concurrency?: number;
}

/** The union of every port any fingerprint declares -- the whole scoped scan target list. */
export function selectPortsToScan(library: FingerprintEntry[]): number[] {
  const ports = new Set<number>();
  for (const fp of library) {
    for (const s of fp.signals.ports) ports.add(s.port);
  }
  return Array.from(ports).sort((a, b) => a - b);
}

/** The union of every HTTP path any fingerprint declares. */
export function selectHttpProbes(library: FingerprintEntry[]): string[] {
  const paths = new Set<string>();
  for (const fp of library) {
    for (const s of fp.signals.http) paths.add(s.path);
  }
  return Array.from(paths);
}

/** Flatten Node's IncomingHttpHeaders (string | string[] | undefined) down to string-only. */
export function flattenHeaders(headers: http.IncomingHttpHeaders): Record<string, string> {
  const flat: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    flat[key] = Array.isArray(value) ? value.join(', ') : value;
  }
  return flat;
}

async function mapWithConcurrency<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

function connectPort(ip: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (result: boolean) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, ip);
  });
}

/** TCP connect scan against a fixed, small port list -- never a full sweep. */
export async function tcpConnectScan(ip: string, ports: number[], opts: ActiveProbeOptions = {}): Promise<number[]> {
  const timeoutMs = opts.portTimeoutMs ?? 800;
  const concurrency = opts.concurrency ?? 8;
  const results = await mapWithConcurrency(ports, concurrency, async (port) => ((await connectPort(ip, port, timeoutMs)) ? port : null));
  return results.filter((p): p is number => p !== null).sort((a, b) => a - b);
}

/**
 * Cert validation is deliberately off here, and ONLY here (this literal, not a
 * shared agent/global) -- homelab admin UIs (pfSense, OPNsense, UniFi, Proxmox,
 * ...) almost universally serve self-signed certs, so requiring a valid chain
 * would break fingerprinting against the exact devices this targets. Scoped to
 * read-only GETs against hosts already inside the user-approved scan scope
 * (scope.ts); no credentials cross this connection.
 */
function requestOnce(ip: string, port: number, path: string, useTls: boolean, timeoutMs: number): Promise<HttpProbeResult | null> {
  return new Promise((resolve) => {
    const mod = useTls ? https : http;
    const req = mod.request(
      { host: ip, port, path, method: 'GET', timeout: timeoutMs, rejectUnauthorized: false }, // codeql[js/disabling-certificate-validation] intentional: see function doc comment above
      (res) => {
        let body = '';
        res.on('data', (chunk) => {
          if (body.length < MAX_BODY_BYTES) body += chunk.toString('utf8');
        });
        res.on('end', () => {
          resolve({ port, path, status: res.statusCode ?? null, body: body.slice(0, MAX_BODY_BYTES), headers: flattenHeaders(res.headers) });
        });
      }
    );
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
    req.end();
  });
}

/** Fetch a declared path on an open port. Tries plain HTTP then HTTPS unless a protocol is forced. */
export async function httpProbe(
  ip: string,
  port: number,
  path: string,
  opts: ActiveProbeOptions & { forceTls?: boolean } = {}
): Promise<HttpProbeResult | null> {
  const timeoutMs = opts.httpTimeoutMs ?? 1500;
  if (opts.forceTls === true) return requestOnce(ip, port, path, true, timeoutMs);
  if (opts.forceTls === false) return requestOnce(ip, port, path, false, timeoutMs);
  return (await requestOnce(ip, port, path, false, timeoutMs)) ?? (await requestOnce(ip, port, path, true, timeoutMs));
}

/**
 * Grab the TLS cert's subject CN + SAN. Verification is deliberately off here,
 * and ONLY here (this literal, not a shared agent/global) -- we need the raw
 * cert to fingerprint the device even when it's self-signed (the norm for
 * homelab admin UIs); `rejectUnauthorized: true` would abort the handshake
 * before a cert is ever available to read. Scoped to hosts already inside the
 * user-approved scan scope (scope.ts); the socket is only ever read, never
 * written to.
 */
export function tlsProbe(ip: string, port: number, opts: ActiveProbeOptions = {}): Promise<TlsProbeResult | null> {
  const timeoutMs = opts.tlsTimeoutMs ?? 1500;
  return new Promise((resolve) => {
    let done = false;
    const finish = (result: TlsProbeResult | null) => {
      if (done) return;
      done = true;
      resolve(result);
    };
    const socket = tls.connect(
      { host: ip, port, rejectUnauthorized: false, timeout: timeoutMs }, // codeql[js/disabling-certificate-validation] intentional: see function doc comment above
      () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();
        if (!cert || !cert.subject) return finish(null);
        const san = cert.subjectaltname ? cert.subjectaltname.split(',').map((s) => s.trim()) : undefined;
        finish({ port, subject_cn: cert.subject.CN, san });
      }
    );
    socket.once('timeout', () => {
      socket.destroy();
      finish(null);
    });
    socket.once('error', () => finish(null));
  });
}

/** Read whatever the service sends unprompted right after connect (SSH, SMTP, etc. all banner first). */
export function bannerGrab(ip: string, port: number, opts: ActiveProbeOptions = {}): Promise<BannerResult | null> {
  const timeoutMs = opts.bannerTimeoutMs ?? 1000;
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let data = '';
    let resolved = false;
    const finish = (result: BannerResult | null) => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      finish({ port, banner: data.slice(0, MAX_BANNER_BYTES) });
    });
    socket.on('timeout', () => finish(data ? { port, banner: data.slice(0, MAX_BANNER_BYTES) } : null));
    socket.on('error', () => finish(null));
    socket.connect(port, ip);
  });
}

/**
 * Full active phase for one candidate host: scoped port scan, then TLS probe +
 * HTTP probe of every declared path on each open port, falling back to a
 * banner grab on ports that answered neither.
 */
export async function probeHost(ip: string, library: FingerprintEntry[], opts: ActiveProbeOptions = {}): Promise<DiscoveredSignals> {
  const ports = selectPortsToScan(library);
  const openPorts = await tcpConnectScan(ip, ports, opts);
  const httpPaths = selectHttpProbes(library);

  const http_responses: HttpProbeResult[] = [];
  const tls_subjects: TlsProbeResult[] = [];
  const banners: BannerResult[] = [];

  for (const port of openPorts) {
    const tlsResult = await tlsProbe(ip, port, opts);
    if (tlsResult) tls_subjects.push(tlsResult);

    let gotHttp = false;
    for (const path of httpPaths) {
      const result = await httpProbe(ip, port, path, { ...opts, forceTls: tlsResult ? true : undefined });
      if (result) {
        http_responses.push(result);
        gotHttp = true;
      }
    }

    if (!gotHttp) {
      const banner = await bannerGrab(ip, port, opts);
      if (banner) banners.push(banner);
    }
  }

  return {
    ip,
    open_ports: openPorts,
    http_responses,
    tls_subjects,
    banners,
    mdns_services: [],
    ssdp_services: [],
    discovery_methods: ['active_probe'],
  };
}
