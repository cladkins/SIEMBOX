import { test } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import * as net from 'net';
import * as http from 'http';
import * as tls from 'tls';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { selectPortsToScan, selectHttpProbes, flattenHeaders, tcpConnectScan, httpProbe, bannerGrab, probeLiveness, sweepCidr, tlsProbe } from './activeDiscovery';
import { loadFingerprintLibrary } from './fingerprintLoader';
import { matchHost } from './matcher';
import { FingerprintEntry } from './types';

function fp(overrides: Partial<FingerprintEntry> = {}): FingerprintEntry {
  return {
    id: 'x',
    name: 'X',
    category: 'test',
    security_value: 5,
    signals: { ports: [], http: [], mdns: [], ssdp: [], tls: [], mac_oui: [] },
    confidence_floor: 50,
    attack_data_sources: [],
    log_access: [{ method: 'file' }],
    onboard_template: 't',
    credentials: { required: false, optional: [] },
    ...overrides,
  };
}

test('selectPortsToScan unions and dedupes ports across the whole library', () => {
  const library = [
    fp({ signals: { ports: [{ port: 443, weight: 1 }, { port: 22, weight: 1 }], http: [], mdns: [], ssdp: [], tls: [], mac_oui: [] } }),
    fp({ signals: { ports: [{ port: 443, weight: 1 }, { port: 80, weight: 1 }], http: [], mdns: [], ssdp: [], tls: [], mac_oui: [] } }),
  ];
  assert.deepEqual(selectPortsToScan(library), [22, 80, 443]);
});

test('selectHttpProbes unions and dedupes declared paths', () => {
  const library = [
    fp({ signals: { ports: [], http: [{ path: '/admin/', weight: 1 }], mdns: [], ssdp: [], tls: [], mac_oui: [] } }),
    fp({ signals: { ports: [], http: [{ path: '/admin/', weight: 1 }, { path: '/', weight: 1 }], mdns: [], ssdp: [], tls: [], mac_oui: [] } }),
  ];
  assert.deepEqual(selectHttpProbes(library).sort(), ['/', '/admin/']);
});

test('flattenHeaders joins multi-value headers and drops undefined ones', () => {
  const flat = flattenHeaders({ 'set-cookie': ['a=1', 'b=2'], 'content-type': 'text/html', 'x-missing': undefined });
  assert.deepEqual(flat, { 'set-cookie': 'a=1, b=2', 'content-type': 'text/html' });
});

test('tcpConnectScan finds the one open port among several closed ones (loopback)', async () => {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const openPort = (server.address() as net.AddressInfo).port;

  try {
    const open = await tcpConnectScan('127.0.0.1', [openPort, 1, 2], { portTimeoutMs: 500 });
    assert.deepEqual(open, [openPort]);
  } finally {
    server.close();
  }
});

test('httpProbe fetches a declared path and captures body + status', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<title>Pi-hole</title>');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as net.AddressInfo).port;

  try {
    const result = await httpProbe('127.0.0.1', port, '/admin/', { forceTls: false, httpTimeoutMs: 1000 });
    assert.equal(result?.status, 200);
    assert.match(result!.body, /Pi-hole/);
    assert.equal(result?.path, '/admin/');
  } finally {
    server.close();
  }
});

test('httpProbe returns null against a closed port', async () => {
  const result = await httpProbe('127.0.0.1', 1, '/', { forceTls: false, httpTimeoutMs: 400 });
  assert.equal(result, null);
});

test('bannerGrab captures unprompted data sent right after connect', async () => {
  const server = net.createServer((socket) => {
    socket.write('SSH-2.0-OpenSSH_8.9\r\n');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as net.AddressInfo).port;

  try {
    const result = await bannerGrab('127.0.0.1', port, { bannerTimeoutMs: 1000 });
    assert.match(result!.banner, /SSH-2\.0-OpenSSH/);
  } finally {
    server.close();
  }
});

test('probeLiveness resolves true when a port is actually open', async () => {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const openPort = (server.address() as net.AddressInfo).port;

  try {
    const alive = await probeLiveness('127.0.0.1', [openPort], 500);
    assert.equal(alive, true);
  } finally {
    server.close();
  }
});

test('probeLiveness resolves true on a refused connection -- a live host that just isn\'t listening there', async () => {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const closedPort = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve())); // now nothing is listening on this port

  const alive = await probeLiveness('127.0.0.1', [closedPort], 500);
  assert.equal(alive, true);
});

// A genuine "every port timed out with no response at all" case needs a host that silently
// drops packets, which isn't portably reproducible without OS-level firewall rules -- not
// something to depend on across arbitrary test/CI environments. The all-fail path (every
// attempt hits fail(), remaining reaches 0, resolve(false)) is simple enough to trust by
// inspection; the empty-list short-circuit below is the one false-path case worth asserting.
test('probeLiveness resolves false immediately given an empty port list', async () => {
  assert.equal(await probeLiveness('127.0.0.1', [], 500), false);
});

test('sweepCidr enumerates every host in the CIDR and probes each one', async () => {
  // 127.0.0.0/30 -> usable hosts .1 and .2. Loopback addresses always answer
  // (open or refused) even with nothing deliberately listening, so both come
  // back alive -- this test checks the enumerate-and-probe wiring, not the
  // alive/dead discrimination itself (covered by the probeLiveness tests above).
  const alive = await sweepCidr('127.0.0.0/30', { portTimeoutMs: 500 });
  assert.deepEqual(alive.sort(), ['127.0.0.1', '127.0.0.2']);
});

/**
 * A real self-signed certificate made by openssl, the way the reported Proxmox
 * cert was. Returns null (the caller skips) when openssl isn't installed.
 */
function makeCertificate(subject: string, san?: string): { key: Buffer; cert: Buffer } | null {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'siembox-tlsprobe-'));
  const keyPath = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');
  try {
    const args = ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes'];
    args.push('-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', subject);
    if (san) args.push('-addext', `subjectAltName=${san}`);
    execFileSync('openssl', args, { stdio: 'ignore' });
    return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
  } catch {
    return null;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Probe a loopback TLS server presenting the given certificate with the real tlsProbe. */
async function probeCertificate(t: TestContext, subject: string, san?: string) {
  const credentials = makeCertificate(subject, san);
  if (!credentials) {
    t.skip('openssl is not available to make a test certificate');
    return null;
  }
  const server = tls.createServer(credentials, (socket) => socket.end());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as net.AddressInfo).port;
  try {
    const result = await tlsProbe('127.0.0.1', port, { tlsTimeoutMs: 2000 });
    assert.ok(result, 'the probe read the certificate');
    return { port, result };
  } finally {
    server.close();
  }
}

test('tlsProbe reads every CN of a certificate whose subject repeats CN, and the shipped library matches it', async (t) => {
  const probed = await probeCertificate(t, '/CN=proxmox.local/CN=pve', 'DNS:proxmox.local,DNS:pve,IP:127.0.0.1');
  if (!probed) return;
  const { port, result } = probed;

  assert.deepEqual(result.subject_cn, ['proxmox.local', 'pve']);
  assert.deepEqual(result.san, ['DNS:proxmox.local', 'DNS:pve', 'IP Address:127.0.0.1']);

  // What used to throw "t.subject_cn?.toLowerCase is not a function" and fail the scan.
  const signals = {
    ip: '127.0.0.1',
    open_ports: [port],
    http_responses: [],
    tls_subjects: [result],
    banners: [],
    mdns_services: [],
    ssdp_services: [],
    discovery_methods: ['active_probe'],
  };
  const matches = matchHost(signals, loadFingerprintLibrary());
  const proxmox = matches.find((m) => m.fingerprint.id === 'proxmox-ve');
  assert.ok(proxmox, 'the proxmox fingerprint matched on the second CN');
  assert.ok(proxmox.matched_signals.includes('tls cn~"pve"'));
});

test('tlsProbe reports a single-CN certificate as a plain string, the shape existing evidence has', async (t) => {
  const probed = await probeCertificate(t, '/O=Homelab/CN=pve');
  if (!probed) return;
  assert.equal(probed.result.subject_cn, 'pve');
  assert.equal(probed.result.san, undefined);
});

test('tlsProbe returns null against a closed port', async () => {
  assert.equal(await tlsProbe('127.0.0.1', 1, { tlsTimeoutMs: 400 }), null);
});
