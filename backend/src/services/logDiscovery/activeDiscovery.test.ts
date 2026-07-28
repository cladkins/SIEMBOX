import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as net from 'net';
import * as http from 'http';
import { selectPortsToScan, selectHttpProbes, flattenHeaders, tcpConnectScan, httpProbe, bannerGrab, probeLiveness, sweepCidr } from './activeDiscovery';
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
