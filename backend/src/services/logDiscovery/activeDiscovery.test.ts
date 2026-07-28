import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as net from 'net';
import * as http from 'http';
import { selectPortsToScan, selectHttpProbes, flattenHeaders, tcpConnectScan, httpProbe, bannerGrab } from './activeDiscovery';
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
