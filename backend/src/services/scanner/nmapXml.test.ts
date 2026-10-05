/**
 * Tests for the nmap-XML parser used on the shipper-dispatched scan path.
 * Fixtures are hand-built from real `nmap -oX` output shapes; the parser's
 * equivalence to node-nmap on live XML is also checked in CI-independent
 * manual runs, but these keep the mapping pinned deterministically.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseNmapXml } from './nmapXml';

const wrap = (hostsXml: string) =>
  `<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap">${hostsXml}</nmaprun>`;

test('no hosts (nothing found) -> empty array', async () => {
  assert.deepEqual(await parseNmapXml(wrap('')), []);
  assert.deepEqual(await parseNmapXml('<?xml version="1.0"?><nmaprun></nmaprun>'), []);
});

test('a host with an open port, hostname and ipv4', async () => {
  const xml = wrap(`
    <host><status state="up"/>
      <address addr="192.168.1.50" addrtype="ipv4"/>
      <hostnames><hostname name="nas01" type="PTR"/></hostnames>
      <ports>
        <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="probed"/></port>
      </ports>
    </host>`);
  const hosts = await parseNmapXml(xml);
  assert.equal(hosts.length, 1);
  assert.deepEqual(hosts[0], {
    hostname: 'nas01',
    ip: '192.168.1.50',
    mac: null,
    openPorts: [{ port: 22, protocol: 'tcp', service: 'ssh', method: 'probed' }],
    osNmap: null,
  });
});

test('closed/filtered ports are excluded; only open ones are kept', async () => {
  const xml = wrap(`
    <host>
      <address addr="10.0.0.5" addrtype="ipv4"/>
      <ports>
        <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
        <port protocol="tcp" portid="443"><state state="closed"/><service name="https"/></port>
        <port protocol="tcp" portid="21"><state state="filtered"/><service name="ftp"/></port>
      </ports>
    </host>`);
  const hosts = await parseNmapXml(xml);
  assert.deepEqual(hosts[0].openPorts, [{ port: 80, protocol: 'tcp', service: 'http' }]);
});

test('a TLS service exposes tunnel + product (product mirrors node-nmap: taken from tunnel)', async () => {
  const xml = wrap(`
    <host>
      <address addr="10.0.0.6" addrtype="ipv4"/>
      <ports>
        <port protocol="tcp" portid="8443"><state state="open"/>
          <service name="https" tunnel="ssl" method="probed"/>
        </port>
      </ports>
    </host>`);
  const [host] = await parseNmapXml(xml);
  assert.deepEqual(host.openPorts, [
    { port: 8443, protocol: 'tcp', service: 'https', tunnel: 'ssl', method: 'probed', product: 'ssl' },
  ]);
});

test('mac address + vendor and an OS match are extracted', async () => {
  const xml = wrap(`
    <host>
      <address addr="192.168.1.1" addrtype="ipv4"/>
      <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Ubiquiti"/>
      <os><osmatch name="Linux 5.X" accuracy="95"/></os>
      <ports></ports>
    </host>`);
  const [host] = await parseNmapXml(xml);
  assert.equal(host.ip, '192.168.1.1');
  assert.equal(host.mac, 'AA:BB:CC:DD:EE:FF');
  assert.equal(host.vendor, 'Ubiquiti');
  assert.equal(host.osNmap, 'Linux 5.X');
});

test('whitespace-only <hostnames/> (xml2js artifact) does not become a hostname', async () => {
  // xml2js can represent an empty <hostnames/> as the string "\n"; node-nmap
  // guards against exactly this, and so must we.
  const xml = `<?xml version="1.0"?><nmaprun><host><hostnames>\n</hostnames><address addr="10.0.0.9" addrtype="ipv4"/></host></nmaprun>`;
  const [host] = await parseNmapXml(xml);
  assert.equal(host.hostname, null);
  assert.equal(host.ip, '10.0.0.9');
});

test('multiple hosts are all returned', async () => {
  const xml = wrap(`
    <host><address addr="10.0.0.1" addrtype="ipv4"/><ports></ports></host>
    <host><address addr="10.0.0.2" addrtype="ipv4"/><ports></ports></host>
    <host><address addr="10.0.0.3" addrtype="ipv4"/><ports></ports></host>`);
  const hosts = await parseNmapXml(xml);
  assert.deepEqual(hosts.map((h) => h.ip), ['10.0.0.1', '10.0.0.2', '10.0.0.3']);
});

test('a host with no <ports> element has null openPorts (matches node-nmap)', async () => {
  const xml = wrap(`<host><address addr="10.0.0.4" addrtype="ipv4"/></host>`);
  const [host] = await parseNmapXml(xml);
  assert.equal(host.openPorts, null);
});

test('malformed XML rejects rather than returning garbage', async () => {
  await assert.rejects(parseNmapXml('<nmaprun><host>'), /./);
});
