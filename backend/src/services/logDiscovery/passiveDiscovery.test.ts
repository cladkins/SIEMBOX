import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseProcNetArp,
  parseArpCommandOutput,
  parseDnsmasqLeases,
  parseIscDhcpdLeases,
  buildMdnsQuery,
  isDnsResponse,
  buildSsdpSearchRequest,
  parseSsdpResponse,
} from './passiveDiscovery';

test('parseProcNetArp skips the header row and incomplete (flags 0x0) entries', () => {
  const content = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
`;
  const entries = parseProcNetArp(content);
  assert.deepEqual(entries, [{ ip: '192.168.1.1', mac: 'aa:bb:cc:dd:ee:ff' }]);
});

test('parseArpCommandOutput handles the Linux "(ip) at mac" format', () => {
  const content = 'router.lan (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0\n';
  assert.deepEqual(parseArpCommandOutput(content), [{ ip: '192.168.1.1', mac: 'aa:bb:cc:dd:ee:ff' }]);
});

test('parseArpCommandOutput handles the macOS "(ip) at mac on ifscope" format', () => {
  const content = '? (192.168.1.50) at 11:22:33:44:55:66 on en0 ifscope [ethernet]\n';
  assert.deepEqual(parseArpCommandOutput(content), [{ ip: '192.168.1.50', mac: '11:22:33:44:55:66' }]);
});

test('parseArpCommandOutput handles multiple entries', () => {
  const content = `? (192.168.1.1) at aa:aa:aa:aa:aa:aa on en0 ifscope [ethernet]
? (192.168.1.2) at bb:bb:bb:bb:bb:bb on en0 ifscope [ethernet]
`;
  assert.equal(parseArpCommandOutput(content).length, 2);
});

test('parseDnsmasqLeases parses "epoch mac ip hostname clientid" lines', () => {
  const content = `1700000000 aa:bb:cc:dd:ee:ff 192.168.1.50 pihole *
1700000001 11:22:33:44:55:66 192.168.1.51 * *
`;
  const leases = parseDnsmasqLeases(content);
  assert.equal(leases.length, 2);
  assert.deepEqual(leases[0], { ip: '192.168.1.50', mac: 'aa:bb:cc:dd:ee:ff', hostname: 'pihole' });
  assert.equal(leases[1].hostname, undefined); // "*" means no hostname
});

test('parseIscDhcpdLeases parses lease blocks and keeps the last block per ip', () => {
  const content = `
lease 192.168.1.60 {
  starts 4 2024/01/01 00:00:00;
  hardware ethernet aa:bb:cc:00:00:01;
  client-hostname "old-name";
}
lease 192.168.1.60 {
  starts 4 2024/01/02 00:00:00;
  hardware ethernet aa:bb:cc:00:00:01;
  client-hostname "new-name";
}
`;
  const leases = parseIscDhcpdLeases(content);
  assert.equal(leases.length, 1);
  assert.equal(leases[0].hostname, 'new-name');
});

test('buildMdnsQuery produces a well-formed single-question DNS message', () => {
  const query = buildMdnsQuery('_home-assistant._tcp.local');
  // header: id(2) flags(2) qdcount(2)=1 ancount(2) nscount(2) arcount(2)
  assert.equal(query.readUInt16BE(4), 1);
  assert.equal(isDnsResponse(query), false); // QR bit unset on a query
});

test('isDnsResponse reads the QR bit from a synthetic response header', () => {
  const response = Buffer.alloc(12);
  response.writeUInt16BE(0x8400, 2); // QR=1, standard response, no error
  assert.equal(isDnsResponse(response), true);
});

test('isDnsResponse is false for a too-short buffer', () => {
  assert.equal(isDnsResponse(Buffer.alloc(2)), false);
});

test('buildSsdpSearchRequest embeds the search target and MX', () => {
  const req = buildSsdpSearchRequest('urn:schemas-upnp-org:device:Basic:1', 3);
  assert.match(req, /ST: urn:schemas-upnp-org:device:Basic:1/);
  assert.match(req, /MX: 3/);
  assert.match(req, /^M-SEARCH \* HTTP\/1\.1/);
});

test('parseSsdpResponse parses HTTP-style headers over UDP, case-insensitively keyed', () => {
  const raw = [
    'HTTP/1.1 200 OK',
    'CACHE-CONTROL: max-age=100',
    'ST: upnp:rootdevice',
    'SERVER: UniFi/1.0 UPnP/1.0',
    '',
    '',
  ].join('\r\n');
  const headers = parseSsdpResponse(raw);
  assert.equal(headers.st, 'upnp:rootdevice');
  assert.equal(headers.server, 'UniFi/1.0 UPnP/1.0');
});
