/**
 * Parser SELECTION-ORDER tests.
 *
 * parserDiscrimination.test.ts checks that a parser doesn't match the wrong log.
 * This file checks the other half of parser selection: when several parsers all
 * legitimately match, priority decides which one wins. The engine loads parsers
 * `ORDER BY priority ASC, id ASC` and breaks on the first match, so a generic
 * parser with a low priority number silently shadows every specific one.
 *
 * That is exactly what happened with CEF: the generic cef-syslog (4) and
 * cef-standard (5) sat ahead of everything, so a UniFi IDS/IPS event was parsed
 * as a bare `cef_event` and none of the UniFi canonical fields (signature_name,
 * rule_name, event_outcome, sensor_ip, network_direction) were ever derived —
 * the vendor-specific parsers at priority 200 were unreachable.
 *
 * These load the REAL catalog definitions, so a future priority edit that
 * reintroduces the inversion fails the build. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import { runParser, ParserDef } from './runParser';

const CATALOG = path.join(__dirname, '../../../../catalog/parsers');

function loadAll(): ParserDef[] {
  return fs
    .readdirSync(CATALOG)
    .filter((f) => f.endsWith('.parser.json'))
    .map((f) => JSON.parse(fs.readFileSync(path.join(CATALOG, f), 'utf8')) as ParserDef);
}

/**
 * Reproduce ParserEngine.processLog's selection: ascending priority, first match
 * wins. The id tiebreak the DB applies is approximated by name so the result is
 * deterministic here.
 */
function selectParser(message: string): { parser: ParserDef; result: NonNullable<ReturnType<typeof runParser>> } | null {
  const ordered = loadAll().sort(
    (a, b) => (a.priority ?? 100) - (b.priority ?? 100) || a.name.localeCompare(b.name)
  );
  for (const parser of ordered) {
    const result = runParser(parser, message, { packetSourceIp: '192.168.1.1' });
    if (result) return { parser, result };
  }
  return null;
}

// Real UCG-Max IDS/IPS event, as stored after the syslog header is stripped.
const UNIFI_IPS =
  'CEF:0|Ubiquiti|UniFi Network|10.4.57|201|Threat Detected and Blocked|7|UNIFIcategory=Security ' +
  'UNIFIhost=UCG Max proto=TCP spt=22536 dpt=80 act=blocked app=HTTP UNIFIrisk=medium ' +
  'UNIFIpolicyName=CINS Army Reputation List UNIFIpolicyType=IDS/IPS UNIFIdirection=incoming ' +
  'UNIFIdeviceIp=192.168.1.1 src=167.94.146.48 dst=192.168.1.194 ' +
  'UNIFIipsSignature=ET CINS Active Threat Intelligence Poor Reputation IP group 215 ' +
  'UNIFIipsSignatureId=2403514 ' +
  'msg=A network intrusion attempt from 167.94.146.48 to 192.168.1.194 has been detected and blocked.';

// Same envelope, Audit category — the other UniFi CEF parser must claim this one.
const UNIFI_AUDIT =
  'CEF:0|Ubiquiti|UniFi Network|10.4.57|300|Admin Login|3|UNIFIcategory=Audit ' +
  'UNIFIadmin=alice UNIFIdeviceIp=192.168.1.1 src=192.168.1.50';

// CEF from a vendor with no specific parser — must still be handled generically.
const OTHER_VENDOR_CEF =
  'CEF:0|Trend Micro|Deep Security Agent|10.0|100|Eicar_test_file|6|' +
  'src=198.51.100.9 dst=203.0.113.7 suser=jdoe act=Quarantine';

test('a vendor-specific CEF parser wins over the generic CEF parsers', () => {
  const picked = selectParser(UNIFI_IPS);

  assert.ok(picked, 'expected some parser to claim a UniFi IDS/IPS CEF event');
  assert.equal(picked!.parser.name, 'ubiquiti-unifi-ids-ips');
  assert.equal(picked!.result.event_type, 'ids_ips_alert');
});

test('the UniFi IDS/IPS parser derives the canonical fields the generic one cannot', () => {
  // The point of winning: cef-syslog produces a bare cef_event with no canonical
  // threat fields, so anything downstream keyed on them sees nothing.
  const { result } = selectParser(UNIFI_IPS)!;

  assert.equal(result.fields.signature_name, 'ET CINS Active Threat Intelligence Poor Reputation IP group 215');
  assert.equal(result.fields.rule_name, 'CINS Army Reputation List');
  assert.equal(result.fields.event_outcome, 'blocked');
  assert.equal(result.fields.sensor_ip, '192.168.1.1');
  assert.equal(result.fields.network_direction, 'incoming');
  assert.equal(result.fields.source_ip, '167.94.146.48');
  assert.equal(result.fields.dest_ip, '192.168.1.194');
});

test('UniFi Client-Devices CEF goes to its own parser, not generic CEF', () => {
  // These are the highest-volume UniFi CEF events (every WiFi connect and
  // disconnect). Without a category-specific parser they fell through to the
  // generic one and lost every client field.
  const parser = loadAll().find((p) => p.name === 'ubiquiti-unifi-client-devices')!;
  const sample = (parser.test_samples as any[])[0].input as string;

  const picked = selectParser(sample);
  assert.ok(picked, 'expected a parser to claim a UniFi client-device event');
  assert.equal(picked!.parser.name, 'ubiquiti-unifi-client-devices');
  assert.equal(picked!.result.event_type, 'wifi_client_session');
  assert.equal(picked!.result.fields.client_ip, '192.168.3.119');
  assert.equal(picked!.result.fields.ssid, 'HomeIoT');
  assert.equal(picked!.result.fields.action, 'connected');
});

test('the three UniFi CEF categories do not steal each other\'s events', () => {
  // They share one envelope and are told apart only by UNIFIcategory, so a
  // loosened discriminator would silently reroute a whole category.
  const byName = new Map(loadAll().map((p) => [p.name, p]));
  const expected: Array<[string, string]> = [
    ['ubiquiti-unifi-client-devices', 'ubiquiti-unifi-client-devices'],
    ['ubiquiti-unifi-ids-ips', 'ubiquiti-unifi-ids-ips'],
    ['ubiquiti-unifi-cef-audit', 'ubiquiti-unifi-cef-audit'],
  ];

  for (const [source, winner] of expected) {
    for (const sample of (byName.get(source)!.test_samples as any[])) {
      const picked = selectParser(sample.input as string);
      assert.equal(picked?.parser.name, winner, `${source} sample was claimed by ${picked?.parser.name}`);
    }
  }
});

test('UniFi Audit CEF goes to the audit parser, not the IDS/IPS one', () => {
  const picked = selectParser(UNIFI_AUDIT);

  assert.ok(picked, 'expected some parser to claim a UniFi audit CEF event');
  assert.equal(picked!.parser.name, 'ubiquiti-unifi-cef-audit');
});

test('CEF from a vendor with no specific parser still falls back to generic CEF', () => {
  // Guard against over-correcting: moving the generic parsers later must not
  // leave unknown-vendor CEF unparsed, nor let an unrelated parser claim it.
  const picked = selectParser(OTHER_VENDOR_CEF);

  assert.ok(picked, 'expected generic CEF to still catch other vendors');
  assert.match(picked!.parser.name, /^cef-/);
  assert.equal(picked!.result.event_type, 'cef_event');
  assert.equal(picked!.result.fields.device_vendor, 'Trend Micro');
});

test('the generic CEF parsers sit in the generic priority band, behind vendor-specific ones', () => {
  // The structural invariant behind the tests above: PARSERS.md reserves
  // 100-500 for generic parsers. cef-syslog/cef-standard were at 4/5, ahead of
  // every specific parser in the catalog.
  const parsers = loadAll();
  const byName = new Map(parsers.map((p) => [p.name, p.priority ?? 100]));

  const genericCef = ['cef-syslog', 'cef-standard'];
  const specificCef = [
    'ubiquiti-unifi-ids-ips',
    'ubiquiti-unifi-cef-audit',
    'ubiquiti-unifi-client-devices',
  ];

  for (const name of genericCef) {
    const priority = byName.get(name);
    assert.ok(priority !== undefined, `${name} missing from the catalog`);
    assert.ok(
      priority! >= 100,
      `${name} has priority ${priority}; generic parsers belong in the 100-500 band or they shadow specific ones`
    );
  }

  const worstGeneric = Math.min(...genericCef.map((n) => byName.get(n)!));
  for (const name of specificCef) {
    const priority = byName.get(name);
    assert.ok(priority !== undefined, `${name} missing from the catalog`);
    assert.ok(
      priority! < worstGeneric,
      `${name} (priority ${priority}) must sort before the generic CEF parsers (${worstGeneric}) to be reachable`
    );
  }
});
