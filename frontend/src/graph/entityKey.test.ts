/**
 * The browser's entity keys mean what the server's do: the backend's own
 * parity list (ENTITY_KEY_FIXTURES in backend/src/services/graph/entityKey.ts,
 * read from that file so the two can't drift), plus IP spellings checked
 * against Node's own address parser.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import { canonicalIp, canonicalKey, keyOfId, tryParseEntity, typeOfId } from './entityKey.ts';
import type { NodeType } from './types.ts';

type Fixture = readonly [NodeType, string, string | null];

/** The backend's ENTITY_KEY_FIXTURES array, evaluated from its source (a plain array literal). */
function backendFixtures(): Fixture[] {
  const source = readFileSync(new URL('../../../backend/src/services/graph/entityKey.ts', import.meta.url), 'utf8');
  const start = source.indexOf('export const ENTITY_KEY_FIXTURES');
  assert.ok(start >= 0, 'ENTITY_KEY_FIXTURES not found in the backend');
  const open = source.indexOf('= [', start) + 2;
  const close = source.indexOf('\n];', open) + 2;
  const literal = source.slice(open, close);
  // Rows are ['type', 'input' | 'x'.repeat(n), 'key' | null]: nothing but string literals.
  assert.match(literal, /^\[\s*\[/);
  return new Function(`return ${literal};`)() as Fixture[];
}

describe('entity keys (parity with the backend)', () => {
  const fixtures = backendFixtures();

  it('reads the whole backend list', () => {
    assert.ok(fixtures.length >= 50, `only ${fixtures.length} fixtures`);
  });

  for (const [type, input, expected] of fixtures) {
    it(`${type} ${JSON.stringify(input).slice(0, 40)} -> ${JSON.stringify(expected)}`, () => {
      assert.equal(canonicalKey(type, input), expected);
      const parsed = tryParseEntity(`${type}:${input}`);
      assert.equal(parsed?.key ?? null, expected);
      if (parsed) assert.equal(parsed.id, `${type}:${expected}`);
    });
  }
});

describe('IP addresses', () => {
  // What the backend computes (net.isIP, then the URL serializer for IPv6).
  function serverIp(s: string): string | null {
    if (s.length === 0 || s.length > 45) return null;
    const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
    if (mapped && net.isIPv4(mapped[1])) return mapped[1];
    if (net.isIPv4(s)) return s;
    if (s.includes('%') || !net.isIPv6(s)) return null;
    const host = new URL(`http://[${s}]/`).hostname.slice(1, -1);
    if (host.startsWith('::ffff:')) {
      const parts = host.slice(7).split(':');
      if (parts.length === 2) {
        const hi = parseInt(parts[0], 16);
        const lo = parseInt(parts[1], 16);
        return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
      }
    }
    return host;
  }

  const samples = [
    '0.0.0.0',
    '255.255.255.255',
    '1.2.3.4.5',
    '1.2.3',
    '00.1.2.3',
    '1.2.3.04',
    '::',
    '::1',
    '1::',
    '1:2:3:4:5:6:7:8',
    '1:2:3:4:5:6:7:8:9',
    '1::2::3',
    ':::',
    '12345::',
    'g::1',
    '::1.2.3',
    '::1.2.3.4',
    '::ffff:1.2.3.4',
    '::ffff:256.1.1.1',
    '::FFFF:0102:0304',
    '0:0:0:0:0:ffff:102:304',
    '2001:db8::1:0:0:1',
    '2001:DB8:0000:0000:0001:0000:0000:0001',
    'FE80::',
    '::1%lo',
    '[::1]',
    ' ::1',
    'fe80::1:2:3:4:5:6:7',
  ];
  for (const s of samples) {
    it(`${JSON.stringify(s)} as the server reads it`, () => {
      assert.equal(canonicalIp(s), serverIp(s));
    });
  }
});

describe('ids', () => {
  it('splits a node id on its first colon (IPv6 keys keep theirs)', () => {
    assert.equal(typeOfId('ip:2001:db8::1'), 'ip');
    assert.equal(keyOfId('ip:2001:db8::1'), '2001:db8::1');
    assert.equal(typeOfId('nope:1'), null);
    assert.equal(typeOfId('group:alert_ips|alert:1'), null);
  });

  it('refuses a type it does not know, and over-long input', () => {
    assert.equal(tryParseEntity('process:1'), null);
    assert.equal(tryParseEntity(`user:${'a'.repeat(300)}`), null);
    assert.equal(tryParseEntity('ip'), null);
    assert.equal(tryParseEntity(':1.2.3.4'), null);
    assert.equal(tryParseEntity(42), null);
  });

  it('lower-cases the type', () => {
    assert.equal(tryParseEntity('IP:1.2.3.4')?.id, 'ip:1.2.3.4');
  });
});
