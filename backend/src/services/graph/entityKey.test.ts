/**
 * Entity keys: one canonical `type:key` per thing, validated before any value
 * reaches SQL. ENTITY_KEY_FIXTURES is the parity list the frontend copy (PR 2)
 * and the rollup's SQL functions (PR 3) are tested against too.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalIp,
  canonicalKey,
  ENTITY_KEY_FIXTURES,
  JUNK_USERS,
  MAX_ENTITY_LENGTH,
  parseEntity,
  toEntity,
  tryParseEntity,
} from './entityKey';
import { GraphError } from './errors';
import { NODE_TYPES } from './types';

test('the parity fixture: every input canonicalizes to its expected key', () => {
  for (const [type, input, expected] of ENTITY_KEY_FIXTURES) {
    assert.equal(canonicalKey(type, input), expected, `${type} ${JSON.stringify(input)}`);
  }
  // It covers every type and both outcomes.
  for (const type of ['ip', 'host', 'user', 'domain', 'alert', 'shipper_tag', 'endpoint'] as const) {
    assert.ok(ENTITY_KEY_FIXTURES.some(([t, , e]) => t === type && e !== null), `${type} valid`);
    assert.ok(ENTITY_KEY_FIXTURES.some(([t, , e]) => t === type && e === null), `${type} invalid`);
  }
});

test('IPs: IPv4 as is, IPv6 in RFC 5952 form, IPv4-mapped IPv6 folded to IPv4', () => {
  assert.equal(canonicalIp('10.0.0.1'), '10.0.0.1');
  assert.equal(canonicalIp('2001:0DB8:0000:0000:0000:0000:0000:0001'), '2001:db8::1');
  assert.equal(canonicalIp('2001:db8:0:0:1:0:0:1'), '2001:db8::1:0:0:1');
  assert.equal(canonicalIp('::ffff:192.0.2.1'), '192.0.2.1');
  assert.equal(canonicalIp('::ffff:c000:201'), '192.0.2.1');
  assert.equal(canonicalIp('0:0:0:0:0:ffff:c000:0201'), '192.0.2.1');
  for (const bad of ['', ' ', '1.2.3', '1.2.3.4.5', '999.1.1.1', 'fe80::1%eth0', '::g', 'nas', 42, null, undefined, {}]) {
    assert.equal(canonicalIp(bad), null, JSON.stringify(bad));
  }
});

test('ids: positive integers within INTEGER, no leading zero', () => {
  for (const type of ['alert', 'rule', 'asset', 'vuln', 'finding', 'identity', 'shipper', 'account'] as const) {
    assert.equal(canonicalKey(type, '1'), '1');
    assert.equal(canonicalKey(type, '2147483647'), '2147483647');
    for (const bad of ['0', '01', '-1', '1.5', '1e3', '2147483648', '99999999999', 'abc', '']) {
      assert.equal(canonicalKey(type, bad), null, `${type} ${bad}`);
    }
  }
});

test('users: case kept, junk refused, control and bidi characters refused, at most 128 characters', () => {
  assert.equal(canonicalKey('user', 'Administrator'), 'Administrator');
  assert.equal(canonicalKey('user', 'alice@corp.example'), 'alice@corp.example');
  for (const junk of JUNK_USERS) {
    assert.equal(canonicalKey('user', junk), null, junk);
    assert.equal(canonicalKey('user', junk.toUpperCase()), null, junk.toUpperCase());
  }
  assert.equal(canonicalKey('user', 'a\u0000b'), null);
  assert.equal(canonicalKey('user', 'a\u009bb'), null, 'C1 control');
  assert.equal(canonicalKey('user', 'admin‮gnp.exe'), null, 'right-to-left override');
  assert.equal(canonicalKey('user', 'x'.repeat(128)), 'x'.repeat(128));
  assert.equal(canonicalKey('user', 'x'.repeat(129)), null);
});

test('hosts and domains: lower-cased; domains need a dot and lose a trailing one', () => {
  assert.equal(canonicalKey('host', 'FileServer'), 'fileserver');
  assert.equal(canonicalKey('host', 'a'.repeat(253)), 'a'.repeat(253));
  assert.equal(canonicalKey('host', 'with space'), null);
  assert.equal(canonicalKey('domain', 'WWW.Example.org.'), 'www.example.org');
  assert.equal(canonicalKey('domain', 'intranet'), null);
  assert.equal(canonicalKey('domain', 'bad⁦.example'), null);
});

test('parseEntity: type:key, split at the first colon (IPv6 keeps its colons)', () => {
  assert.deepEqual(parseEntity('ip:2001:db8::1'), { type: 'ip', key: '2001:db8::1', id: 'ip:2001:db8::1' });
  assert.deepEqual(parseEntity('IP:::ffff:198.51.100.7'), { type: 'ip', key: '198.51.100.7', id: 'ip:198.51.100.7' });
  assert.deepEqual(parseEntity('user:Root'), { type: 'user', key: 'Root', id: 'user:Root' });
  assert.deepEqual(parseEntity('shipper_tag:DEADBEEF'), { type: 'shipper_tag', key: 'deadbeef', id: 'shipper_tag:deadbeef' });
  assert.equal(parseEntity('host:nas:8080').key, 'nas:8080', 'a host key may hold a colon');
});

test('parseEntity: anything else is a 400 GRAPH_BAD_ENTITY, never another status', () => {
  for (const bad of [undefined, '', 'ip', ':1.2.3.4', 'process:1', 'ip:nope', 'alert:0', 'user:-', 'x'.repeat(MAX_ENTITY_LENGTH + 1), 42, ['ip:1.2.3.4']]) {
    assert.throws(
      () => parseEntity(bad),
      (err: unknown) => err instanceof GraphError && err.statusCode === 400 && err.code === 'GRAPH_BAD_ENTITY',
      JSON.stringify(bad)
    );
  }
  assert.equal(tryParseEntity('process:1'), null);
  assert.equal(tryParseEntity('alert:x'), null);
});

test('every node type has a validator', () => {
  const samples: Record<string, string> = {
    ip: '192.0.2.1',
    host: 'nas',
    user: 'root',
    domain: 'example.com',
    shipper_tag: '0123abcd',
    endpoint: '3f2504e0-4f89-11d3-9a0c-0305e82c3301',
  };
  for (const type of NODE_TYPES) {
    const ref = toEntity(type, samples[type] ?? '7');
    assert.ok(ref, type);
    assert.equal(ref.id, `${type}:${ref.key}`);
  }
});
