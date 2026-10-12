/**
 * Validation for PATCH /log-discovery/sources/:id (edit an API-polled source's
 * address, port, HTTPS and endpoint). validateSourceTargetUpdate is the pure
 * (DB-free) core of the route; the HTTP, role and storage behaviour is covered
 * by logDiscovery.edit.db.test.ts. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateSourceTargetUpdate, validateManualSourceInput } from './logDiscovery';

const MANUAL = { manual: true, currentIp: '192.168.1.50' };
const DISCOVERED = { manual: false, currentIp: '192.168.1.50' };

function rejected(body: unknown, ctx = MANUAL) {
  const r = validateSourceTargetUpdate(body, ctx);
  assert.equal(r.ok, false, `${JSON.stringify(body)} should be rejected`);
  return r.ok ? { status: 0, message: '' } : r;
}

test('port, tls and endpoint are accepted; null resets each to its default', () => {
  assert.deepEqual(validateSourceTargetUpdate({ port: 8124, tls: true, endpoint: '/api/hassio/core/logs' }, DISCOVERED), {
    ok: true,
    value: { port: 8124, tls: true, endpoint: '/api/hassio/core/logs' },
  });
  assert.deepEqual(validateSourceTargetUpdate({ port: null, tls: null, endpoint: null }, DISCOVERED), {
    ok: true,
    value: { port: null, tls: null, endpoint: null },
  });
  assert.deepEqual(validateSourceTargetUpdate({ endpoint: '   ' }, DISCOVERED), { ok: true, value: { endpoint: null } }, 'empty endpoint = default');
  assert.deepEqual(validateSourceTargetUpdate({ port: 1 }, MANUAL), { ok: true, value: { port: 1 } });
  assert.deepEqual(validateSourceTargetUpdate({ port: 65535 }, MANUAL), { ok: true, value: { port: 65535 } });
});

test('port must be an integer 1-65535', () => {
  for (const port of [0, 65536, -1, 80.5, '8123', true, [8123]]) {
    const r = rejected({ port });
    assert.equal(r.status, 400);
    assert.match(r.message, /port must be an integer between 1 and 65535/);
  }
});

test('tls must be a boolean', () => {
  for (const tls of ['yes', 1, 'true']) {
    const r = rejected({ tls });
    assert.equal(r.status, 400);
    assert.match(r.message, /tls must be a boolean/);
  }
});

test('the endpoint path rules apply (path only, same host, no traversal, no control characters, capped)', () => {
  for (const endpoint of ['http://evil.example/x', '//evil.example/x', 'api/error_log', '/a/../b', '/x?y=1', '/x\r\nHost: evil', '/' + 'a'.repeat(300), 7]) {
    assert.equal(rejected({ endpoint }).status, 400, JSON.stringify(endpoint));
  }
});

test("only a manual source's address can change, validated like POST /sources/manual", () => {
  assert.deepEqual(validateSourceTargetUpdate({ ip_address: ' 192.168.1.60 ' }, MANUAL), { ok: true, value: { ip_address: '192.168.1.60' } });
  assert.deepEqual(validateSourceTargetUpdate({ ip_address: 'fd00::60' }, MANUAL), { ok: true, value: { ip_address: 'fd00::60' } });

  const discoveredMove = rejected({ ip_address: '192.168.1.60' }, DISCOVERED);
  assert.equal(discoveredMove.status, 403, 'a discovered source is never pointed at another host');
  assert.match(discoveredMove.message, /only a manually added source's address can be edited/);

  for (const ip_address of ['homeassistant.local', 'http://192.168.1.60', '192.168.1.0/24', '', 'fe80::1%eth0', 12]) {
    const r = rejected({ ip_address });
    assert.equal(r.status, 400, JSON.stringify(ip_address));
    assert.match(r.message, /literal IPv4 or IPv6 address/);
    // The create route says the same about the same input.
    const created = validateManualSourceInput({ ip_address, fingerprint_id: 'home-assistant' });
    assert.equal(created.ok, false, `POST /sources/manual rejects ${JSON.stringify(ip_address)} too`);
  }
});

test('sending the current address back changes nothing, for any source and however IPv6 is written', () => {
  assert.deepEqual(validateSourceTargetUpdate({ ip_address: '192.168.1.50', port: 8124 }, DISCOVERED), {
    ok: true,
    value: { port: 8124 },
  });
  const v6 = { manual: false, currentIp: 'fd00::50' };
  assert.deepEqual(validateSourceTargetUpdate({ ip_address: 'FD00:0:0:0:0:0:0:50' }, v6), { ok: true, value: {} });
});

test('an empty or non-object body is a 400 that says what can be sent', () => {
  for (const body of [{}, { hostname: 'x' }, null, 'port=8123', [1]]) {
    const r = rejected(body);
    assert.equal(r.status, 400);
  }
  assert.match(rejected({}).message, /Nothing to change/);
});
