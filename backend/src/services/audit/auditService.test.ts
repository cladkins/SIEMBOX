/**
 * AuditService.log must always write its row. audit_logs.ip_address is INET and
 * callers pass request-derived addresses (req.ip, which a trusted proxy's
 * X-Forwarded-For can set to anything), so a value Postgres would reject is
 * stored as NULL rather than failing the INSERT (log() only reports a failed
 * INSERT, so the row would be lost). Hermetic: the pool is mocked. Run with
 * `npm test` (tsx --test).
 */
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import pool from '../../config/database';
import { AuditService, toInet } from './auditService';

const params: unknown[][] = [];
mock.method(pool, 'query', async (_text: string, values: unknown[]) => {
  params.push(values);
  return { rows: [], rowCount: 1 };
});

test('toInet keeps IPv4 and IPv6 addresses', () => {
  for (const ip of ['127.0.0.1', '10.9.9.9', '::1', '::ffff:127.0.0.1', '2001:db8::1']) {
    assert.equal(toInet(ip), ip);
  }
});

test('toInet cuts off an IPv6 zone id, which INET rejects', () => {
  assert.equal(toInet('fe80::1%eth0'), 'fe80::1');
});

test('toInet turns anything else into null', () => {
  for (const value of ['not-an-ip', 'unknown', '', ' 10.9.9.9', '1.2.3.4:80', '1.2.3.4, 5.6.7.8', '2001:db8::1%', undefined, null, 42]) {
    assert.equal(toInet(value), null, JSON.stringify(value));
  }
});

test('log() writes the row with a NULL ip_address when the address is not one', async () => {
  params.length = 0;
  for (const ipAddress of ['not-an-ip', 'fe80::1%eth0', '10.9.9.9']) {
    await AuditService.log({ userId: 1, action: 'access.denied', ipAddress, userAgent: 'test', responseStatus: 403 });
  }
  assert.deepEqual(
    params.map((values) => values[4]),
    [null, 'fe80::1', '10.9.9.9'],
    'every row is written; ip_address ($5) is NULL, the zone-less address, or the address'
  );
});
