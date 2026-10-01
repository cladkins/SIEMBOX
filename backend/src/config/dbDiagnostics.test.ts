/**
 * Tests for the database-connection failure hints. The motivating incident: a
 * backend on the Compose bridge network with DB_HOST=127.0.0.1 crash-looped on
 * `connect ECONNREFUSED 127.0.0.1:5432` while Postgres itself was healthy, and
 * nothing in the logs said the host setting was the problem.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diagnoseDbConnectionError, isLoopbackHost } from './dbDiagnostics';

function connErr(code: string, extra: Record<string, unknown> = {}): Error {
  return Object.assign(new Error(`connect ${code}`), { code, ...extra });
}

test('the incident: loopback DB_HOST inside a bridge-network container points at DB_HOST=postgres + redeploy', () => {
  const hint = diagnoseDbConnectionError(connErr('ECONNREFUSED', { address: '127.0.0.1', port: 5432 }), {
    env: { DB_HOST: '127.0.0.1', DB_PORT: '5432' },
    inContainer: true,
  });
  assert.ok(hint, 'expected a hint');
  assert.match(hint!, /DB_HOST is 127\.0\.0\.1, a loopback address/);
  assert.match(hint!, /DB_HOST=postgres/);
  assert.match(hint!, /redeploy the stack/);
  assert.match(hint!, /plain container restart keeps the old environment/);
  assert.match(hint!, /network_mode: host/);
});

test('an unset DB_HOST falls back to localhost and gets the same bridge-network advice', () => {
  const hint = diagnoseDbConnectionError(connErr('ECONNREFUSED'), { env: {}, inContainer: true });
  assert.match(hint!, /DB_HOST is localhost/);
  assert.match(hint!, /DB_HOST=postgres/);
});

test('host networking enabled: points at the Postgres loopback publish and port conflicts, not at DB_HOST', () => {
  const hint = diagnoseDbConnectionError(connErr('ECONNREFUSED'), {
    env: { DB_HOST: 'localhost', SIEMBOX_HOST_NETWORKING: 'true' },
    inContainer: true,
  });
  assert.match(hint!, /Host networking is enabled/);
  assert.match(hint!, /127\.0\.0\.1:5432:5432/);
  assert.match(hint!, /ss -ltnp 'sport = :5432'/);
  assert.doesNotMatch(hint!, /DB_HOST=postgres/);
});

test('host networking advice uses the configured DB_PORT', () => {
  const hint = diagnoseDbConnectionError(connErr('ECONNREFUSED'), {
    env: { DB_HOST: '127.0.0.1', DB_PORT: '5433', SIEMBOX_HOST_NETWORKING: 'true' },
    inContainer: true,
  });
  assert.match(hint!, /127\.0\.0\.1:5433:5432/);
  assert.match(hint!, /sport = :5433/);
});

test('running outside a container: Postgres is simply not running locally', () => {
  const hint = diagnoseDbConnectionError(connErr('ECONNREFUSED'), {
    env: { DB_HOST: 'localhost' },
    inContainer: false,
  });
  assert.match(hint!, /Nothing is listening on localhost:5432/);
  assert.match(hint!, /Start PostgreSQL/);
});

test('non-loopback refusal: check the database service, not DB_HOST', () => {
  const hint = diagnoseDbConnectionError(connErr('ECONNREFUSED'), {
    env: { DB_HOST: 'postgres' },
    inContainer: true,
  });
  assert.match(hint!, /Postgres at postgres:5432 refused the connection/);
  assert.match(hint!, /docker ps/);
  assert.doesNotMatch(hint!, /loopback/);
});

test('unresolvable host: names the compose service and network', () => {
  const hint = diagnoseDbConnectionError(connErr('ENOTFOUND'), { env: { DB_HOST: 'postgress' }, inContainer: true });
  assert.match(hint!, /DB_HOST "postgress" could not be resolved/);
  assert.match(hint!, /siembox-network/);
  assert.ok(diagnoseDbConnectionError(connErr('EAI_AGAIN'), { env: { DB_HOST: 'db' } }));
});

test('timeouts / unreachable network are reported with the code', () => {
  const hint = diagnoseDbConnectionError(connErr('ETIMEDOUT'), { env: { DB_HOST: '10.0.0.5', DB_PORT: '5432' } });
  assert.match(hint!, /10\.0\.0\.5:5432 is unreachable \(ETIMEDOUT\)/);
  assert.ok(diagnoseDbConnectionError(connErr('EHOSTUNREACH'), { env: {} }));
});

test("AggregateError from Node's address-family fallback is diagnosed via its inner errors", () => {
  // `localhost` resolving to ::1 and 127.0.0.1 yields an AggregateError whose
  // own .code may be absent and whose message is empty.
  const agg = new AggregateError(
    [connErr('ECONNREFUSED', { address: '::1' }), connErr('ECONNREFUSED', { address: '127.0.0.1' })],
    ''
  );
  const hint = diagnoseDbConnectionError(agg, { env: { DB_HOST: 'localhost' }, inContainer: true });
  assert.match(hint!, /loopback address/);
});

test('errors this module cannot explain return null (auth, SQL, non-errors)', () => {
  assert.equal(diagnoseDbConnectionError(connErr('28P01'), { env: {} }), null);
  assert.equal(diagnoseDbConnectionError(new Error('syntax error at or near "SELEC"'), { env: {} }), null);
  assert.equal(diagnoseDbConnectionError(null, { env: {} }), null);
  assert.equal(diagnoseDbConnectionError(undefined, { env: {} }), null);
  assert.equal(diagnoseDbConnectionError('boom', { env: {} }), null);
});

test('hints never leak the database password or other settings', () => {
  const env = {
    DB_HOST: '127.0.0.1',
    DB_PASSWORD: 'sup3r-s3cret-pw',
    JWT_SECRET: 'jwt-s3cret',
    CREDENTIAL_ENCRYPTION_KEY: 'k'.repeat(64),
  };
  for (const code of ['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT']) {
    for (const inContainer of [true, false]) {
      const hint = diagnoseDbConnectionError(connErr(code), { env, inContainer }) ?? '';
      assert.doesNotMatch(hint, /sup3r-s3cret-pw|jwt-s3cret|kkkk/);
    }
  }
});

test('isLoopbackHost: loopback forms yes, look-alikes and real hosts no', () => {
  for (const h of ['localhost', 'LOCALHOST', '127.0.0.1', '127.1.2.3', '::1', '[::1]', ' localhost ']) {
    assert.equal(isLoopbackHost(h), true, h);
  }
  for (const h of ['postgres', '192.168.1.240', '10.0.0.1', '127.0.0.1.evil.example', '1127.0.0.1', 'db.localhost.example']) {
    assert.equal(isLoopbackHost(h), false, h);
  }
});
