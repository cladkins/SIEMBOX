import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isFailure, mapEvent } from './authentik';

test('isFailure matches fail/denied/invalid, case-insensitively', () => {
  assert.equal(isFailure('login_failed'), true);
  assert.equal(isFailure('AUTHORIZATION_DENIED'), true);
  assert.equal(isFailure('invalid_password'), true);
  assert.equal(isFailure('login'), false);
  assert.equal(isFailure(null), false);
  assert.equal(isFailure(undefined), false);
});

test('mapEvent produces the JSON shape authentik-audit.parser.json expects', () => {
  const event = {
    pk: 'a1b2c3',
    created: '2024-01-15T12:00:00Z',
    action: 'login',
    user: { username: 'alice' },
    client_ip: '203.0.113.5',
    app: 'authentik.core',
  };
  const mapped = mapEvent(event);
  assert.ok(mapped);
  assert.deepEqual(JSON.parse(mapped!.message), {
    timestamp: '2024-01-15T12:00:00Z',
    event: 'login',
    user: 'alice',
    ip: '203.0.113.5',
    success: true,
    app: 'authentik.core',
  });
  assert.equal(mapped!.eventId, 'a1b2c3');
  assert.equal(mapped!.timestamp?.toISOString(), '2024-01-15T12:00:00.000Z');
});

test('mapEvent marks a failed-login action as success:false', () => {
  const mapped = mapEvent({ pk: 'x', created: '2024-01-15T12:00:00Z', action: 'login_failed', client_ip: '203.0.113.5' });
  assert.equal(JSON.parse(mapped!.message).success, false);
});

test('mapEvent handles a null/anonymous user without throwing', () => {
  const mapped = mapEvent({ pk: 'x', created: '2024-01-15T12:00:00Z', action: 'login_failed', user: null });
  assert.equal(JSON.parse(mapped!.message).user, null);
});

test('mapEvent returns null when created is missing', () => {
  assert.equal(mapEvent({ pk: 'x', action: 'login' }), null);
});
