/**
 * Access control for /api/notifications. Every route here was previously
 * reachable by any logged-in role, including 'viewer'. That role could read
 * channel delivery secrets and disable or redirect alert delivery. These tests
 * lock in the fix:
 * - Every route that changes delivery or sends a message requires admin.
 * - GET /channels returns `config` only to admins.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import router, { redactChannelsForRole } from './notifications';
import { requireAdmin } from '../middleware/auth';

const channels = [
  { id: 1, name: 'slack', channel_type: 'slack', enabled: true, config: { webhook_url: 'https://hooks.slack.com/services/T/B/secret' } },
  { id: 2, name: 'ntfy', channel_type: 'ntfy', enabled: false, config: { url: 'https://ntfy.sh/x', token: 'tk_secret' } },
];

test('admins get channel config (they need it to edit channels)', () => {
  assert.deepEqual(redactChannelsForRole(channels, 'admin'), channels);
});

for (const role of ['operator', 'analyst', 'viewer', undefined]) {
  test(`role ${String(role)} gets channels with config redacted`, () => {
    const out = redactChannelsForRole(channels, role);
    assert.equal(out.length, channels.length, 'channel count must survive (Onboarding counts them)');
    for (const [i, c] of out.entries()) {
      assert.deepEqual(c.config, {}, 'no delivery secret may leak');
      assert.equal(c.id, channels[i].id);
      assert.equal(c.name, channels[i].name);
      assert.equal(c.enabled, channels[i].enabled);
    }
    assert.match(JSON.stringify(out), /^((?!secret).)*$/, 'serialized response contains no secret');
  });
}

test('redaction does not mutate the input rows', () => {
  redactChannelsForRole(channels, 'viewer');
  assert.ok(channels[0].config.webhook_url, 'original row keeps its config');
});

// Find the handler chain for METHOD PATH on the router.
function routeHandlers(method: string, path: string): unknown[] {
  const layer = (router as any).stack.find(
    (l: any) => l.route && l.route.path === path && l.route.methods[method]
  );
  assert.ok(layer, `route ${method.toUpperCase()} ${path} exists`);
  return layer.route.stack.map((l: any) => l.handle);
}

const ADMIN_ONLY: Array<[string, string]> = [
  ['post', '/channels'],
  ['put', '/channels/:id'],
  ['delete', '/channels/:id'],
  ['post', '/channels/:id/test'],
  ['post', '/test-alert'],
  ['put', '/settings'],
];

for (const [method, path] of ADMIN_ONLY) {
  test(`${method.toUpperCase()} ${path} requires admin`, () => {
    assert.ok(routeHandlers(method, path).includes(requireAdmin));
  });
}

for (const [method, path] of [['get', '/channels'], ['get', '/settings']] as Array<[string, string]>) {
  test(`${method.toUpperCase()} ${path} stays readable by any logged-in role`, () => {
    assert.ok(!routeHandlers(method, path).includes(requireAdmin));
  });
}
