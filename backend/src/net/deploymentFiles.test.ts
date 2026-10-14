/**
 * The deployment files the client-address model relies on (clientAddress.ts;
 * DEPLOYMENT.md, "Client addresses and reverse proxies"):
 *
 * - Both compose files share the `api-socket` volume: read-write at
 *   /run/siembox on the backend, which listens there, read-only on the
 *   frontend, whose nginx connects. The backend gets TRUSTED_PROXIES (default
 *   `frontend`), and API_RATE_LIMIT_MAX, EDR_AGENT_RATE_MAX,
 *   SHIPPER_LOG_PUSH_MAX, SIEMBOX_PROXY_SOCKET, the sign-in settings and
 *   CORS_ORIGIN from .env (empty: the code default; for CORS_ORIGIN that is
 *   same-origin only, which .env.example keeps); BACKEND_UPSTREAM keeps its
 *   default.
 * - The nginx template proxies /api to the socket, with BACKEND_UPSTREAM as a
 *   backup that is only used when connecting fails and is never marked down,
 *   and sets X-Forwarded-For with $proxy_add_x_forwarded_for: the backend takes
 *   the client from its last entry, so passing a client's own header through
 *   unchanged would let every client pick its address.
 *
 * Hermetic: reads files from the repository. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import * as yaml from '../utils/yaml';
import { DEFAULT_PROXY_SOCKET } from './apiListeners';
import { DEFAULT_TRUSTED_PROXIES } from './trustedProxies';

const REPO = path.join(__dirname, '../../..');
const SOCKET_DIR = path.posix.dirname(DEFAULT_PROXY_SOCKET);

interface ComposeService {
  environment?: Record<string, string>;
  volumes?: string[];
}
interface ComposeFile {
  services: Record<string, ComposeService>;
  volumes?: Record<string, unknown>;
}

for (const file of ['compose.yaml', 'compose.prod.yaml']) {
  test(`${file}: the api-socket volume and the client-address settings`, () => {
    const compose = yaml.load(fs.readFileSync(path.join(REPO, file), 'utf8')) as ComposeFile;
    const { backend, frontend } = compose.services;
    assert.ok(backend.volumes?.includes(`api-socket:${SOCKET_DIR}`), 'the backend mounts it read-write');
    assert.ok(frontend.volumes?.includes(`api-socket:${SOCKET_DIR}:ro`), 'the frontend mounts it read-only');
    assert.deepEqual(compose.volumes?.['api-socket'], { driver: 'local' });
    assert.equal(backend.environment?.TRUSTED_PROXIES, `\${TRUSTED_PROXIES:-${DEFAULT_TRUSTED_PROXIES}}`);
    // Passed through from .env; empty means the code default.
    for (const name of [
      'API_RATE_LIMIT_MAX',
      'EDR_AGENT_RATE_MAX',
      'SHIPPER_LOG_PUSH_MAX',
      'SIEMBOX_PROXY_SOCKET',
      // Sign-in protection (services/auth/signInPolicy.ts)
      'LOGIN_PROTECTION',
      'LOGIN_MAX_FAILURES',
      'LOGIN_MAX_FAILURES_PER_ADDRESS',
      'LOGIN_MAX_FAILURES_PER_ACCOUNT',
      'AUTH_ALERTS',
      'AUTH_FAILURE_AUDIT_RETENTION_DAYS',
      // Same-origin only unless set (net/cors.ts); never `*` by default.
      'CORS_ORIGIN',
    ]) {
      assert.equal(backend.environment?.[name], `\${${name}:-}`, name);
    }
    assert.equal(frontend.environment?.BACKEND_UPSTREAM, '${BACKEND_UPSTREAM:-backend:8421}');
  });
}

test('.env.example: CORS_ORIGIN is empty (same-origin only)', () => {
  const lines = fs.readFileSync(path.join(REPO, '.env.example'), 'utf8').split('\n');
  assert.deepEqual(
    lines.filter((line) => line.startsWith('CORS_ORIGIN=')),
    ['CORS_ORIGIN=']
  );
});

/** The `;`-separated directives in an nginx block body, whitespace collapsed. */
function directives(body: string): string[] {
  return body
    .split(';')
    .map((d) => d.trim().replace(/\s+/g, ' '))
    .filter(Boolean);
}

test('nginx template: the socket first, BACKEND_UPSTREAM as backup, the load-bearing headers', () => {
  // Without comments, which quote the directives they explain.
  const conf = fs.readFileSync(path.join(REPO, 'frontend/nginx.conf.template'), 'utf8').replace(/#.*$/gm, '');
  // Each block ends at the first line holding only "}" (${BACKEND_UPSTREAM} has a brace mid-line).
  const upstream = /upstream siembox_api \{([\s\S]*?)\n\s*\}/.exec(conf)?.[1] ?? '';
  assert.deepEqual(directives(upstream), [
    `server unix:${DEFAULT_PROXY_SOCKET} max_fails=1 fail_timeout=30s`,
    'server ${BACKEND_UPSTREAM} backup max_fails=0',
  ]);
  const api = directives(/location \/api \{([\s\S]*?)\n\s*\}/.exec(conf)?.[1] ?? '');
  const named = (name: string) => api.filter((d) => d.startsWith(`${name} `));
  assert.deepEqual(named('proxy_pass'), ['proxy_pass http://siembox_api']);
  assert.deepEqual(named('proxy_next_upstream'), ['proxy_next_upstream error'], 'no replay after a timeout');
  assert.deepEqual(
    named('proxy_set_header').filter((d) => /x-forwarded-for|x-real-ip/i.test(d)),
    ['proxy_set_header X-Real-IP $remote_addr', 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for']
  );
});
