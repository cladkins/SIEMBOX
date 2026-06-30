/**
 * Adversarial cross-match tests for parser selection — locks in two fixes:
 *
 *  1. JSON parsers must match their OWN format, not "any JSON". Before the
 *     discriminator, authentik-audit (the lowest-priority-number JSON parser)
 *     claimed every Caddy/Traefik/etc. JSON log because applyJsonParser accepted
 *     anything that merely parsed as JSON.
 *  2. nginx-komodo-timestamp-first must require a real nginx access-log timestamp,
 *     not just "[anything] token" — which used to swallow unrelated app lines
 *     like a Termix "[8:03:56 AM] SSH connection established" message.
 *
 * These load the REAL catalog parser definitions so the test fails if a future
 * catalog edit reintroduces the over-match. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import { runParser, ParserDef } from './runParser';

const CATALOG = path.join(__dirname, '../../../../catalog/parsers');
function load(name: string): ParserDef {
  return JSON.parse(fs.readFileSync(path.join(CATALOG, `${name}.parser.json`), 'utf8')) as ParserDef;
}

const authentik = load('authentik-audit');
const caddy = load('caddy-access');
const jsonGeneric = load('json-parser');
const nginxKomodoTs = load('nginx-komodo-timestamp-first');

const caddyLog =
  '{"level":"info","ts":1705320000.123,"logger":"http.log.access","msg":"handled request","request":{"client_ip":"203.0.113.5","method":"GET","uri":"/api/health","proto":"HTTP/2.0","headers":{"User-Agent":["Mozilla/5.0"]}},"status":200,"size":18,"duration":0.0012}';
const traefikLog =
  '{"ClientAddr":"203.0.113.5:51234","RequestMethod":"GET","RequestPath":"/api/whoami","RequestProtocol":"HTTP/2.0","DownstreamStatus":200}';
const authentikLog =
  '{"timestamp":"2024-01-15T12:00:00Z","event":"login","user":"alice","ip":"203.0.113.5","success":false}';
const genericJson = '{"timestamp":"2024-01-15T12:00:00Z","level":"info","msg":"just a normal app log"}';
// Termix web-SSH app line (the misparse from the field): emoji + timestamp-first.
const termixLine = '[8:03:56 AM] [SUCCESS] [\u{1F5A5}] SSH connection established [op:terminal]';
const komodoAccess = '[15/Jan/2024:12:00:00 +0000] - 200 200 - GET https /api/health';

test('authentik-audit does NOT claim a Caddy JSON log', () => {
  assert.equal(runParser(authentik, caddyLog), null);
});

test('authentik-audit does NOT claim a Traefik JSON log', () => {
  assert.equal(runParser(authentik, traefikLog), null);
});

test('authentik-audit does NOT claim a generic timestamp+level+msg JSON log', () => {
  assert.equal(runParser(authentik, genericJson), null);
});

test('authentik-audit still matches a real Authentik audit log', () => {
  const r = runParser(authentik, authentikLog);
  assert.ok(r, 'expected authentik-audit to match its own log');
  assert.equal(r!.fields.service, 'authentik');
});

test('caddy-access matches its own log (no longer shadowed by authentik-audit)', () => {
  const r = runParser(caddy, caddyLog);
  assert.ok(r, 'expected caddy-access to match its own log');
  assert.equal(r!.fields.service, 'caddy');
  assert.equal(String(r!.fields.status_code), '200');
});

test('json-parser (empty field_mappings) remains a catch-all for any JSON', () => {
  assert.ok(runParser(jsonGeneric, genericJson), 'generic json-parser should still match any JSON');
});

test('nginx-komodo-timestamp-first does NOT claim a Termix app line', () => {
  assert.equal(runParser(nginxKomodoTs, termixLine), null);
});

test('nginx-komodo-timestamp-first still matches a real Komodo access line', () => {
  const r = runParser(nginxKomodoTs, komodoAccess);
  assert.ok(r, 'expected nginx-komodo-timestamp-first to match a real access line');
  assert.equal(r!.fields.service, 'nginx');
});
