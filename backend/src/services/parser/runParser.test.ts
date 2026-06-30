/**
 * Unit tests for the DB-free parse -> derive -> normalize pipeline. Run with
 * `npm test` (tsx --test). No database required.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runParser, deriveService, ParserDef } from './runParser';

test('regex parser maps named groups, normalizes IP/user, and types SSH events', () => {
  const parser: ParserDef = {
    name: 'ssh-auth',
    parser_type: 'regex',
    pattern:
      '(?<event>Failed password|Accepted password) for (?:invalid user )?(?<username>\\S+) from (?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)',
    field_mappings: { event: 'event', username: 'username', src_ip: 'src_ip' },
  };
  const out = runParser(parser, 'Failed password for invalid user admin from 192.168.1.50 port 22 ssh2');
  assert.ok(out, 'parser should match');
  // Canonical normalization: src_ip -> source_ip, mirrored to client_ip; username -> user.
  assert.equal(out!.fields.source_ip, '192.168.1.50');
  assert.equal(out!.fields.client_ip, '192.168.1.50');
  assert.equal(out!.fields.user, 'admin');
  // postProcessFields derives the shared auth_outcome marker from the event text.
  assert.equal(out!.fields.auth_outcome, 'failure');
  // SSH parser name + "Failed" event -> ssh_failed_login.
  assert.equal(out!.event_type, 'ssh_failed_login');
  // service is derived from the parser name.
  assert.equal(out!.fields.service, 'sshd');
});

test('regex parser accepts reversed {field: group} mappings', () => {
  const parser: ParserDef = {
    name: 'firewall-drop',
    parser_type: 'regex',
    pattern: 'SRC=(?<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)',
    // Written reversed (field -> group) the way several seeded parsers did.
    field_mappings: { src_ip: 'ip' },
  };
  const out = runParser(parser, 'kernel: DROP SRC=10.0.0.9 DST=10.0.0.1');
  assert.ok(out);
  assert.equal(out!.fields.source_ip, '10.0.0.9');
});

test('regex parser returns null when the line does not match', () => {
  const parser: ParserDef = {
    name: 'ssh-auth',
    parser_type: 'regex',
    pattern: 'Failed password for (?<username>\\S+)',
    field_mappings: { username: 'username' },
  };
  assert.equal(runParser(parser, 'an unrelated log line'), null);
});

test('json parser maps flat keys and normalizes status', () => {
  const parser: ParserDef = {
    name: 'nginx-json',
    parser_type: 'json',
    pattern: '',
    field_mappings: { remote_addr: 'src_ip', status: 'status', request_uri: 'request_uri' },
  };
  const out = runParser(
    parser,
    '{"remote_addr":"203.0.113.7","status":404,"request_uri":"/admin"}'
  );
  assert.ok(out);
  assert.equal(out!.fields.source_ip, '203.0.113.7');
  assert.equal(out!.fields.status_code, 404); // status -> status_code
  assert.equal(out!.fields.path, '/admin'); // request_uri -> path
});

test('json parser resolves dotted paths for nested logs (Caddy-style)', () => {
  const parser: ParserDef = {
    name: 'caddy-access',
    parser_type: 'json',
    pattern: '',
    field_mappings: { 'request.client_ip': 'src_ip', 'request.host': 'host' },
  };
  const out = runParser(
    parser,
    '{"request":{"client_ip":"198.51.100.4","host":"app.example.com"}}'
  );
  assert.ok(out);
  assert.equal(out!.fields.source_ip, '198.51.100.4');
  assert.equal(out!.fields.host, 'app.example.com');
});

test('json parser strips a label prefix before the JSON body', () => {
  const parser: ParserDef = {
    name: 'authentik-events',
    parser_type: 'json',
    pattern: '',
    field_mappings: { username: 'username', event: 'event' },
  };
  const out = runParser(parser, 'Authentik Server: {"username":"bob","event":"login_failure"}');
  assert.ok(out);
  assert.equal(out!.fields.user, 'bob');
  // login_failure -> auth_outcome failure (canonical auth marker).
  assert.equal(out!.fields.auth_outcome, 'failure');
});

test('json parser returns null on invalid JSON', () => {
  const parser: ParserDef = {
    name: 'whatever',
    parser_type: 'json',
    pattern: '',
    field_mappings: { a: 'a' },
  };
  assert.equal(runParser(parser, 'this is not json'), null);
});

test('explicit parser.event_type overrides the auto-derived type', () => {
  const parser: ParserDef = {
    name: 'ssh-auth',
    parser_type: 'regex',
    pattern: '(?<event>Failed password)',
    field_mappings: { event: 'event' },
    event_type: 'custom_override',
  };
  const out = runParser(parser, 'Failed password for root');
  assert.ok(out);
  assert.equal(out!.event_type, 'custom_override');
});

test('packetSourceIp fills source_ip when absent and always sets observer_ip', () => {
  const parser: ParserDef = {
    name: 'bare-message',
    parser_type: 'regex',
    pattern: '(?<msg>.+)',
    field_mappings: { msg: 'detail' },
  };
  const out = runParser(parser, 'something happened', { packetSourceIp: '172.16.0.5' });
  assert.ok(out);
  assert.equal(out!.fields.source_ip, '172.16.0.5'); // fallback to packet sender
  assert.equal(out!.fields.observer_ip, '172.16.0.5'); // forwarder always recorded
});

test('deriveService maps known parser names and ignores unknown ones', () => {
  assert.equal(deriveService('my-ssh-parser'), 'sshd');
  assert.equal(deriveService('nginx-access'), 'nginx');
  assert.equal(deriveService('plex-media-server'), 'plex');
  assert.equal(deriveService('jellyfin'), 'jellyfin');
  assert.equal(deriveService('totally-unknown-thing'), undefined);
});
