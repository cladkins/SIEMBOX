/**
 * Endpoint-agent update decisions (agentUpdate.ts): semver compare and update
 * eligibility, auto/bulk targeting, heartbeat `update` validation, the
 * AgentConfig `agent_update` shape and GitHub release parsing. Pure: no
 * database, no network. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAgentUpdateConfig,
  checkUpdateEligibility,
  compareSemver,
  isDevBuild,
  parseHeartbeatUpdate,
  parseLatestRelease,
  parseSemver,
  sanitizeAgentVersion,
  selectAgentsToUpdate,
  type AgentUpdateRow,
} from './agentUpdate';
import { buildAgentConfig } from './edrService';

const REQ = 'b6f1c2d0-1111-4222-8333-444455556666';

test('parseSemver accepts only plain X.Y.Z', () => {
  const cases: Array<[unknown, boolean]> = [
    ['1.4.0', true], ['0.0.1', true], ['10.20.30', true],
    ['v1.4.0', false], ['1.4', false], ['1.4.0-rc1', false], ['1.4.0+b1', false],
    ['dev', false], ['a8922f4-dirty', false], ['', false], [' 1.4.0', false],
    ['1.4.0\n', false], [null, false], [undefined, false], [140, false],
  ];
  for (const [input, ok] of cases) assert.equal(parseSemver(input) !== null, ok, String(input));
});

test('compareSemver is numeric, not lexical', () => {
  const cases: Array<[string, string, number | null]> = [
    ['1.2.3', '1.2.3', 0], ['1.2.3', '1.2.4', -1], ['1.10.0', '1.9.9', 1],
    ['2.0.0', '1.99.99', 1], ['0.9.0', '0.10.0', -1], ['dev', '1.0.0', null],
  ];
  for (const [a, b, want] of cases) {
    const got = compareSemver(a, b);
    assert.equal(got === null ? null : Math.sign(got), want, `${a} vs ${b}`);
  }
});

test('dev builds are any non-semver version, including unknown', () => {
  assert.equal(isDevBuild('dev'), true);
  assert.equal(isDevBuild('a8922f4-dirty'), true);
  assert.equal(isDevBuild(null), true);
  assert.equal(isDevBuild('1.3.2'), false);
});

test('eligibility: never a downgrade or same-version update; dev builds manual only', () => {
  type Case = [string | null, string | null, 'manual' | 'auto', boolean];
  const cases: Case[] = [
    ['1.3.2', '1.4.0', 'manual', true],
    ['1.3.2', '1.4.0', 'auto', true],
    ['1.4.0', '1.4.0', 'manual', false], // same version
    ['1.5.0', '1.4.0', 'manual', false], // downgrade
    ['1.10.0', '1.9.0', 'manual', false], // numeric, not lexical
    ['dev', '1.4.0', 'manual', true],
    ['dev', '1.4.0', 'auto', false],
    [null, '1.4.0', 'manual', true],
    [null, '1.4.0', 'auto', false],
    ['1.3.2', '1.4.0-rc1', 'manual', false], // prerelease is never a target
    ['1.3.2', 'v1.4.0', 'manual', false],
    ['1.3.2', null, 'manual', false],
  ];
  for (const [cur, target, mode, want] of cases) {
    assert.equal(checkUpdateEligibility(cur, target, mode).eligible, want, `${cur} -> ${target} (${mode})`);
  }
});

function row(over: Partial<AgentUpdateRow> & { agent_id: string }): AgentUpdateRow {
  return { agent_version: '1.3.0', update_request_id: null, update_target_version: null, update_state: null, ...over };
}

test('selectAgentsToUpdate: auto skips dev builds, current agents and agents with a request for this version', () => {
  const agents = [
    row({ agent_id: 'old' }),
    row({ agent_id: 'current', agent_version: '1.4.0' }),
    row({ agent_id: 'newer', agent_version: '2.0.0' }),
    row({ agent_id: 'dev', agent_version: 'dev' }),
    row({ agent_id: 'pending', update_request_id: REQ, update_target_version: '1.4.0', update_state: 'pending' }),
    row({ agent_id: 'failed', update_request_id: REQ, update_target_version: '1.4.0', update_state: 'failed' }),
    row({ agent_id: 'stale-target', update_request_id: REQ, update_target_version: '1.3.5', update_state: 'installing' }),
  ];
  assert.deepEqual(selectAgentsToUpdate(agents, '1.4.0', 'auto'), ['old', 'stale-target']);
});

test('selectAgentsToUpdate: "update all" also retries failed requests but leaves in-flight ones', () => {
  const agents = [
    row({ agent_id: 'old' }),
    row({ agent_id: 'dev', agent_version: 'dev' }),
    row({ agent_id: 'installing', update_request_id: REQ, update_target_version: '1.4.0', update_state: 'installing' }),
    row({ agent_id: 'failed', update_request_id: REQ, update_target_version: '1.4.0', update_state: 'failed' }),
  ];
  assert.deepEqual(selectAgentsToUpdate(agents, '1.4.0', 'manual-bulk'), ['old', 'failed']);
});

test('parseHeartbeatUpdate accepts a well-formed report', () => {
  const got = parseHeartbeatUpdate({ request_id: REQ.toUpperCase(), version: '1.4.0', state: 'failed', error: 'x'.repeat(900) });
  assert.ok(got);
  assert.equal(got.request_id, REQ);
  assert.equal(got.state, 'failed');
  assert.equal(got.error?.length, 500);
  assert.equal(got.version, '1.4.0');
});

test('parseHeartbeatUpdate rejects malformed input and only keeps error for failed', () => {
  const ok = { request_id: REQ, version: '1.4.0', state: 'installing', error: '' };
  const bad: unknown[] = [
    undefined, null, 'x', [], 42,
    { ...ok, request_id: undefined },
    { ...ok, request_id: 42 },
    { ...ok, request_id: '' },
    { ...ok, request_id: 'a'.repeat(65) },
    { ...ok, request_id: 'not-a-uuid' },
    { ...ok, state: 'pending' }, // server-only state
    { ...ok, state: 'bogus' },
    { ...ok, state: undefined },
    { ...ok, state: 3 },
    { ...ok, error: 7 },
    { ...ok, version: {} },
  ];
  for (const input of bad) assert.equal(parseHeartbeatUpdate(input), null, JSON.stringify(input));
  assert.equal(parseHeartbeatUpdate(ok)?.error, null);
  assert.equal(parseHeartbeatUpdate({ ...ok, state: 'succeeded', error: 'ignored' })?.error, null);
  assert.equal(parseHeartbeatUpdate({ ...ok, version: 'dev' })?.version, null);
});

test('sanitizeAgentVersion keeps a short string only', () => {
  assert.equal(sanitizeAgentVersion(' 1.3.2 '), '1.3.2');
  assert.equal(sanitizeAgentVersion('a'.repeat(65)), undefined);
  assert.equal(sanitizeAgentVersion(''), undefined);
  assert.equal(sanitizeAgentVersion({ toString: () => '1.0.0' }), undefined);
});

test('AgentConfig.agent_update is {version, request_id} or null', () => {
  assert.deepEqual(
    buildAgentUpdateConfig({ update_request_id: REQ, update_target_version: '1.4.0' }),
    { version: '1.4.0', request_id: REQ }
  );
  // A finished request keeps its target for display but has no request id.
  assert.equal(buildAgentUpdateConfig({ update_request_id: null, update_target_version: '1.4.0' }), null);
  assert.equal(buildAgentUpdateConfig(null), null);

  const without = buildAgentConfig(3, 2);
  assert.ok('agent_update' in without);
  assert.equal(without.agent_update, null);
  assert.equal(without.config_version, 5);
  const withUpdate = buildAgentConfig(3, 2, { version: '1.4.0', request_id: REQ });
  assert.deepEqual(withUpdate.agent_update, { version: '1.4.0', request_id: REQ });
});

test('parseLatestRelease: needs a vX.Y.Z tag and a SHA256SUMS asset', () => {
  const assets = [{ name: 'siembox-agent_1.4.0_amd64.deb' }, { name: 'SHA256SUMS' }];
  assert.deepEqual(parseLatestRelease({ tag_name: 'v1.4.0', assets }), { ok: true, version: '1.4.0' });

  const absent = parseLatestRelease({ tag_name: 'v1.4.0', assets: [{ name: 'siembox-agent_1.4.0_amd64.deb' }] });
  assert.equal(absent.ok, false);
  assert.match((absent as { error: string }).error, /SHA256SUMS/);
  // Exact name only.
  assert.equal(parseLatestRelease({ tag_name: 'v1.4.0', assets: [{ name: 'sha256sums' }, { name: 'SHA256SUMS.txt' }] }).ok, false);
  assert.equal(parseLatestRelease({ tag_name: 'v1.4.0' }).ok, false);
});

test('parseLatestRelease rejects non-semver tags, prereleases and junk', () => {
  const assets = [{ name: 'SHA256SUMS' }];
  const bad: unknown[] = [
    { tag_name: 'nightly', assets },
    { tag_name: '1.4.0', assets }, // release tags carry the v
    { tag_name: 'v1.4.0-rc1', assets },
    { tag_name: 'v1.4', assets },
    { tag_name: 'v1.4.0', prerelease: true, assets },
    { tag_name: 'v1.4.0', draft: true, assets },
    { tag_name: 5, assets },
    null, 'x', undefined, {},
  ];
  for (const input of bad) assert.equal(parseLatestRelease(input).ok, false, JSON.stringify(input));
});
