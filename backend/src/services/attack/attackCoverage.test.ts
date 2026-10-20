/**
 * The ATT&CK coverage model (attackCoverage.ts, pure): one fixture per level,
 * the reasons, sub-technique roll-up, exclusions, platform scope and
 * inference, headline numbers and the Navigator layer's shape.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  NAVIGATOR_COLORS,
  allPlatforms,
  buildCoverage,
  buildMatrix,
  buildNavigatorLayer,
  evaluateRule,
  inferPlatforms,
  parsePlatformsParam,
  type CoverageRuleInput,
  type CoverageSampleSource,
  type Exclusion,
  type RuleEvaluation,
} from './attackCoverage';
import { attackDataset } from './attackData';

const WINDOW = { hours: 24 };

const SOURCES: CoverageSampleSource[] = [
  {
    parser_name: 'ssh-authentication',
    samples: [
      { event: 'Accepted password', service: 'sshd', user: 'alice', source_ip: '10.0.0.1' },
      { event: 'Failed password', service: 'sshd', user: 'root', source_ip: '203.0.113.5' },
    ],
  },
  {
    parser_name: 'linux-sudo',
    samples: [{ event_type: 'sudo_command', command: '/usr/bin/apt update', user: 'alice' }],
  },
];

let nextId = 1;
function rule(over: Partial<CoverageRuleInput>): CoverageRuleInput {
  return {
    id: nextId++,
    name: `rule-${nextId}`,
    enabled: true,
    tags: [],
    conditions: [],
    aggregation: null,
    alerts_30d: 0,
    last_alert: null,
    ...over,
  };
}

const SSH_FAILED = [
  { field: 'event', operator: 'contains', value: 'Failed password' },
  { field: 'service', operator: 'equals', value: 'sshd' },
];

test('a disabled rule is disabled, whatever the data', () => {
  const r = evaluateRule(rule({ enabled: false, tags: ['attack.t1110.001'], conditions: SSH_FAILED }), SOURCES, WINDOW);
  assert.equal(r.level, 'disabled');
  assert.equal(r.proven_by, null);
  assert.match(r.reason, /disabled/);
  assert.deepEqual(r.techniques, ['T1110.001']);
});

test('an enabled rule some sample satisfies is covered, naming the parsers and the aggregation', () => {
  const r = evaluateRule(
    rule({
      tags: ['attack.t1110.001'],
      conditions: SSH_FAILED,
      aggregation: { field: 'source_ip', timeframe: '5m', threshold: 5 },
    }),
    SOURCES,
    WINDOW
  );
  assert.equal(r.level, 'covered');
  assert.deepEqual(r.matched_parsers, ['ssh-authentication']);
  assert.match(r.reason, /1 recent log from ssh-authentication satisfies its conditions/);
  assert.match(r.reason, /3 logs sampled from 2 parsers over the last 24 h/);
  assert.match(r.reason, /alerts at 5 matching logs per `source_ip` within 5m/);
});

test('no_data names the condition no sample satisfies', () => {
  const missingField = evaluateRule(
    rule({ tags: ['attack.t1548.003'], conditions: [{ field: 'sudo_target', operator: 'equals', value: 'root' }] }),
    SOURCES,
    WINDOW
  );
  assert.equal(missingField.level, 'no_data');
  assert.match(missingField.reason, /no recent log from your parsers has the field `sudo_target`/);

  const noValue = evaluateRule(
    rule({ tags: ['attack.t1548.003'], conditions: [{ field: 'command', operator: 'contains', value: '/bin/bash' }] }),
    SOURCES,
    WINDOW
  );
  assert.equal(noValue.level, 'no_data');
  assert.match(noValue.reason, /no recent log satisfies `command contains "\/bin\/bash"`/);
  assert.match(noValue.reason, /the field is in 1 sampled log from linux-sudo/);

  const together = evaluateRule(
    rule({
      tags: ['attack.t1110.001'],
      conditions: [
        { field: 'event', operator: 'contains', value: 'Failed' },
        { field: 'user', operator: 'equals', value: 'alice' },
      ],
    }),
    SOURCES,
    WINDOW
  );
  assert.equal(together.level, 'no_data');
  assert.match(together.reason, /no single recent log satisfies all 2 conditions together/);
  assert.match(together.reason, /closest: a ssh-authentication log satisfies 1 of 2/);

  const empty = evaluateRule(rule({ conditions: SSH_FAILED }), [], WINDOW);
  assert.equal(empty.level, 'no_data');
  assert.match(empty.reason, /No parsed logs in the last 24 h/);

  const unsafe = evaluateRule(rule({ conditions: SSH_FAILED, unsafe_regex: true }), SOURCES, WINDOW);
  assert.equal(unsafe.level, 'no_data');
  assert.match(unsafe.reason, /flagged unsafe/);
});

test('an enabled rule that alerted in 30 days is proven by alert, even with no matching sample now', () => {
  const r = evaluateRule(
    rule({ tags: ['attack.t1548.003'], conditions: [{ field: 'nope', operator: 'exists' }], alerts_30d: 3, last_alert: '2026-10-01T00:00:00.000Z' }),
    SOURCES,
    WINDOW
  );
  assert.equal(r.level, 'proven');
  assert.equal(r.proven_by, 'alert');
  assert.match(r.reason, /Raised 3 alerts in the last 30 days, last 2026-10-01/);
  // ...but a disabled rule's old alerts prove nothing about today.
  assert.equal(evaluateRule(rule({ enabled: false, alerts_30d: 3 }), SOURCES, WINDOW).level, 'disabled');
});

test('revoked or unknown technique tags are not counted', () => {
  const r = evaluateRule(rule({ tags: ['attack.t1086', 'attack.t9999', 'attack.credential_access', 'ssh'] }), SOURCES, WINDOW);
  assert.deepEqual(r.techniques, []);
});

function ev(id: number, level: RuleEvaluation['level'], techniques: string[], name = `r${id}`): RuleEvaluation {
  return {
    id,
    name,
    enabled: level !== 'disabled',
    techniques,
    level,
    proven_by: level === 'proven' ? 'alert' : null,
    reason: `${level} because`,
    matched_parsers: [],
    alerts_30d: level === 'proven' ? 1 : 0,
    last_alert: null,
  };
}

function coverage(rules: RuleEvaluation[], platforms = ['Linux'], exclusions: Exclusion[] = []) {
  return buildCoverage({ rules, platforms, exclusions, alertsByTechnique: new Map(), alertsByParent: new Map() });
}

function tech(result: ReturnType<typeof coverage>, id: string) {
  const t = result.techniques.find((x) => x.id === id);
  assert.ok(t, `${id} is in the result`);
  return t;
}

test('one technique per level: none / disabled / no_data / covered / proven, best rule wins', () => {
  const result = coverage([
    ev(1, 'disabled', ['T1046']),
    ev(2, 'no_data', ['T1021.004']),
    ev(3, 'disabled', ['T1021.004']),
    ev(4, 'covered', ['T1505.003']),
    ev(5, 'no_data', ['T1505.003']),
    ev(6, 'proven', ['T1548.003']),
  ]);
  assert.equal(tech(result, 'T1098').level, 'none');
  assert.equal(tech(result, 'T1046').level, 'disabled');
  assert.equal(tech(result, 'T1021.004').level, 'no_data');
  assert.equal(tech(result, 'T1505.003').level, 'covered');
  assert.equal(tech(result, 'T1548.003').level, 'proven');
  assert.equal(tech(result, 'T1548.003').proven_by, 'alert');
  // Rules are listed best first, each with its own reason.
  assert.deepEqual(
    tech(result, 'T1505.003').rules.map((r) => [r.id, r.level, r.reason]),
    [
      [4, 'covered', 'covered because'],
      [5, 'no_data', 'no_data because'],
    ]
  );
  assert.equal(result.rules.tagged, 6);
  assert.deepEqual(result.rules.by_level, { disabled: 2, no_data: 2, covered: 1, proven: 1 });
});

test('sub-techniques roll up into the parent; tagging the parent covers only the parent', () => {
  const result = coverage([ev(1, 'covered', ['T1110.001']), ev(2, 'covered', ['T1059'])], ['Linux']);
  const parent = tech(result, 'T1110');
  assert.equal(parent.level, 'covered');
  assert.equal(parent.subtechniques!.covered, 1);
  assert.equal(parent.subtechniques!.total, 4);
  assert.deepEqual(parent.rules.map((r) => r.technique_id), ['T1110.001']);
  assert.equal(tech(result, 'T1110.003').level, 'none');

  const shell = tech(result, 'T1059');
  assert.equal(shell.level, 'covered');
  assert.equal(shell.subtechniques!.covered, 0);
  assert.equal(tech(result, 'T1059.004').level, 'none');
  // Sub-techniques follow their parent in the list.
  const ids = result.techniques.map((t) => t.id);
  assert.equal(ids[ids.indexOf('T1110') + 1], 'T1110.001');
});

test('the parent takes the best of its own rules and its sub-techniques', () => {
  const result = coverage([ev(1, 'disabled', ['T1110']), ev(2, 'proven', ['T1110.003'])]);
  assert.equal(tech(result, 'T1110').level, 'proven');
  assert.equal(tech(result, 'T1110').subtechniques!.covered, 1);
});

test('excluded techniques keep their level, leave the percentages, and a parent exclusion covers its subs', () => {
  const rules = [ev(1, 'covered', ['T1548.003']), ev(2, 'covered', ['T1110.001'])];
  const before = coverage(rules);
  const exclusions: Exclusion[] = [
    { technique_id: 'T1548', note: 'no sudo here', created_by: 'alice', created_at: null },
    { technique_id: 'T1110.003', note: null, created_by: null, created_at: null },
  ];
  const after = coverage(rules, ['Linux'], exclusions);

  const abuse = tech(after, 'T1548');
  assert.equal(abuse.excluded, true);
  assert.equal(abuse.exclusion!.note, 'no sudo here');
  assert.equal(abuse.level, 'none', 'its only sub-technique is excluded with it, so nothing rolls up');
  const sudo = tech(after, 'T1548.003');
  assert.equal(sudo.excluded, true);
  assert.equal(sudo.exclusion!.inherited_from, 'T1548');
  assert.equal(sudo.level, 'covered');

  const brute = tech(after, 'T1110');
  assert.equal(brute.excluded, false);
  assert.equal(brute.subtechniques!.total, 3);
  assert.equal(brute.subtechniques!.excluded, 1);

  assert.equal(after.summary.in_scope, before.summary.in_scope);
  assert.equal(after.summary.excluded, 1);
  assert.equal(after.summary.counted, before.summary.counted - 1);
  assert.equal(after.summary.covered, before.summary.covered - 1);
  const privEsc = after.tactics.find((t) => t.shortname === 'privilege-escalation')!;
  assert.equal(privEsc.excluded, 1);
});

test('headline numbers: % of counted parent techniques at covered or better, per tactic and overall', () => {
  const result = coverage([ev(1, 'covered', ['T1110.001']), ev(2, 'proven', ['T1021.004']), ev(3, 'no_data', ['T1046'])]);
  const cred = result.tactics.find((t) => t.shortname === 'credential-access')!;
  assert.equal(cred.covered, 1);
  assert.equal(cred.percent, Math.round((1 / cred.counted) * 1000) / 10);
  const disc = result.tactics.find((t) => t.shortname === 'discovery')!;
  assert.equal(disc.covered, 0);
  assert.equal(disc.by_level.no_data, 1);
  assert.equal(result.summary.covered, 2);
  assert.equal(result.summary.proven, 1);
  assert.equal(result.summary.percent, Math.round((2 / result.summary.counted) * 1000) / 10);
  // 15 tactics, in matrix order.
  assert.deepEqual(
    result.tactics.map((t) => t.order),
    [...attackDataset().tactics].map((t) => t.order).sort((a, b) => a - b)
  );
  // A tactic with nothing in scope has no percentage rather than 0%.
  const pre = coverage([], ['Windows']).tactics.find((t) => t.shortname === 'reconnaissance')!;
  assert.equal(pre.counted, 0);
  assert.equal(pre.percent, null);
});

test('the platform scope filters techniques', () => {
  const linux = coverage([ev(1, 'covered', ['T1547.001'])], ['Linux']);
  assert.equal(linux.techniques.some((t) => t.id === 'T1547.001'), false, 'a Windows-only technique is out of a Linux scope');
  assert.equal(linux.rules.tagged, 1);
  const windows = coverage([ev(1, 'covered', ['T1547.001'])], ['Windows']);
  assert.equal(tech(windows, 'T1547.001').level, 'covered');
  assert.equal(windows.techniques.some((t) => t.id === 'T1548.003'), false);
  const pre = coverage([], ['PRE']);
  assert.ok(pre.techniques.some((t) => t.id === 'T1595'));
  assert.ok(pre.summary.in_scope < linux.summary.in_scope);
});

test('the matrix lists in-scope techniques per tactic, in tactic order, with the dataset version', () => {
  const m = buildMatrix(['Linux']);
  assert.equal(m.attack_version, attackDataset().version);
  assert.equal(m.tactics.length, attackDataset().tactics.length);
  assert.deepEqual(
    m.tactics.map((t) => t.order),
    m.tactics.map((t) => t.order).slice().sort((a, b) => a - b)
  );
  const cred = m.tactics.find((t) => t.shortname === 'credential-access')!;
  const brute = cred.techniques.find((t) => t.id === 'T1110')!;
  assert.ok(brute.subtechniques.some((s) => s.id === 'T1110.001'));
  const all = m.tactics.flatMap((t) => t.techniques.map((x) => x.id));
  assert.equal(all.includes('T1547'), true);
  assert.equal(
    m.tactics.flatMap((t) => t.techniques.flatMap((x) => x.subtechniques.map((s) => s.id))).includes('T1547.001'),
    false
  );
  assert.equal(all.includes('T1086'), false, 'revoked techniques are left out');
});

test('parsePlatformsParam: names any case, aliases, all, and unknown names refused', () => {
  assert.deepEqual(parsePlatformsParam(undefined), { platforms: null });
  assert.deepEqual(parsePlatformsParam(''), { platforms: null });
  assert.deepEqual(parsePlatformsParam('linux, Network'), { platforms: ['Linux', 'Network Devices'] });
  assert.deepEqual(parsePlatformsParam('windows,WINDOWS'), { platforms: ['Windows'] });
  assert.deepEqual(parsePlatformsParam('all'), { platforms: allPlatforms() });
  const bad = parsePlatformsParam('Linux,Amiga');
  assert.ok('error' in bad && /unknown platform "Amiga"/.test(bad.error));
  assert.ok('error' in parsePlatformsParam(['Linux', 'Windows']));
});

test('inferPlatforms maps parsers, assets, agents and containers; falls back to the default', () => {
  const inferred = inferPlatforms({
    parsers: [
      { name: 'ssh-authentication', event_type: 'ssh_auth', logs_7d: 100 },
      { name: 'netfilter-firewall', event_type: 'firewall_event', logs_7d: 5 },
      { name: 'pihole-query', event_type: 'dns_query', logs_7d: 5 },
      { name: 'authentik-audit', event_type: 'authentik_audit', logs_7d: 5 },
      { name: 'plex', event_type: 'plex_event', logs_7d: 5 },
      { name: 'windows-security', event_type: 'win_event', logs_7d: 0 },
    ],
    asset_os: [{ os: 'Microsoft Windows 11', count: 2 }],
    agent_os: [{ os: 'darwin', count: 1 }],
    shipper_containers: 4,
  });
  assert.deepEqual(inferred.platforms, ['Containers', 'Identity Provider', 'Linux', 'macOS', 'Network Devices', 'Windows']);
  const linux = inferred.inferred_from.find((e) => e.platform === 'Linux' && e.source === 'parsers')!;
  assert.deepEqual(linux.items, ['ssh-authentication']);
  const net = inferred.inferred_from.find((e) => e.platform === 'Network Devices')!;
  assert.deepEqual(net.items, ['netfilter-firewall', 'pihole-query']);
  assert.ok(inferred.inferred_from.some((e) => e.platform === 'Windows' && e.source === 'assets'));
  assert.ok(inferred.inferred_from.some((e) => e.platform === 'macOS' && e.source === 'endpoint_agents'));
  assert.ok(inferred.inferred_from.some((e) => e.platform === 'Containers' && e.source === 'shipper_containers'));
  assert.deepEqual(inferred.unmapped_parsers, ['plex'], 'a parser with no logs in 7 days is not evidence');

  const none = inferPlatforms({ parsers: [], asset_os: [], agent_os: [], shipper_containers: 0 });
  assert.deepEqual(none.platforms, ['Containers', 'Linux', 'Network Devices']);
  assert.ok(none.inferred_from.every((e) => e.source === 'default'));
});

test('the Navigator layer: format 4.5, enterprise-attack, scores and colours by level, excluded disabled', () => {
  const result = coverage(
    [ev(1, 'covered', ['T1110.001'], 'SSH Brute Force'), ev(2, 'disabled', ['T1046'], 'Port scan'), ev(3, 'proven', ['T1021.004'], 'SSH lateral')],
    ['Linux', 'Network Devices'],
    [{ technique_id: 'T1098', note: 'single-user box', created_by: null, created_at: null }]
  );
  const layer = buildNavigatorLayer(result, { generatedAt: '2026-10-20T00:00:00.000Z' }) as any;
  assert.equal(layer.domain, 'enterprise-attack');
  assert.deepEqual(layer.versions, { attack: attackDataset().version.split('.')[0], navigator: '5.1.0', layer: '4.5' });
  assert.equal(typeof layer.name, 'string');
  assert.deepEqual(layer.filters, { platforms: ['Linux', 'Network Devices'] });
  assert.equal(layer.gradient.minValue, 1);
  assert.equal(layer.gradient.maxValue, 4);
  assert.ok(Array.isArray(layer.legendItems) && layer.legendItems.length === 4);
  for (const t of layer.techniques) {
    assert.match(t.techniqueID, /^T\d{4}(\.\d{3})?$/);
    assert.equal(typeof t.enabled, 'boolean');
    assert.equal(typeof t.comment, 'string');
    assert.equal('tactic' in t, false, 'one entry per technique applies to every tactic');
  }
  const byId = new Map(layer.techniques.map((t: any) => [t.techniqueID, t]));
  const sub = byId.get('T1110.001') as any;
  assert.equal(sub.score, 3);
  assert.equal(sub.color, NAVIGATOR_COLORS.covered);
  assert.match(sub.comment, /SSH Brute Force \(covered\)/);
  const parent = byId.get('T1110') as any;
  assert.match(parent.comment, /1 of 4 sub-techniques covered/);
  assert.equal((byId.get('T1021.004') as any).score, 4);
  assert.equal((byId.get('T1046') as any).score, 1);
  const excluded = byId.get('T1098') as any;
  assert.equal(excluded.enabled, false);
  assert.equal('score' in excluded, false);
  assert.match(excluded.comment, /Not applicable: single-user box/);
  assert.equal(byId.has('T1059'), false, 'techniques with no rule are left out');
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(layer)));
});
