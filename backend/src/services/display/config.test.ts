/**
 * Display configs and link inputs (services/display/config.ts), and the
 * admin list's status (linkStatus.ts). Pure. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  LIMITS,
  PANEL_IDS,
  PANEL_KINDS,
  canonicalTimeZone,
  configPanelKeys,
  describeDisplay,
  normalizeCidr,
  panelKey,
  parseAllowedCidrs,
  parseCreateLink,
  parseDisplayConfig,
  parseExpiresAt,
  parseLinkName,
  parseUpdateLink,
  type DisplayConfig,
  type Invalid,
  type PanelSpec,
} from './config';
import { displayLinkStatus, liveWindowSeconds } from './linkStatus';

const NOW = new Date('2026-10-16T12:00:00Z');
const one = (panels: unknown[], extra: Record<string, unknown> = {}) => ({ views: [{ title: 'Overview', panels }], ...extra });

function ok(input: unknown, options?: Parameters<typeof parseDisplayConfig>[1]): DisplayConfig {
  const result = parseDisplayConfig(input, options);
  assert.ok(result.ok, `expected a valid config, got ${JSON.stringify(result)}`);
  return result.value;
}

function refused(input: unknown, field: string, message?: RegExp, options?: Parameters<typeof parseDisplayConfig>[1]): Invalid {
  const result = parseDisplayConfig(input, options);
  assert.equal(result.ok, false, `expected a refusal at ${field}`);
  const invalid = result as Invalid;
  assert.equal(invalid.code, 'DISPLAY_CONFIG_INVALID');
  assert.equal(invalid.field, field, invalid.message);
  if (message) assert.match(invalid.message, message);
  return invalid;
}

test('defaults: operations privacy, 30 s refresh, rotation every 20 s, screen time zone, clock and burn-in shift on', () => {
  const config = ok(one([{ id: 'open_alerts' }]));
  assert.deepEqual(config, {
    privacy: 'operations',
    refresh_seconds: 30,
    rotation: { enabled: true, seconds: 20 },
    timezone: null,
    clock: true,
    burn_in_shift: true,
    views: [{ title: 'Overview', panels: [{ id: 'open_alerts' }] }],
  });
});

test('every panel kind and every variant, with its key; variants default', () => {
  const variants: Record<string, Array<[unknown, string]>> = {
    recent_alerts: [
      [undefined, 'recent_alerts:high'],
      ['critical', 'recent_alerts:critical'],
      ['high', 'recent_alerts:high'],
      ['medium', 'recent_alerts:medium'],
    ],
    top_rules: [
      [undefined, 'top_rules:24'],
      [1, 'top_rules:1'],
      [24, 'top_rules:24'],
    ],
    sources: [
      [undefined, 'sources:15'],
      [5, 'sources:5'],
      [15, 'sources:15'],
      [30, 'sources:30'],
      [60, 'sources:60'],
    ],
    threat_map: [
      [undefined, 'threat_map:1'],
      [1, 'threat_map:1'],
      [7, 'threat_map:7'],
      [30, 'threat_map:30'],
    ],
  };
  assert.deepEqual(PANEL_IDS.sort(), [
    'alert_pulse',
    'digital_risk',
    'endpoints',
    'ingest',
    'open_alerts',
    'recent_alerts',
    'shippers',
    'sources',
    'threat_map',
    'top_rules',
    'top_sources',
    'vulnerabilities',
  ]);
  for (const id of PANEL_IDS) {
    const kind = PANEL_KINDS[id];
    if (!kind.param) {
      const forLink = id !== 'endpoints';
      const config = ok(one([{ id }]), { forLink });
      assert.deepEqual(config.views[0].panels, [{ id }]);
      assert.equal(panelKey(config.views[0].panels[0]), id, 'variant-free keys are bare');
      continue;
    }
    assert.ok(variants[id], `test the variants of ${id}`);
    for (const [value, key] of variants[id]) {
      const panel = value === undefined ? { id } : { id, [kind.param.name]: value };
      const config = ok(one([panel]));
      assert.equal(panelKey(config.views[0].panels[0]), key);
      assert.equal((config.views[0].panels[0] as unknown as Record<string, unknown>)[kind.param.name], value ?? kind.param.default);
    }
    for (const bad of ['24', 0, 2, 'low', null, true, 1.5]) {
      if (kind.param.values.includes(bad as string | number)) continue;
      refused(one([{ id, [kind.param.name]: bad }]), `config.views[0].panels[0].${kind.param.name}`, /must be one of/);
    }
  }
});

test('unknown keys are refused with the path of the field, at every level', () => {
  refused({ ...one([{ id: 'ingest' }]), theme: 'light' }, 'config.theme', /not a display setting/);
  refused(one([{ id: 'ingest' }], { rotation: { enabled: true, speed: 3 } }), 'config.rotation.speed');
  refused({ views: [{ title: 'A', panels: [{ id: 'ingest' }], layout: 'grid' }] }, 'config.views[0].layout');
  refused(one([{ id: 'open_alerts' }, { id: 'ingest', window_days: 7 }]), 'config.views[0].panels[1].window_days', /not an option of "ingest"/);
  refused(one([{ id: 'threat_map', window_hours: 1 }]), 'config.views[0].panels[0].window_hours');
  refused(one([{ id: 'ingest', sql: 'SELECT 1' }]), 'config.views[0].panels[0].sql');
  refused(one([{ id: 'raw_logs' }]), 'config.views[0].panels[0].id', /must be one of/);
  refused(one([{}]), 'config.views[0].panels[0].id');
  refused(one(['open_alerts']), 'config.views[0].panels[0]', /must be an object/);
  refused({ views: [{ title: 'A', panels: [{ id: 'ingest' }] }, { title: 'B', panels: [{ id: 'nope' }] }] }, 'config.views[1].panels[0].id');
  // A caller-chosen prefix for messages
  refused({ x: 1 }, 'preview.x', undefined, { path: 'preview' });
});

test('bounds: views, panels per view, titles, refresh, rotation, flags, privacy', () => {
  const view = (i: number) => ({ title: `View ${i}`, panels: [{ id: 'open_alerts' }] });
  ok({ views: Array.from({ length: 6 }, (_, i) => view(i)) });
  refused({ views: Array.from({ length: 7 }, (_, i) => view(i)) }, 'config.views', /at most 6 views/);
  refused({ views: [] }, 'config.views');
  refused({}, 'config.views');
  refused({ views: 'all' }, 'config.views');
  refused({ views: [null] }, 'config.views[0]');

  const six = ['open_alerts', 'alert_pulse', 'ingest', 'shippers', 'digital_risk', 'vulnerabilities'].map((id) => ({ id }));
  ok(one(six));
  refused(one([...six, { id: 'top_sources' }]), 'config.views[0].panels', /at most 6 panels/);
  refused(one([]), 'config.views[0].panels');

  assert.equal(ok({ views: [{ title: '  NOC wall  ', panels: [{ id: 'ingest' }] }] }).views[0].title, 'NOC wall', 'trimmed');
  ok({ views: [{ title: 'x'.repeat(40), panels: [{ id: 'ingest' }] }] });
  ok({ views: [{ title: '🛡'.repeat(40), panels: [{ id: 'ingest' }] }] }, undefined);
  refused({ views: [{ title: 'x'.repeat(41), panels: [{ id: 'ingest' }] }] }, 'config.views[0].title', /at most 40/);
  refused({ views: [{ title: '   ', panels: [{ id: 'ingest' }] }] }, 'config.views[0].title', /required/);
  refused({ views: [{ title: 'a\nb', panels: [{ id: 'ingest' }] }] }, 'config.views[0].title', /control characters/);
  refused({ views: [{ title: 'a b', panels: [{ id: 'ingest' }] }] }, 'config.views[0].title', /control characters/);
  refused({ views: [{ panels: [{ id: 'ingest' }] }] }, 'config.views[0].title');
  refused({ views: [{ title: 5, panels: [{ id: 'ingest' }] }] }, 'config.views[0].title');

  for (const refresh of [15, 30, 60, 120]) assert.equal(ok(one([{ id: 'ingest' }], { refresh_seconds: refresh })).refresh_seconds, refresh);
  for (const refresh of [0, 10, 45, '30', null]) refused(one([{ id: 'ingest' }], { refresh_seconds: refresh }), 'config.refresh_seconds');

  assert.deepEqual(ok(one([{ id: 'ingest' }], { rotation: { seconds: 10 } })).rotation, { enabled: true, seconds: 10 });
  assert.deepEqual(ok(one([{ id: 'ingest' }], { rotation: { enabled: false, seconds: 600 } })).rotation, { enabled: false, seconds: 600 });
  for (const seconds of [9, 601, 20.5, '20', -1]) refused(one([{ id: 'ingest' }], { rotation: { seconds } }), 'config.rotation.seconds');
  refused(one([{ id: 'ingest' }], { rotation: { enabled: 'yes' } }), 'config.rotation.enabled');
  refused(one([{ id: 'ingest' }], { rotation: true }), 'config.rotation');

  for (const flag of ['clock', 'burn_in_shift']) {
    assert.equal((ok(one([{ id: 'ingest' }], { [flag]: false })) as unknown as Record<string, unknown>)[flag], false);
    refused(one([{ id: 'ingest' }], { [flag]: 'off' }), `config.${flag}`);
  }

  assert.equal(ok(one([{ id: 'ingest' }], { privacy: 'public' })).privacy, 'public');
  refused(one([{ id: 'ingest' }], { privacy: 'lobby' }), 'config.privacy');
  refused('views', 'config', /must be an object/);
  refused(null, 'config');
  refused([], 'config');
});

test('a panel key appears once per view, and a config shows at most 12 distinct panels', () => {
  refused(one([{ id: 'open_alerts' }, { id: 'open_alerts' }]), 'config.views[0].panels[1]', /"open_alerts" is already in this view/);
  refused(one([{ id: 'recent_alerts' }, { id: 'recent_alerts', min_severity: 'high' }]), 'config.views[0].panels[1]', /recent_alerts:high/);
  // Different variants are different panels; the same panel in two views is fine.
  ok(one([{ id: 'top_rules', window_hours: 1 }, { id: 'top_rules', window_hours: 24 }]));
  const repeated = ok({
    views: [
      { title: 'A', panels: [{ id: 'open_alerts' }, { id: 'ingest' }] },
      { title: 'B', panels: [{ id: 'ingest' }, { id: 'open_alerts' }] },
    ],
  });
  assert.deepEqual(configPanelKeys(repeated), ['open_alerts', 'ingest']);

  const twelve: PanelSpec[][] = [
    [{ id: 'open_alerts' }, { id: 'alert_pulse' }, { id: 'ingest' }, { id: 'shippers' }, { id: 'digital_risk' }, { id: 'vulnerabilities' }],
    [
      { id: 'top_sources' },
      { id: 'recent_alerts', min_severity: 'critical' },
      { id: 'recent_alerts', min_severity: 'high' },
      { id: 'top_rules', window_hours: 1 },
      { id: 'sources', silent_after_minutes: 5 },
      { id: 'threat_map', window_days: 7 },
    ],
  ];
  const config = ok({ views: twelve.map((panels, i) => ({ title: `V${i}`, panels })) });
  assert.equal(configPanelKeys(config).length, 12);
  const thirteen = [...twelve, [{ id: 'threat_map', window_days: 30 }]];
  refused({ views: thirteen.map((panels, i) => ({ title: `V${i}`, panels })) }, 'config.views', /at most 12 different panels \(this one has 13\)/);
});

test('a serialized config over 16 kB is refused before anything else', () => {
  const big = { views: [{ title: 'A', panels: [{ id: 'ingest' }] }], padding: 'x'.repeat(LIMITS.configBytes) };
  refused(big, 'config', /at most 16 kB/);
  // Counted in bytes, not characters
  const multibyte = { views: [{ title: 'A', panels: [{ id: 'ingest' }] }], pad: 'é'.repeat(8200) };
  refused(multibyte, 'config', /16 kB/);
});

test('time zones: IANA names (canonicalized), UTC, or null; anything else is refused', () => {
  assert.equal(ok(one([{ id: 'ingest' }], { timezone: 'Europe/London' })).timezone, 'Europe/London');
  assert.equal(ok(one([{ id: 'ingest' }], { timezone: 'UTC' })).timezone, 'UTC');
  assert.equal(ok(one([{ id: 'ingest' }], { timezone: 'America/New_York' })).timezone, 'America/New_York');
  assert.equal(ok(one([{ id: 'ingest' }], { timezone: null })).timezone, null);
  assert.ok(canonicalTimeZone('Asia/Kolkata'));
  for (const bad of ['Mars/Olympus', 'Europe/Londn', '+01:00', '', 'Europe/London; DROP', 'x'.repeat(80), 5]) {
    refused(one([{ id: 'ingest' }], { timezone: bad }), 'config.timezone', undefined);
  }
});

test('endpoint health is refused in link configs, allowed for the signed-in board', () => {
  refused(one([{ id: 'endpoints' }]), 'config.views[0].panels[0].id', /Endpoint health is admin-only and can't be shown on a display link in this version\./);
  assert.equal(ok(one([{ id: 'endpoints' }]), { forLink: false }).views[0].panels[0].id, 'endpoints');
  // Only admin-only kinds are refused, and endpoints is the only one today.
  assert.deepEqual(
    PANEL_IDS.filter((id) => PANEL_KINDS[id].minRole !== 'viewer'),
    ['endpoints']
  );
});

test('public-area displays refuse the label lists (top rules, top sources)', () => {
  for (const panel of [{ id: 'top_rules' }, { id: 'top_rules', window_hours: 1 }, { id: 'top_sources' }]) {
    refused(one([{ id: 'open_alerts' }, panel], { privacy: 'public' }), 'config.views[0].panels[1].id', /not available on a public-area display/);
    ok(one([{ id: 'open_alerts' }, panel], { privacy: 'operations' }));
  }
  // Everything else a link may show is allowed in public mode.
  for (const id of PANEL_IDS.filter((p) => PANEL_KINDS[p].publicAllowed)) ok(one([{ id }], { privacy: 'public' }));
});

test('describeDisplay is the layout with panel keys', () => {
  const config = ok({
    privacy: 'public',
    refresh_seconds: 60,
    timezone: 'UTC',
    views: [{ title: 'Lobby', panels: [{ id: 'open_alerts' }, { id: 'threat_map', window_days: 7 }] }],
  });
  assert.deepEqual(describeDisplay('Lobby TV', 3, config), {
    name: 'Lobby TV',
    config_version: 3,
    privacy: 'public',
    refresh_seconds: 60,
    rotation: { enabled: true, seconds: 20 },
    timezone: 'UTC',
    clock: true,
    burn_in_shift: true,
    views: [{ title: 'Lobby', panels: ['open_alerts', 'threat_map:7'] }],
  });
});

test('CIDRs: addresses and networks, normalized to network form', () => {
  const cases: Array<[string, string]> = [
    ['10.20.30.12', '10.20.30.12/32'],
    ['10.20.30.12/16', '10.20.0.0/16'],
    [' 192.168.1.0/24 ', '192.168.1.0/24'],
    ['0.0.0.0/0', '0.0.0.0/0'],
    ['172.16.5.4/12', '172.16.0.0/12'],
    ['10.255.255.255/9', '10.128.0.0/9'],
    ['2001:DB8::1', '2001:db8::1/128'],
    ['2001:db8:1:2:3:4:5:6/64', '2001:db8:1:2::/64'],
    ['2001:db8::/32', '2001:db8::/32'],
    ['fd00:0:0:0:0:0:0:1/127', 'fd00::/127'],
    ['::/0', '::/0'],
    ['::1', '::1/128'],
    ['1:0:0:2:0:0:0:3', '1:0:0:2::3/128'],
    ['::ffff:10.1.2.3', '10.1.2.3/32'],
    ['::ffff:10.1.2.3/120', '10.1.2.0/24'],
    ['64:ff9b::192.0.2.1/128', '64:ff9b::c000:201/128'],
  ];
  for (const [input, expected] of cases) assert.equal(normalizeCidr(input), expected, input);
  for (const bad of ['10.0.0.0/33', '2001:db8::/129', '10.0.0', '10.0.0.0/', '10.0.0.0/-1', '10.0.0.0/8/8', 'fe80::1%eth0', 'example.com', '', '10.0.0.0/08x', '256.0.0.1']) {
    assert.equal(normalizeCidr(bad), null, bad);
  }
  assert.deepEqual(parseAllowedCidrs(['10.20.30.12/16', '10.20.0.0/16', '192.168.1.5']), {
    ok: true,
    value: ['10.20.0.0/16', '192.168.1.5/32'],
  });
  assert.deepEqual(parseAllowedCidrs([]), { ok: true, value: [] });
  const bad = parseAllowedCidrs(['10.0.0.0/8', 'nope']) as Invalid;
  assert.deepEqual([bad.ok, bad.code, bad.field], [false, 'DISPLAY_LINK_BAD_REQUEST', 'allowed_cidrs[1]']);
  assert.equal((parseAllowedCidrs('10.0.0.0/8') as Invalid).field, 'allowed_cidrs');
  assert.equal((parseAllowedCidrs([5]) as Invalid).field, 'allowed_cidrs[0]');
  const many = Array.from({ length: 33 }, (_, i) => `10.0.${i}.0/24`);
  assert.match((parseAllowedCidrs(many) as Invalid).message, /at most 32/);
  assert.equal(parseAllowedCidrs(many.slice(0, 32)).ok, true);
});

test('expires_at: null is never; a date must be ISO 8601 and in the future', () => {
  assert.deepEqual(parseExpiresAt(null, NOW), { ok: true, value: null });
  const future = parseExpiresAt('2027-03-01T09:00:00Z', NOW);
  assert.ok(future.ok && future.value?.toISOString() === '2027-03-01T09:00:00.000Z');
  assert.ok(parseExpiresAt('2026-10-17', NOW).ok);
  assert.ok(parseExpiresAt('2026-10-16T13:00:00+00:30', NOW).ok, '12:30 UTC');
  assert.equal(parseExpiresAt('2026-10-16T13:00:00+01:30', NOW).ok, false, '11:30 UTC, in the past');
  for (const past of ['2026-10-16T12:00:00Z', '2026-10-16T11:59:59Z', '2020-01-01']) {
    const result = parseExpiresAt(past, NOW) as Invalid;
    assert.equal(result.ok, false, past);
    assert.equal(result.field, 'expires_at');
    assert.match(result.message, /in the future/);
  }
  for (const bad of ['3 Nov', 'tomorrow', '2026-13-45', '2027-02-30T25:00:00Z', 1767225600000, '', 'x'.repeat(50), true]) {
    const result = parseExpiresAt(bad, NOW) as Invalid;
    assert.equal(result.ok, false, String(bad));
    assert.equal(result.code, 'DISPLAY_LINK_BAD_REQUEST');
  }
});

test('link names: trimmed, 1..80 characters, no control characters', () => {
  assert.deepEqual(parseLinkName('  NOC wall left '), { ok: true, value: 'NOC wall left' });
  assert.ok(parseLinkName('x'.repeat(80)).ok);
  for (const bad of ['', '   ', 'x'.repeat(81), 'a\tb', 42, null]) {
    const result = parseLinkName(bad) as Invalid;
    assert.equal(result.ok, false, String(bad));
    assert.equal(result.field, 'name');
    assert.equal(result.code, 'DISPLAY_LINK_BAD_REQUEST');
  }
});

test('create and update bodies: known fields only; update needs at least one', () => {
  const config = one([{ id: 'open_alerts' }]);
  const created = parseCreateLink({ name: 'NOC', config }, NOW);
  assert.ok(created.ok);
  assert.deepEqual(
    { expiresAt: created.value.expiresAt, allowedCidrs: created.value.allowedCidrs, privacy: created.value.config.privacy },
    { expiresAt: null, allowedCidrs: [], privacy: 'operations' }
  );
  const full = parseCreateLink({ name: 'NOC', config, expires_at: '2027-01-01', allowed_cidrs: ['10.0.0.1/8'] }, NOW);
  assert.ok(full.ok && full.value.allowedCidrs[0] === '10.0.0.0/8' && full.value.expiresAt !== null);

  const cases: Array<[unknown, string, string]> = [
    [{ config }, 'name', 'DISPLAY_LINK_BAD_REQUEST'],
    [{ name: 'NOC' }, 'config', 'DISPLAY_CONFIG_INVALID'],
    [{ name: 'NOC', config, token: 'sbd1_x' }, 'token', 'DISPLAY_LINK_BAD_REQUEST'],
    [{ name: 'NOC', config, enabled: false }, 'enabled', 'DISPLAY_LINK_BAD_REQUEST'],
    [{ name: 'NOC', config: { views: [] } }, 'config.views', 'DISPLAY_CONFIG_INVALID'],
    [{ name: 'NOC', config, expires_at: '2020-01-01' }, 'expires_at', 'DISPLAY_LINK_BAD_REQUEST'],
    [{ name: 'NOC', config, allowed_cidrs: ['x'] }, 'allowed_cidrs[0]', 'DISPLAY_LINK_BAD_REQUEST'],
    [[], 'body', 'DISPLAY_LINK_BAD_REQUEST'],
  ];
  for (const [body, field, code] of cases) {
    const result = parseCreateLink(body, NOW) as Invalid;
    assert.deepEqual([result.ok, result.field, result.code], [false, field, code], JSON.stringify(body));
  }

  assert.deepEqual(parseUpdateLink({ enabled: false }, NOW), { ok: true, value: { enabled: false } });
  assert.deepEqual(parseUpdateLink({ expires_at: null, allowed_cidrs: [] }, NOW), { ok: true, value: { expiresAt: null, allowedCidrs: [] } });
  const renamed = parseUpdateLink({ name: ' Lobby ', config }, NOW);
  assert.ok(renamed.ok && renamed.value.name === 'Lobby' && renamed.value.config?.views.length === 1);
  for (const [body, field] of [
    [{}, 'body'],
    [{ enabled: 'no' }, 'enabled'],
    [{ revoked_at: null }, 'revoked_at'],
    [{ config: { views: [{ title: 'A', panels: [{ id: 'endpoints' }] }] } }, 'config.views[0].panels[0].id'],
    [{ expires_at: '2026-10-15' }, 'expires_at'],
  ] as Array<[unknown, string]>) {
    const result = parseUpdateLink(body, NOW) as Invalid;
    assert.deepEqual([result.ok, result.field], [false, field], JSON.stringify(body));
  }
});

test('status: revoked, expired, paused, never used, live within its window, idle after', () => {
  const base = { revoked_at: null, expires_at: null, enabled: true, last_used_at: null };
  const ago = (seconds: number) => new Date(NOW.getTime() - seconds * 1000);
  assert.equal(displayLinkStatus({ ...base, revoked_at: ago(1), enabled: false }, 30, NOW), 'revoked');
  assert.equal(displayLinkStatus({ ...base, expires_at: NOW, enabled: false }, 30, NOW), 'expired');
  assert.equal(displayLinkStatus({ ...base, expires_at: new Date(NOW.getTime() + 1000) }, 30, NOW), 'never_used');
  assert.equal(displayLinkStatus({ ...base, enabled: false, last_used_at: ago(1) }, 30, NOW), 'paused');
  assert.equal(displayLinkStatus(base, 30, NOW), 'never_used');
  // Uses are written at most once a minute, so a 15 s screen stays live for 90 s.
  assert.equal(liveWindowSeconds(15), 90);
  assert.equal(liveWindowSeconds(30), 120);
  assert.equal(liveWindowSeconds(120), 360);
  assert.equal(displayLinkStatus({ ...base, last_used_at: ago(89) }, 15, NOW), 'live');
  assert.equal(displayLinkStatus({ ...base, last_used_at: ago(91) }, 15, NOW), 'idle');
  assert.equal(displayLinkStatus({ ...base, last_used_at: ago(359) }, 120, NOW), 'live');
  assert.equal(displayLinkStatus({ ...base, last_used_at: ago(3600) }, 120, NOW), 'idle');
});
