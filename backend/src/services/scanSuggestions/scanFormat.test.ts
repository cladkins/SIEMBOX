/**
 * The suggested-scan format: what validate-scans accepts and refuses (schema,
 * schedule, options per kind, inputs, no concrete targets, honest
 * intrusiveness). Pure. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { containsAddress, containsHostname, crossCheckSuggestions, selectionMayBeIntrusive, validateSuggestion, withTimezone } from './scanFormat';

const base = {
  schema: 'siembox.scan/v1',
  id: 'asset-test',
  name: 'Test sweep',
  kind: 'asset',
  category: 'inventory',
  description: 'A sweep.',
  why: 'Because.',
  intrusive: false,
  load: 'light',
  schedule: { frequency: 'daily', time: '02:30' },
  options: { scanType: 'ping' },
  inputs: [{ field: 'targets', label: 'Subnets', hint: 'Your subnets in CIDR form.' }],
};

const vuln = (sel: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
  ...base,
  id: 'vuln-test',
  kind: 'vulnerability',
  category: 'cves',
  options: { templateSelection: sel },
  inputs: [{ field: 'target' }],
  ...extra,
});

function errors(doc: unknown, strict = true): string {
  return validateSuggestion(doc, { strict }).errors.join('\n');
}

test('a valid asset suggestion: normalized, schedule without a time zone', () => {
  const v = validateSuggestion(base, { strict: true, expectId: 'asset-test' });
  assert.equal(v.ok, true, v.errors.join('\n'));
  assert.deepEqual(v.suggestion!.schedule, { frequency: 'daily', time: '02:30' });
  assert.deepEqual(v.suggestion!.inputs, [{ field: 'targets', required: true, label: 'Subnets', hint: 'Your subnets in CIDR form.' }]);
  assert.match(errors({ ...base, id: 'other' }), /^$/);
  assert.match(validateSuggestion(base, { expectId: 'nope' }).errors.join(), /must match the file name/);
});

test('schema, kind, category, load and unknown keys', () => {
  assert.match(errors({ ...base, schema: 'x' }), /schema must be siembox.scan\/v1/);
  assert.match(errors({ ...base, kind: 'portscan' }), /kind must be one of/);
  assert.match(errors({ ...base, category: 'misc' }), /category must be one of/);
  assert.match(errors({ ...base, load: 'extreme' }), /load must be one of/);
  assert.match(errors({ ...base, extra: 1 }), /unknown key "extra"/);
  assert.equal(validateSuggestion({ ...base, extra: 1 }, { strict: false }).ok, true, 'non-strict: a newer key is a warning');
  assert.match(errors({ ...base, id: 'Bad_Id' }), /kebab-case/);
  assert.match(errors({ ...base, tags: ['Has Space'] }), /tags must be/);
});

test('schedule: the Scheduled Scans rules, and never a time zone', () => {
  assert.match(errors({ ...base, schedule: { frequency: 'daily', time: '25:00' } }), /schedule: time must be HH:MM/);
  assert.match(errors({ ...base, schedule: { frequency: 'weekly', time: '02:00' } }), /days must be a non-empty array/);
  assert.match(errors({ ...base, schedule: { frequency: 'daily', time: '02:00', timezone: 'UTC' } }), /timezone must not be set/);
  assert.match(errors({ ...base, schedule: { frequency: 'daily', time: '02:00', days: [1] } }), /days not used by a daily schedule/);
  assert.match(errors({ ...base, schedule: undefined }), /schedule is required/);
  assert.equal(validateSuggestion({ ...base, schedule: { frequency: 'hourly', minute: 5, every_hours: 4 } }).ok, true);
});

test('options: per kind, with the route checks, and never a target key', () => {
  assert.match(errors({ ...base, options: { scanType: 'stealth' } }), /scanType/);
  assert.match(errors({ ...base, options: { scanType: 'ping', targets: ['<subnet>'] } }), /never names targets/);
  assert.match(errors({ ...base, options: { scanType: 'ping', assignedShipperId: 2 } }), /never names targets/);
  assert.match(errors({ ...base, options: { scanType: 'ping', extra: true } }), /not an option of a asset suggestion/);
  assert.match(errors(vuln({ tags: ['UPPER CASE'] })), /not a valid tag/);
  assert.match(errors(vuln({ severities: ['urgent'], tags: ['cve'], excludeTags: ['intrusive', 'dos', 'fuzz'] })), /severities must be/);
  assert.match(errors(vuln({ excludeTags: ['intrusive', 'dos', 'fuzz'] })), /selects no templates/);
  assert.match(errors(vuln({ cves: true, excludeTags: ['intrusive', 'dos', 'fuzz'] }, { options: { templateSelection: { cves: true, excludeTags: ['intrusive', 'dos', 'fuzz'] }, rateLimit: 0 } })), /rateLimit/);
  assert.match(errors({ ...base, kind: 'log_discovery', category: 'log-sources', options: { mode: 'loud' }, inputs: [] }), /mode/);
  assert.equal(validateSuggestion({ ...base, kind: 'log_discovery', category: 'log-sources', options: { mode: 'passive' }, inputs: [] }).ok, true);
  const unknownTag = validateSuggestion(vuln({ tags: ['brand-new-tag'], excludeTags: ['intrusive', 'dos', 'fuzz'] }));
  assert.equal(unknownTag.ok, true);
  assert.match(unknownTag.warnings.join(), /not a common nuclei-templates tag/);
});

test('inputs: what the kind needs, nothing it does not', () => {
  assert.match(errors({ ...base, inputs: [] }), /"targets" is required for a asset suggestion/);
  assert.match(errors({ ...base, inputs: [{ field: 'targets' }, { field: 'image_ref' }] }), /not an input of a asset suggestion/);
  assert.match(errors({ ...base, inputs: [{ field: 'targets' }, { field: 'targets' }] }), /listed twice/);
  const container = { ...base, kind: 'container', category: 'containers', options: { all_images: true }, inputs: [] };
  assert.equal(validateSuggestion(container).ok, true);
  assert.match(errors({ ...container, inputs: [{ field: 'image_ref' }] }), /not needed when options.all_images/);
  assert.match(errors({ ...container, options: {} }), /"image_ref" is required/);
});

test('no concrete targets: addresses anywhere, host names in options and inputs', () => {
  assert.match(errors({ ...base, description: 'Sweeps 10.0.0.0/8 nightly.' }), /description: names an IP address or CIDR/);
  assert.match(errors({ ...base, why: 'Like fd00::1 does.' }), /why: names an IP address/);
  assert.match(errors({ ...base, inputs: [{ field: 'targets', hint: 'e.g. 192.168.1.0/24' }] }), /inputs\[0\]\.hint: names an IP/);
  assert.match(errors({ ...base, inputs: [{ field: 'targets', hint: 'e.g. nas.home.lan' }] }), /inputs\[0\]\.hint: names a host/);
  assert.equal(containsAddress('runs at 02:30 every day'), false);
  assert.equal(containsAddress('nginx 1.24 and TLS 1.0'), false);
  assert.equal(containsAddress('2001:db8::/32'), true);
  assert.equal(containsHostname('http/exposures/ and ssl/'), false);
  assert.equal(containsHostname('registry/app:tag'), false);
  assert.equal(containsHostname('scan.example.com:8443'), true);
});

test('intrusive selections must say so', () => {
  const safe = { tags: ['panel'], excludeTags: ['intrusive', 'dos', 'fuzz'] };
  assert.equal(validateSuggestion(vuln(safe)).ok, true);
  assert.match(errors(vuln({ tags: ['panel'] })), /does not exclude the intrusive, dos, fuzz/);
  assert.match(errors(vuln({ all: true })), /runs all templates/);
  assert.match(errors(vuln({ tags: ['default-login'], excludeTags: ['intrusive', 'dos', 'fuzz'] })), /selects "default-login"/);
  assert.match(errors(vuln({ all: true }, { intrusive: true })), /intrusive_note is required/);
  assert.equal(validateSuggestion(vuln({ all: true }, { intrusive: true, intrusive_note: 'Sends payloads.' })).ok, true);
  assert.match(errors({ ...base, intrusive_note: 'x' }), /only for intrusive: true/);
  assert.equal(selectionMayBeIntrusive({ templates: ['http/default-logins/'], excludeTags: ['intrusive', 'dos', 'fuzz'] }), 'it selects "http/default-logins/"');
});

test('endpoint policies: scans checked like a policy, time zones filled at add time', () => {
  const entry = { enabled: true, schedule: { frequency: 'daily', time: '02:00' }, window: { start: '00:00', end: '06:00' } };
  const policy = {
    ...base,
    id: 'endpoint-test',
    kind: 'endpoint_policy',
    category: 'endpoints',
    schedule: undefined,
    options: { scans: { vuln: entry, yara: entry, packages: entry, inventory: { enabled: true, interval_minutes: 60 } } },
    inputs: [{ field: 'endpoints' }],
  };
  delete (policy as Record<string, unknown>).schedule;
  assert.equal(validateSuggestion(policy).ok, true, errors(policy));
  assert.match(errors({ ...policy, schedule: { frequency: 'daily', time: '01:00' } }), /sets each scan type's timing under options.scans/);
  assert.match(errors({ ...policy, options: { scans: { vuln: entry } } }), /scans.yara is required/);
  assert.match(
    errors({ ...policy, options: { scans: { ...policy.options.scans, vuln: { ...entry, window: { start: '00:00', end: '06:00', timezone: 'UTC' } } } } }),
    /window.timezone must not be set/
  );
  assert.match(errors({ ...policy, options: { scans: { ...policy.options.scans, inventory: { enabled: true, interval_minutes: 1 } } } }), /interval_minutes must be an integer from 15/);
  const filled = withTimezone(policy.options.scans, 'Europe/Berlin') as Record<string, any>;
  assert.equal(filled.vuln.schedule.timezone, 'Europe/Berlin');
  assert.equal(filled.vuln.window.timezone, 'Europe/Berlin');
  assert.equal(filled.inventory.schedule, undefined);
});

test('across a set: duplicate ids and names', () => {
  const a = validateSuggestion(base).suggestion!;
  const b = { ...a, id: 'asset-other' };
  assert.deepEqual(crossCheckSuggestions([a, b]).map((p) => p.error), ['name "Test sweep" is also used by asset-test']);
  assert.deepEqual(crossCheckSuggestions([a, a]).map((p) => p.error), ['id "asset-test" is used 2 times']);
});
