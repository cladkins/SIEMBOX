import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  categoriesOf,
  describeInputs,
  describeOptions,
  describeSuggestionSchedule,
  filterSuggestions,
  missingInputsText,
  type ScanSuggestion,
} from './scanSuggestions.ts';

function suggestion(over: Partial<ScanSuggestion>): ScanSuggestion {
  return {
    id: 'x',
    name: 'X',
    kind: 'asset',
    category: 'inventory',
    tags: [],
    description: 'd',
    why: 'w',
    intrusive: false,
    intrusive_note: null,
    load: 'light',
    schedule: { frequency: 'daily', time: '02:30' },
    options: { scanType: 'ping' },
    inputs: [{ field: 'targets', required: true, label: null, hint: null }],
    ...over,
  };
}

const sweep = suggestion({ id: 'sweep', name: 'Daily host discovery', tags: ['nmap'] });
const kev = suggestion({
  id: 'kev',
  name: 'KEV check',
  kind: 'vulnerability',
  category: 'cves',
  options: { templateSelection: { tags: ['kev'], excludeTags: ['intrusive', 'dos', 'fuzz'] }, rateLimit: 100 },
  inputs: [
    { field: 'target', required: true, label: 'Host or range', hint: null },
    { field: 'shipper', required: false, label: null, hint: null },
  ],
});
const servers = suggestion({
  id: 'servers',
  name: 'Servers — nightly full',
  kind: 'endpoint_policy',
  category: 'endpoints',
  schedule: null,
  options: {
    scans: {
      vuln: { enabled: true, schedule: { frequency: 'daily', time: '02:00' }, window: { start: '00:00', end: '06:00' } },
      yara: { enabled: false, interval_minutes: 1440 },
      packages: { enabled: true, interval_minutes: 360 },
      inventory: { enabled: true, interval_minutes: 60 },
    },
  },
  inputs: [{ field: 'endpoints', required: true, label: null, hint: null }],
});
const images = suggestion({ id: 'images', kind: 'container', category: 'containers', options: { all_images: true }, inputs: [] });

describe('scanSuggestions', () => {
  it('filters by kind, category, allowed kinds and text', () => {
    const all = [sweep, kev, servers, images];
    assert.deepEqual(filterSuggestions(all, {}).map((s) => s.id), ['sweep', 'kev', 'servers', 'images']);
    assert.deepEqual(filterSuggestions(all, { kind: 'vulnerability' }).map((s) => s.id), ['kev']);
    assert.deepEqual(filterSuggestions(all, { category: 'endpoints' }).map((s) => s.id), ['servers']);
    assert.deepEqual(filterSuggestions(all, { kinds: ['endpoint_policy'] }).map((s) => s.id), ['servers']);
    assert.deepEqual(filterSuggestions(all, { query: 'NMAP' }).map((s) => s.id), ['sweep']);
    assert.deepEqual(filterSuggestions(all, { kinds: ['endpoint_policy'], kind: 'asset' }), []);
    assert.deepEqual(categoriesOf(all), ['inventory', 'cves', 'endpoints', 'containers']);
  });

  it('describes the schedule in the zone it will be added in', () => {
    assert.equal(describeSuggestionSchedule(sweep, 'America/Chicago'), 'Daily at 02:30 (America/Chicago)');
    assert.equal(describeSuggestionSchedule(suggestion({ schedule: { frequency: 'weekly', days: [0], time: '03:00' } }), 'UTC'), 'Sundays at 03:00 (UTC)');
    assert.equal(describeSuggestionSchedule(servers, 'UTC'), 'Each scan type has its own timing');
  });

  it('describes options per kind', () => {
    assert.deepEqual(describeOptions(sweep, 'UTC'), ['Ping sweep (-sn, no ports)']);
    assert.deepEqual(describeOptions(kev, 'UTC'), ['Templates tagged: kev', 'Excluding tags: intrusive, dos, fuzz', 'Rate limit: 100 requests/second']);
    assert.deepEqual(describeOptions(images, 'UTC'), ['Every discovered image (SIEMBox host and log shipper hosts)']);
    const policy = describeOptions(servers, 'Europe/Berlin');
    assert.equal(policy.length, 4);
    assert.match(policy[0], /^Vulnerabilities: Daily at 02:00 \(Europe\/Berlin\), /);
    assert.equal(policy[1], 'YARA: Off');
  });

  it('describes what is left to fill in', () => {
    assert.equal(describeInputs(kev), 'Host or range; optional: Log shipper to run from');
    assert.equal(describeInputs(images), 'Nothing: enable it as it is');
    assert.equal(describeInputs(servers), 'Endpoints to assign');
    assert.equal(missingInputsText(['targets']), 'Needs targets');
    assert.equal(missingInputsText(['image_ref']), 'Needs an image');
    assert.equal(missingInputsText([]), '');
    assert.equal(missingInputsText(undefined), '');
  });
});
