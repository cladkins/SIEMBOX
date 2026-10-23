/**
 * A small SigmaHQ-shaped release archive for the SigmaHQ library tests: one
 * rule of each kind the library has to tell apart. Exported for the other
 * test files; its own test checks the archive builds into the expected
 * library. `prefix` makes field names and titles unique per test run (the DB
 * test shares its database with other test files).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeZip, type TestZipEntry } from '../../utils/testZip.test';
import { buildSigmaLibrary } from './sigmaLibrary';

export const IDS = {
  ua: '0a1b2c3d-0000-4000-8000-000000000001',
  split: '0a1b2c3d-0000-4000-8000-000000000002',
  not: '0a1b2c3d-0000-4000-8000-000000000003',
  lossy: '0a1b2c3d-0000-4000-8000-000000000004',
  deprecated: '0a1b2c3d-0000-4000-8000-000000000005',
  keyword: '0a1b2c3d-0000-4000-8000-000000000006',
  redos: '0a1b2c3d-0000-4000-8000-000000000007',
  windows: '0a1b2c3d-0000-4000-8000-000000000008',
} as const;

/** Rule files keyed by path. `variant` 2 changes the split rule (3 alternatives) and the UA rule's level. */
export function fixtureRules(prefix: string, variant: 1 | 2 = 1): Record<string, string> {
  const f = (name: string) => `${prefix}_${name}`;
  const rules: Record<string, string> = {
    'rules/web/proxy_generic/proxy_ua_fixture.yml': `title: ${prefix} Hack Tool User Agent
id: ${IDS.ua}
status: test
description: Detects a hack tool user agent.
references:
  - https://example.invalid/ua
author: Jane Doe, John Roe
date: 2020-01-01
modified: 2024-05-06
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  category: proxy
detection:
  selection:
    c-useragent|contains: '${prefix}-sqlmap'
  condition: selection
falsepositives:
  - Penetration tests
level: ${variant === 1 ? 'high' : 'critical'}
`,
    'rules/linux/fixture/split.yml': `title: ${prefix} Split Rule
id: ${IDS.split}
status: stable
author: SigmaHQ
logsource:
  product: ${prefix}
detection:
  selection_a:
    ${f('alpha')}: one
  selection_b:
    ${f('beta')}: two
${variant === 2 ? `  selection_c:\n    ${f('alpha')}: three\n` : ''}  condition: 1 of selection_*
level: medium
`,
    'rules/linux/fixture/not.yml': `title: ${prefix} Filtered Rule
id: ${IDS.not}
status: test
logsource:
  product: ${prefix}
detection:
  selection:
    ${f('alpha')}: one
  filter:
    ${f('gamma')}: benign
  condition: selection and not filter
level: high
`,
    'rules/network/fixture/lossy.yml': `title: ${prefix} Lossy Rule
id: ${IDS.lossy}
status: test
logsource:
  product: ${prefix}
detection:
  selection:
    ${f('alpha')}: one
    DestinationIp|cidr: 10.0.0.0/8
  condition: selection
level: high
`,
    'rules/linux/fixture/deprecated.yml': `title: ${prefix} Old Rule
id: ${IDS.deprecated}
status: deprecated
logsource:
  product: ${prefix}
detection:
  selection:
    ${f('alpha')}: one
  condition: selection
level: low
`,
    'rules/cloud/github/keyword.yml': `title: ${prefix} Keyword Rule
id: ${IDS.keyword}
status: test
logsource:
  product: github
  service: audit
detection:
  keywords:
    - '${prefix}-secret-word'
  condition: keywords
level: medium
`,
    'rules/linux/fixture/redos.yml': `title: ${prefix} Backtracking Rule
id: ${IDS.redos}
status: test
logsource:
  product: ${prefix}
detection:
  selection:
    ${f('alpha')}|re: '^(a+)+$'
  condition: selection
level: high
`,
    'rules/windows/process_creation/fixture.yml': `title: ${prefix} Windows Rule
id: ${IDS.windows}
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\${prefix}.exe'
  condition: selection
level: high
`,
    // No id, and not YAML at all: left out.
    'rules/misc/no_id.yml': `title: ${prefix} No Id\nlogsource:\n  product: x\ndetection:\n  s:\n    a: b\n  condition: s\n`,
    'rules/misc/broken.yml': 'title: [unclosed\n  - : :\n',
    // A js-yaml 3 code tag: the backend's loader (js-yaml 4) refuses it.
    'rules/misc/code.yml': `title: !!js/function 'function () { return 1 }'\nid: 0a1b2c3d-0000-4000-8000-0000000000ff\n`,
  };
  if (variant === 2) delete rules['rules/linux/fixture/not.yml'];
  return rules;
}

export function fixtureArchive(prefix: string, variant: 1 | 2 = 1, extra: TestZipEntry[] = []): Buffer {
  const entries: TestZipEntry[] = [
    { name: 'rules/', data: '', stored: true },
    ...Object.entries(fixtureRules(prefix, variant)).map(([name, data]) => ({ name, data })),
    { name: 'version.txt', data: 'Release Date: 2026-07-09\nLabel: r2026-04-01-50-g552f3fee4\nCommit-Hash: 552f3fee\n' },
    { name: 'LICENSE.Detection.Rules.md', data: 'DRL 1.1' },
    ...extra,
  ];
  return makeZip(entries);
}

test('the fixture archive builds: 7 listed rules, 6 convertible', () => {
  const { rules, stats } = buildSigmaLibrary(fixtureArchive('fx'), { tag: 'r2099-01-01', asset: 'sigma_core+.zip' });
  assert.equal(stats.rules, 7);
  assert.deepEqual(stats.skipped, { not_listed: 1, no_id: 1, duplicate_id: 0, unreadable: 2 });
  const conv = rules.filter((r) => r.convertible).map((r) => r.sigma_id).sort();
  assert.deepEqual(conv, [IDS.ua, IDS.split, IDS.not, IDS.keyword, IDS.redos, IDS.windows].sort());
});
