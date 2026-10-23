/**
 * Compatibility of converted SigmaHQ rules with this install's logs, on
 * fixture samples: fields decide, the logsource has to fit, and the dry run
 * counts matches (exclude groups included). DB-free. Run with `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSigmaLibrary } from './sigmaLibrary';
import { countSigmaMatches, planSigmaCompat, sigmaLogsource, type CompatSource } from './sigmaCompat';
import { IDS, fixtureArchive } from './sigmaFixture.test';

const { rules } = buildSigmaLibrary(fixtureArchive('fx'), { tag: 't', asset: 'sigma_core+.zip' });
const candidates = rules
  .filter((r) => r.convertible)
  .map((r) => ({ sigma_id: r.sigma_id, product: r.product, category: r.category, service: r.service, parts: r.parts }));

const SOURCES: CompatSource[] = [
  // A reverse proxy: user agents, one of them the hack tool.
  {
    parser_name: 'traefik-access',
    samples: [
      { user_agent: 'Mozilla/5.0', path: '/', service: 'traefik' },
      { user_agent: 'curl fx-sqlmap/1.0', path: '/login', service: 'traefik' },
    ],
  },
  // The fixture product's parser: has alpha and gamma, not beta.
  {
    parser_name: 'fx-app',
    samples: [
      { fx_alpha: 'one', fx_gamma: 'benign' },
      { fx_alpha: 'one', fx_gamma: 'other' },
      { fx_alpha: 'zzz', fx_gamma: 'other' },
    ],
  },
  // A firewall that also has a raw message: must not count for the GitHub keyword rule.
  { parser_name: 'netfilter-firewall', samples: [{ message: 'fx-secret-word DROP', action: 'drop' }] },
  { parser_name: 'idle-parser', samples: [] },
];

const plan = planSigmaCompat(candidates, SOURCES);
const result = (id: string) => plan.results.get(id)!;

test('fields present on a parser that fits the logsource: compatible', () => {
  const ua = result(IDS.ua);
  assert.equal(ua.compatible, true);
  assert.deepEqual(ua.parsers.map((p) => p.parser_name), ['traefik-access']);
  // The split rule: part 1 (alpha) fits fx-app; part 2 needs fx_beta, which nobody emits.
  const split = result(IDS.split);
  assert.equal(split.compatible, true);
  assert.deepEqual(split.parsers, [{ parser_name: 'fx-app', parts: [0], sampled: 3 }]);
});

test('a field no parser emits: "no matching logs yet" naming that field', () => {
  const win = result(IDS.windows);
  assert.equal(win.compatible, false);
  assert.equal(win.missing_field, 'image');
  assert.deepEqual(win.parsers, []);
});

test('fields alone are not enough: the parser must fit the rule logsource', () => {
  // The GitHub keyword rule: netfilter-firewall has `message` (and the word), but is not GitHub.
  const kw = result(IDS.keyword);
  assert.equal(kw.compatible, false);
  assert.equal(kw.keyword, true);
  assert.equal(kw.logsource_mismatch, 'service audit');
  // With a parser named for it, it is compatible.
  const ok = planSigmaCompat(candidates, [{ parser_name: 'github-audit', samples: [{ message: 'x' }] }]).results.get(IDS.keyword)!;
  assert.equal(ok.compatible, true);
});

test('logsource hints: service, then category, then product; unknown ones match their own name', () => {
  assert.deepEqual(sigmaLogsource({ product: 'linux', service: 'sshd' }), { label: 'service sshd', hints: ['ssh'] });
  assert.equal(sigmaLogsource({ category: 'webserver' }).hints.includes('nginx'), true);
  assert.deepEqual(sigmaLogsource({ product: 'okta' }), { label: 'product okta', hints: ['okta'] });
  assert.deepEqual(sigmaLogsource({}), { label: 'no logsource', hints: [] });
});

test('the dry run counts samples a part would fire on, honouring exclude', () => {
  const counts = countSigmaMatches(plan.sources, plan.pairs);
  assert.deepEqual(counts[IDS.ua], { 'traefik-access': 1 });
  assert.deepEqual(counts[IDS.split], { 'fx-app': 2 });
  // selection alpha=one and not gamma=benign: only the second sample.
  assert.deepEqual(counts[IDS.not], { 'fx-app': 1 });
});

test('bounded: pairs are only planned where every field is present', () => {
  for (const item of plan.pairs) {
    for (const pair of item.pairs) {
      const src = plan.sources[pair.source];
      for (const c of pair.part.conditions) assert.ok(src.samples.some((s) => s[c.field] !== undefined), `${item.sigma_id} ${c.field}`);
    }
  }
  assert.ok(!plan.pairs.some((p) => p.sigma_id === IDS.windows));
  assert.ok(!plan.sources.some((s) => s.parser_name === 'idle-parser'));
});
