/**
 * The pure parts of Threat Hunting: the AI output guard, the terms a hunt
 * searches for, and how log lines are matched to them. No database.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { aiExtract, sanitizeAiOutput } from './huntAi';
import { escapeLike, huntTerms, matchRows, type HypothesisRow, type IndicatorRow } from './huntService';

const REPORT = 'The actor used 45.142.212.100 and evil-cdn.com. They ran rundll32.exe from %TEMP%.';
const always = () => true;

test('sanitizeAiOutput keeps only indicators that are in the report and valid', () => {
  const out = sanitizeAiOutput(
    {
      title: 'Campaign',
      summary: 'Summary',
      hypotheses: [
        { title: 'Rundll32 from temp', search_terms: ['rundll32.exe', 'ab', 'x'.repeat(300), 'RUNDLL32.EXE'], attack_techniques: ['t1218.011', 'nope'] },
        { title: '' },
      ],
      indicators: [
        { type: 'ipv4', value: '45.142.212.100' },
        { type: 'ipv4', value: '8.8.4.4' }, // not in the report: hallucinated
        { type: 'domain', value: 'evil-cdn[.]com' },
        { type: 'bogus', value: 'x' },
      ],
      not_indicators: ['Vendor.com'],
    },
    REPORT,
    always
  );
  assert.equal(out.title, 'Campaign');
  assert.equal(out.hypotheses.length, 1);
  assert.deepEqual(out.hypotheses[0].search_terms, ['rundll32.exe']);
  assert.deepEqual(out.hypotheses[0].attack_techniques, ['T1218.011']);
  assert.deepEqual(out.indicators.map((i) => i.value), ['45.142.212.100', 'evil-cdn.com']);
  assert.deepEqual(out.not_indicators, ['vendor.com']);
});

test('aiExtract returns null without a configured model and parses a completion', async () => {
  assert.equal(await aiExtract(null, REPORT, always, { config: { provider: 'anthropic', model: 'm' } }), null);
  const out = await aiExtract('T', REPORT, always, {
    config: { provider: 'ollama', model: 'm' },
    complete: async () => '```json\n{"hypotheses":[{"title":"H","search_terms":["rundll32.exe"]}]}\n```',
  });
  assert.equal(out?.hypotheses[0].title, 'H');
});

test('escapeLike escapes LIKE wildcards', () => {
  assert.equal(escapeLike('100%_a\\b'), '100\\%\\_a\\\\b');
});

const indicator = (id: number, ioc_type: IndicatorRow['ioc_type'], value: string, enabled = true): IndicatorRow => ({
  id, hunt_id: 1, stix_id: `indicator--${id}`, ioc_type, value, context: null, found_by: 'regex', enabled,
  match_count: 0, first_seen: null, last_seen: null, created_at: new Date(),
});
const hypothesis = (id: number, terms: string[], enabled = true): HypothesisRow => ({
  id, hunt_id: 1, stix_id: `note--${id}`, title: `H${id}`, description: null, attack_techniques: [], search_terms: terms,
  found_by: 'ai', enabled, match_count: 0, first_seen: null, last_seen: null, created_at: new Date(),
});

test('huntTerms takes enabled indicators and hypothesis terms', () => {
  const terms = huntTerms(
    [indicator(1, 'ipv4', '45.142.212.100'), indicator(2, 'domain', 'Evil-CDN.com'), indicator(3, 'md5', 'a'.repeat(32), false)],
    [hypothesis(10, ['Rundll32.exe', 'ab']), hypothesis(11, ['ignored'], false)]
  );
  assert.deepEqual(
    terms.map((t) => [t.needle, t.kind]),
    [['45.142.212.100', 'ipv4'], ['evil-cdn.com', 'domain'], ['rundll32.exe', 'keyword']]
  );
});

test('matchRows counts each log line per term, with whole-token matching', () => {
  const terms = huntTerms([indicator(1, 'ipv4', '45.142.212.100'), indicator(2, 'domain', 'evil-cdn.com')], [hypothesis(10, ['rundll32.exe'])]);
  const t = (s: string) => new Date(s);
  const rows = [
    { id: 1, timestamp: t('2026-11-01T00:00:00Z'), source_ip: '10.0.0.1', hostname: 'fw', app_name: 'fw', raw_message: 'DENY 45.142.212.100:443' },
    { id: 2, timestamp: t('2026-11-02T00:00:00Z'), source_ip: '10.0.0.1', hostname: 'fw', app_name: 'fw', raw_message: 'DENY 145.142.212.100:443' },
    { id: 3, timestamp: t('2026-11-03T00:00:00Z'), source_ip: '10.0.0.2', hostname: 'dns', app_name: 'dns', raw_message: 'query cdn.EVIL-CDN.com A from 45.142.212.100' },
    { id: 4, timestamp: t('2026-11-04T00:00:00Z'), source_ip: '10.0.0.3', hostname: 'pc', app_name: 'sysmon', raw_message: 'Image C:\\Windows\\rundll32.exe' },
  ];
  const { hits, logsMatched } = matchRows(terms, rows);
  assert.deepEqual([...logsMatched].sort(), [1, 3, 4]);
  const ip = hits.get(terms[0])!;
  assert.equal(ip.count, 2);
  assert.deepEqual(ip.first, t('2026-11-01T00:00:00Z'));
  assert.deepEqual(ip.last, t('2026-11-03T00:00:00Z'));
  assert.equal(hits.get(terms[1])!.count, 1);
  assert.equal(hits.get(terms[2])!.count, 1);
});
