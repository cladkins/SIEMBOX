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

test('progressText reports days searched', async () => {
  const { progressText } = await import('./huntService');
  assert.equal(progressText(6 * 86_400_000, 30 * 86_400_000), 'Searched 6 of 30 days');
  assert.equal(progressText(0.25 * 86_400_000, 1 * 86_400_000), 'Searched 0.3 of 1 days');
  assert.equal(progressText(14.4 * 86_400_000, 30 * 86_400_000), 'Searched 14 of 30 days');
});

test('matchCondition lower-cases once and escapes LIKE wildcards', async () => {
  const { matchCondition } = await import('./huntService');
  const c = matchCondition(['evil.com', '100%_x'], 4);
  assert.equal(c.sql, 'lower(raw_message) LIKE ANY($4::text[])');
  assert.deepEqual(c.params, [['%evil.com%', '%100\\%\\_x%']]);
});

test('matchRows groups matching lines by device: the header host, else the sender IP', async () => {
  const { deviceOf, rankDevices, UNKNOWN_DEVICE } = await import('./huntService');
  const terms = huntTerms([indicator(1, 'ipv4', '45.142.212.100'), indicator(2, 'domain', 'evil-cdn.com')], [hypothesis(10, ['rundll32.exe', 'temp'])]);
  const t = (s: string) => new Date(s);
  const rows = [
    { id: 1, timestamp: t('2026-11-01T00:00:00Z'), source_ip: '10.0.0.1', hostname: 'FW-01', app_name: 'filterlog', raw_message: 'DENY 45.142.212.100:443' },
    { id: 2, timestamp: t('2026-11-02T00:00:00Z'), source_ip: '10.0.0.9', hostname: 'fw-01', app_name: 'filterlog', raw_message: 'DENY 45.142.212.100:80' },
    { id: 3, timestamp: t('2026-11-03T00:00:00Z'), source_ip: '10.0.0.2', hostname: '-', app_name: 'dns', raw_message: 'query cdn.evil-cdn.com A' },
    { id: 4, timestamp: t('2026-11-04T00:00:00Z'), source_ip: '10.0.0.3', hostname: 'pc7', app_name: 'sysmon', raw_message: 'rundll32.exe C:\\temp\\x.dll' },
    { id: 5, timestamp: t('2026-11-05T00:00:00Z'), source_ip: null, hostname: null, app_name: null, raw_message: 'rundll32.exe again' },
    { id: 6, timestamp: t('2026-11-06T00:00:00Z'), source_ip: '10.0.0.3', hostname: 'pc7', app_name: 'sysmon', raw_message: 'nothing here' },
  ];
  const { devices } = matchRows(terms, rows);
  assert.deepEqual([...devices.keys()].sort(), ['10.0.0.2', UNKNOWN_DEVICE, 'fw-01', 'pc7'].sort());

  const fw = devices.get('fw-01')!;
  assert.equal(fw.deviceType, 'host');
  assert.equal(fw.lineIds.size, 2);
  assert.equal(fw.lastRawLogId, 2);
  assert.equal(fw.sourceIp, '10.0.0.9', 'the newest line names the sender');
  assert.deepEqual([...fw.indicators], [[1, 2]]);

  // A junk host name falls back to the sender.
  assert.equal(devices.get('10.0.0.2')!.deviceType, 'ip');
  // Two terms of one hypothesis on one line count that line once.
  assert.deepEqual([...devices.get('pc7')!.hypotheses], [[10, 1]]);
  assert.equal(devices.get('pc7')!.lineIds.size, 1);

  assert.equal(rankDevices(devices)[0].device, 'fw-01');
  assert.deepEqual(deviceOf(' Web01 ', '10.0.0.1'), { device: 'web01', deviceType: 'host' });
  assert.deepEqual(deviceOf('unknown', '::ffff:10.0.0.1'), { device: '10.0.0.1', deviceType: 'ip' });
  assert.deepEqual(deviceOf(null, 'not an ip'), { device: UNKNOWN_DEVICE, deviceType: null });
});

test('deviceAlertKeys names the device, its sender and the top indicators for the Context Graph', async () => {
  const { deviceAlertKeys } = await import('./huntService');
  assert.deepEqual(
    deviceAlertKeys({ device: 'fw-01', deviceType: 'host', hostname: 'FW-01', sourceIp: '10.0.0.1' }, [
      { type: 'domain', value: 'evil-cdn.com', lines: 1 },
      { type: 'ipv4', value: '45.142.212.100', lines: 2 },
      { type: 'ipv4', value: '45.142.212.101', lines: 1 },
    ]),
    { host: 'fw-01', client_ip: '10.0.0.1', observer_ip: '10.0.0.1', source_ip: '45.142.212.100', domain: 'evil-cdn.com' }
  );
  // A sender-only device: no host key. A URL indicator gives its host as the domain.
  assert.deepEqual(
    deviceAlertKeys({ device: '10.0.0.2', deviceType: 'ip', hostname: null, sourceIp: '10.0.0.2' }, [
      { type: 'url', value: 'https://Bad.Example.net/payload', lines: 3 },
      { type: 'sha256', value: 'a'.repeat(64), lines: 5 },
    ]),
    { client_ip: '10.0.0.2', observer_ip: '10.0.0.2', domain: 'bad.example.net' }
  );
});

test('deviceAlertText says where the lines were seen and what the run searched', async () => {
  const { deviceAlertText } = await import('./huntService');
  const text = deviceAlertText(
    { id: 7, title: 'Campaign', source_url: 'https://example.org/report' },
    {
      device: 'fw-01',
      hostname: 'FW-01',
      sourceIp: '10.0.0.1',
      appNames: new Set(['filterlog']),
      lineIds: new Set([1, 2]),
      first: new Date('2026-11-01T00:00:00Z'),
      last: new Date('2026-11-02T00:00:00Z'),
    },
    [{ type: 'ipv4', value: '45.142.212.100', lines: 2 }],
    [],
    { from: new Date('2026-10-19T00:00:00Z'), to: new Date('2026-11-02T00:00:00Z'), complete: true, lookbackDays: 14, devices: 3, lines: 9 },
    2
  );
  assert.match(text, /found 2 matching log line\(s\) on fw-01/);
  assert.match(text, /Seen on: host FW-01 · sender 10\.0\.0\.1 · app filterlog/);
  assert.match(text, /Indicator ipv4 45\.142\.212\.100: 2 line\(s\)/);
  assert.match(text, /Searched all stored logs from 2026-10-19 00:00 UTC to 2026-11-02 00:00 UTC \(the full 14-day window\)/);
  assert.match(text, /3 device\(s\); 2 other device\(s\) have their own alert/);
  assert.match(text, /Report: https:\/\/example\.org\/report/);
});
