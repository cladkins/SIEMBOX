import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { gridLayout, mapFill } from './layout.ts';
import { panelTitle, viewAttributions } from './panelInfo.ts';

const keys = (n: number) => Array.from({ length: n }, (_, i) => `p${i}`);
const shape = (l: { columns: number; rows: number }) => `${l.columns}x${l.rows}`;

describe('grid by panel count', () => {
  it('follows the table in §5.2 on a landscape screen', () => {
    assert.deepEqual([1, 2, 3, 4, 5, 6].map((n) => shape(gridLayout(keys(n), false))), ['1x1', '2x1', '3x1', '2x2', '3x2', '3x2']);
  });

  it('never leaves a hole: five panels stretch the last one', () => {
    assert.deepEqual(gridLayout(keys(5), false).spans, [1, 1, 1, 1, 2]);
    assert.deepEqual(gridLayout(keys(6), false).spans, [1, 1, 1, 1, 1, 1]);
  });

  it('uses one column up to 3 panels on a portrait screen, two beyond', () => {
    assert.equal(shape(gridLayout(keys(3), true)), '1x3');
    assert.equal(shape(gridLayout(keys(4), true)), '2x2');
    assert.equal(shape(gridLayout(keys(6), true)), '2x3');
  });

  it('gives the threat map two columns with 4 panels or fewer', () => {
    const four = gridLayout(['threat_map:1', 'top_sources', 'top_rules:24', 'open_alerts'], false);
    assert.equal(shape(four), '3x2');
    assert.deepEqual(four.spans, [2, 1, 1, 2]);
    const three = gridLayout(['open_alerts', 'threat_map:7', 'ingest'], false);
    assert.equal(shape(three), '2x2');
    assert.deepEqual(three.keys, ['threat_map:7', 'open_alerts', 'ingest']);
    assert.deepEqual(three.spans, [2, 1, 1]);
    assert.equal(shape(gridLayout(['ingest', 'threat_map:1'], false)), '3x1');
    const six = gridLayout(['threat_map:1', 'a', 'b', 'c', 'd', 'e'], false);
    assert.deepEqual(six.spans, [1, 1, 1, 1, 1, 1]);
  });
});

describe('map fill', () => {
  it('is darkest at zero and brighter with more alerts', () => {
    const l = (t: number) => Number(/(\d+(?:\.\d+)?)%\)$/.exec(mapFill(t))![1]);
    assert.ok(l(0) < l(0.001));
    assert.ok(l(0.001) < l(0.5));
    assert.ok(l(0.5) < l(1));
    assert.ok(l(1) <= 82);
  });
});

describe('panel titles and attributions', () => {
  it('names each kind and variant', () => {
    assert.equal(panelTitle('sources:15'), 'Sources (silent > 15 m)');
    assert.equal(panelTitle('recent_alerts:high'), 'Recent high & critical');
    assert.equal(panelTitle('threat_map:7'), 'Alert origins, 7 days');
  });

  it('prints DB-IP only on views with the map or top sources, HIBP only with digital risk', () => {
    assert.deepEqual(viewAttributions(['open_alerts'], ['dbip', 'hibp']), []);
    assert.deepEqual(viewAttributions(['threat_map:1'], ['dbip', 'hibp']), ['dbip']);
    assert.deepEqual(viewAttributions(['top_sources', 'digital_risk'], ['dbip', 'hibp']), ['dbip', 'hibp']);
    assert.deepEqual(viewAttributions(['digital_risk'], []), []);
  });
});
