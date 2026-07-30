import { test } from 'node:test';
import assert from 'node:assert/strict';
import { selectNewLines, parseLineTimestamp } from './homeAssistant';

const LINE1 = '2024-01-15 12:00:00.001 INFO (MainThread) [homeassistant.core] Starting Home Assistant';
const LINE2 = '2024-01-15 12:00:01.002 WARNING (MainThread) [homeassistant.components.http.ban] Banned IP 203.0.113.5';
const LINE3 = '2024-01-15 12:00:02.003 INFO (MainThread) [homeassistant.core] Home Assistant initialized';
const LINE4 = '2024-01-15 12:00:03.004 INFO (MainThread) [homeassistant.core] Some later event';

test('selectNewLines with no cursor (first poll) returns a bounded tail, not the whole buffer', () => {
  const manyLines = Array.from({ length: 300 }, (_, i) => `2024-01-15 12:00:00.${i} INFO (MainThread) [x] line ${i}`);
  const { newLines, nextCursor } = selectNewLines(manyLines.join('\n'), null);
  assert.equal(newLines.length, 200);
  assert.equal(newLines[newLines.length - 1], manyLines[manyLines.length - 1]);
  assert.equal(nextCursor, manyLines.slice(-3).join('\n'));
});

test('selectNewLines finds the cursor window and returns only lines after it', () => {
  const cursor = [LINE1, LINE2, LINE3].join('\n'); // a prior poll's tail-of-3
  const fullText = [LINE1, LINE2, LINE3, LINE4].join('\n');
  const { newLines, nextCursor } = selectNewLines(fullText, cursor);
  assert.deepEqual(newLines, [LINE4]);
  assert.equal(nextCursor, [LINE2, LINE3, LINE4].join('\n'));
});

test('selectNewLines falls back to a bounded tail when the cursor window is not found (buffer reset)', () => {
  const staleCursor = 'some line that no longer exists\nanother stale line\nand a third';
  const fullText = [LINE1, LINE2, LINE3, LINE4].join('\n');
  const { newLines } = selectNewLines(fullText, staleCursor);
  assert.deepEqual(newLines, [LINE1, LINE2, LINE3, LINE4]); // fewer than 200 lines total, so the whole (small) buffer
});

test('selectNewLines returns nothing new when the cursor is the whole buffer (no new lines yet)', () => {
  const fullText = [LINE1, LINE2, LINE3].join('\n');
  const cursor = [LINE1, LINE2, LINE3].join('\n');
  const { newLines } = selectNewLines(fullText, cursor);
  assert.deepEqual(newLines, []);
});

test('parseLineTimestamp extracts HA\'s native leading timestamp', () => {
  const ts = parseLineTimestamp(LINE2);
  assert.ok(ts);
  assert.equal(ts!.toISOString(), '2024-01-15T12:00:01.002Z');
});

test('parseLineTimestamp returns null for a line with no leading timestamp', () => {
  assert.equal(parseLineTimestamp('not a log line'), null);
});
