/**
 * Tests for ANSI stripping on syslog ingestion. Colorized container stdout (~1 in
 * 6 shipped lines) used to reach the parsers with leading ESC bytes, so every
 * ^-anchored parser missed it. stripAnsi runs before parsing/storage now.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { stripAnsi, parseSyslogMessage } from './syslogParser';

const ESC = '\u001b';

test('stripAnsi removes SGR color codes (real shipper + Go zerolog examples)', () => {
  assert.equal(stripAnsi(`${ESC}[0;32m[INFO]${ESC}[0m Log shipper running`), '[INFO] Log shipper running');
  assert.equal(
    stripAnsi(`${ESC}[90m4:42PM${ESC}[0m ${ESC}[32mINF${ESC}[0m request received`),
    '4:42PM INF request received'
  );
});

test('stripAnsi leaves clean text untouched (legit brackets + emoji preserved)', () => {
  const clean = '[8:03:56 AM] [SUCCESS] [🖥️] SSH connection established';
  assert.equal(stripAnsi(clean), clean);
});

test('stripAnsi removes a stray ESC byte not part of a CSI sequence', () => {
  assert.equal(stripAnsi(`abc${ESC}def`), 'abcdef');
});

test('parseSyslogMessage strips ANSI before extracting tag + message', () => {
  const raw = `<134>Jun 30 19:54:43 streambox myapp[a1b2c3d4]: ${ESC}[32minfo${ESC}[0m service started`;
  const out = parseSyslogMessage(raw);
  assert.equal(out.appName, 'myapp');
  assert.equal(out.shipperId, 'a1b2c3d4');
  assert.equal(out.message, 'info service started');
});
