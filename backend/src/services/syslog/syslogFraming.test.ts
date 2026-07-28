/**
 * Syslog transport framing tests.
 *
 * Both transports are newline-framed and both used to get it wrong in ways that
 * only showed up on LONG messages — which is why ordinary logs looked fine while
 * a >1 KB CEF event from a UniFi gateway landed in the unparsed bucket:
 *
 *  - TCP is a byte stream, so `data` events break at arbitrary offsets. Treating
 *    each chunk as a complete set of messages turned one long line into two
 *    corrupt raw_logs.
 *  - UDP never split at all, so a datagram carrying two lines became one
 *    raw_log that no ^…$ anchored parser can match (`.` doesn't cross \n).
 *
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { splitSyslogFrames } from './syslogServer';

const A = '<134>Jul 28 12:50:51 UCG-Max CEF:0|Ubiquiti|UniFi Network|10.4.57|201|Alpha|7|UNIFIcategory=Security src=1.2.3.4';
const B = '<134>Jul 28 12:50:52 UCG-Max CEF:0|Ubiquiti|UniFi Network|10.4.57|201|Bravo|7|UNIFIcategory=Security src=5.6.7.8';

test('a single terminated line yields one message and no remainder', () => {
  const { lines, remainder } = splitSyslogFrames(`${A}\n`);

  assert.deepEqual(lines, [A]);
  assert.equal(remainder, '');
});

test('several lines packed into one chunk are split apart', () => {
  // The UDP bug: this used to be stored as ONE raw_log.
  const { lines } = splitSyslogFrames(`${A}\n${B}\n`, { final: true });

  assert.deepEqual(lines, [A, B]);
});

test('an unterminated tail is held back, not emitted as a message', () => {
  const { lines, remainder } = splitSyslogFrames(`${A}\n${B.slice(0, 40)}`);

  assert.deepEqual(lines, [A]);
  assert.equal(remainder, B.slice(0, 40));
});

test('a line split across two chunks is reassembled intact', () => {
  // The TCP bug: chunk 1 used to be processed as a complete (truncated)
  // message and chunk 2 as a second, header-less one.
  const split = 60;
  const first = splitSyslogFrames(A.slice(0, split));
  assert.deepEqual(first.lines, [], 'no complete line yet');

  const second = splitSyslogFrames(first.remainder + A.slice(split) + '\n');
  assert.deepEqual(second.lines, [A], 'reassembled to the original line');
  assert.equal(second.remainder, '');
});

test('a line split across three chunks is reassembled intact', () => {
  let pending = '';
  const chunks = [A.slice(0, 20), A.slice(20, 70), A.slice(70) + '\n'];
  const out: string[] = [];

  for (const chunk of chunks) {
    const { lines, remainder } = splitSyslogFrames(pending + chunk);
    out.push(...lines);
    pending = remainder;
  }

  assert.deepEqual(out, [A]);
  assert.equal(pending, '');
});

test('CRLF framing does not leave a trailing \\r on the message', () => {
  // A stray \r defeats a $-anchored parser: `.` matches neither \n nor \r.
  const { lines } = splitSyslogFrames(`${A}\r\n${B}\r\n`, { final: true });

  assert.deepEqual(lines, [A, B]);
  assert.ok(!lines.some((l) => l.endsWith('\r')));
});

test('blank lines and keepalive newlines are dropped', () => {
  const { lines } = splitSyslogFrames(`\n${A}\n\n   \n${B}\n`, { final: true });

  assert.deepEqual(lines, [A, B]);
});

test('final flush emits an unterminated last line rather than losing it', () => {
  // A sender that closes the connection without a trailing newline.
  const { lines, remainder } = splitSyslogFrames(A, { final: true });

  assert.deepEqual(lines, [A]);
  assert.equal(remainder, '');
});

test('an empty final flush produces nothing', () => {
  assert.deepEqual(splitSyslogFrames('', { final: true }), { lines: [], remainder: '' });
});

test('a chunk boundary landing exactly on the newline is handled', () => {
  const first = splitSyslogFrames(`${A}\n`);
  assert.deepEqual(first.lines, [A]);
  assert.equal(first.remainder, '');

  const second = splitSyslogFrames(first.remainder + `${B}\n`);
  assert.deepEqual(second.lines, [B]);
});
