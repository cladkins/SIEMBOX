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

// ---------------------------------------------------------------------------
// UniFi tag handling. Real lines captured from a UCG-Max + U6/U7 APs: the APs
// use "<mac>,<model>-<fw>" as their TAG with the real program inside the
// message, and the gateway logs untagged iptables lines whose first ':' sits
// inside "MAC=28:70:…" — both used to produce junk app_names.
// ---------------------------------------------------------------------------

const AP = '1c0b8bc42f58,U7-Lite-8.6.11+18870';

test('UniFi AP: program peeled out of the message (hostapd)', () => {
  const out = parseSyslogMessage(
    `<30>Jun 30 18:00:00 U7-Lite ${AP}: hostapd: wifi0ap5: STA c0:49:ef:8c:07:2c IEEE 802.11: disassociated`
  );
  assert.equal(out.appName, 'hostapd');
  assert.equal(out.hostname, 'U7-Lite');
  assert.equal(out.message, 'wifi0ap5: STA c0:49:ef:8c:07:2c IEEE 802.11: disassociated');
});

test('UniFi AP: kernel lines keep their bracketed uptime prefix in the message', () => {
  const out = parseSyslogMessage(
    `<30>Jun 30 18:00:00 U6-Ext 1c6a1b60baa0,U6-Extender-6.8.2+15592: kernel: [947552.028975] [wifi0ap1] ieee80211_set_node_vid node c0:49:ef:8c:07:2c lan[0] dvlan stas 0`
  );
  assert.equal(out.appName, 'kernel');
  assert.equal(out.message, '[947552.028975] [wifi0ap1] ieee80211_set_node_vid node c0:49:ef:8c:07:2c lan[0] dvlan stas 0');
});

test('UniFi AP: empty middle field ("…: : wevent: …") still yields the program', () => {
  const out = parseSyslogMessage(
    `<30>Jun 30 18:00:00 U6-Ext 1c6a1b60baa0,U6-Extender-6.8.2+15592: : wevent: wevent.ubnt_custom_event(): EVENT_STA_JOIN wifi0ap1: c0:49:ef:8c:07:2c / 1`
  );
  assert.equal(out.appName, 'wevent');
  assert.equal(out.message, 'wevent.ubnt_custom_event(): EVENT_STA_JOIN wifi0ap1: c0:49:ef:8c:07:2c / 1');
});

test('UniFi AP: doubled program name ("stahtd: stahtd: …") is de-echoed', () => {
  const out = parseSyslogMessage(
    `<30>Jun 30 18:00:00 U6-Ext 1c6a1b60c3c0,U6-Extender-6.8.2+15592: stahtd: stahtd: [STA-TRACKER].stahtd_dump_event(): {"message_type":"STA_ASSOC_TRACKER","mac":"c0:49:ef:8c:07:2c"}`
  );
  assert.equal(out.appName, 'stahtd');
  assert.equal(out.message, '[STA-TRACKER].stahtd_dump_event(): {"message_type":"STA_ASSOC_TRACKER","mac":"c0:49:ef:8c:07:2c"}');
});

test('UniFi AP: program with pid ("syswrapper[16283]: …")', () => {
  const out = parseSyslogMessage(
    `<30>Jun 30 18:00:00 U7-Lite ${AP}: syswrapper[16283]: Trigger rrm scan(3): sleep 1;cfg80211tool wifi1ap1 acsrrm 40; sleep 1;`
  );
  assert.equal(out.appName, 'syswrapper');
  assert.equal(out.processId, '16283');
  assert.equal(out.message, 'Trigger rrm scan(3): sleep 1;cfg80211tool wifi1ap1 acsrrm 40; sleep 1;');
});

test('UniFi AP: device tag in the HOSTNAME slot gets its trailing colon dropped', () => {
  const out = parseSyslogMessage(
    `<30>Jun 30 18:00:00 ${AP}: hostapd: wifi0ap5: STA c0:49:ef:8c:07:2c IEEE 802.11: disassociated`
  );
  assert.equal(out.hostname, AP);
  assert.equal(out.appName, 'hostapd');
});

test('UniFi gateway: untagged iptables line is NOT split inside MAC=…', () => {
  const line =
    '[PREROUTING-DNAT-4] DESCR="PortForward DNAT [NPM HTTP/HTTPS]" IN=eth4 OUT= MAC=28:70:4e:84:bc:d9:00:01:5c:a2:7e:46:08:00 SRC=23.172.217.87 DST=73.155.250.5 LEN=40 TOS=00 PREC=0x00 TTL=245 ID=17017 PROTO=TCP SPT=50189 DPT=443 SEQ=944224711 ACK=0 WINDOW=1024 SYN URGP=0';
  const out = parseSyslogMessage(`<4>Jun 30 18:00:00 UCG-Max ${line}`);
  assert.equal(out.appName, null);
  assert.equal(out.hostname, 'UCG-Max');
  assert.equal(out.message, line);
});

test('UniFi gateway: normal daemon tags still extract (coredns JSON)', () => {
  const out = parseSyslogMessage(
    `<30>Jun 30 18:00:00 UCG-Max coredns: {"timestamp":"2026-06-30T18:00:12-05:00","type":"dnsAdBlock","domain":"browser-intake-datadoghq.com"}`
  );
  assert.equal(out.appName, 'coredns');
  assert.equal(out.hostname, 'UCG-Max');
  assert.equal(out.message, '{"timestamp":"2026-06-30T18:00:12-05:00","type":"dnsAdBlock","domain":"browser-intake-datadoghq.com"}');
});

test('regression: multi-word tags and shipper/pid suffixes still work', () => {
  const a = parseSyslogMessage('<134>Jun 30 19:54:43 host Authentik Server: user logged in');
  assert.equal(a.appName, 'Authentik Server');
  assert.equal(a.message, 'user logged in');

  const b = parseSyslogMessage('<134>Jun 30 19:54:43 host sshd[1234]: Accepted publickey for root');
  assert.equal(b.appName, 'sshd');
  assert.equal(b.processId, '1234');

  const c = parseSyslogMessage('<134>Jun 30 19:54:43 host nginx[a1b2c3d4]: GET /health');
  assert.equal(c.appName, 'nginx');
  assert.equal(c.shipperId, 'a1b2c3d4');

  const d = parseSyslogMessage('<134>Jun 30 19:54:43 host sshd[1234][a1b2c3d4]: Accepted');
  assert.equal(d.appName, 'sshd');
  assert.equal(d.processId, '1234');
  assert.equal(d.shipperId, 'a1b2c3d4');
});

test('CEF envelope is never split off as a syslog TAG', () => {
  // A UniFi gateway IDS line: "CEF:" sits where a TAG would, and the first-colon
  // split used to produce appName "CEF" with the message starting at "0|…",
  // which no CEF parser could match. The whole envelope must survive intact.
  const out = parseSyslogMessage(
    '<4>Jun 24 15:22:05 UCG-Max CEF:0|Ubiquiti|UniFi Network|10.4.57|201|Threat Detected and Blocked|7|UNIFIcategory=Security src=203.0.113.5 dst=198.51.100.10 proto=TCP spt=55000 dpt=443 act=blocked'
  );
  assert.equal(out.hostname, 'UCG-Max');
  assert.notEqual(out.appName, 'CEF');
  assert.ok(out.message.startsWith('CEF:0|Ubiquiti|'));
});

// ---------------------------------------------------------------------------
// Trailing line terminators.
//
// JavaScript's `$` (without /m) matches strictly at end of input — unlike
// Perl/Python it does NOT match before a final newline. So one trailing \n
// defeats every $-anchored pattern: this module's own RFC 3164 regex first,
// and then every catalog parser downstream.
//
// The strip used to live inside the `if (priMatch)` branch, so it only ran for
// messages carrying a PRI. A sender that omits the PRI and terminates its
// datagram with a newline — a real UniFi gateway shipping CEF — had its whole
// line stored verbatim, header included, and matched nothing at all.
// ---------------------------------------------------------------------------

const CEF_BODY =
  'Jul 28 13:30:45 UCG-Max CEF:0|Ubiquiti|UniFi Network|10.4.57|400|WiFi Client Connected|1|' +
  'UNIFIcategory=Client Devices UNIFIhost=UCG Max UNIFIclientIp=192.168.3.119 msg=Watch connected.';

test('no PRI + trailing newline: header is still stripped', () => {
  const out = parseSyslogMessage(`${CEF_BODY}\n`);

  assert.equal(out.hostname, 'UCG-Max', 'hostname must be extracted, not left in the message');
  assert.ok(out.message.startsWith('CEF:0|Ubiquiti|'), `header not stripped: ${out.message.slice(0, 40)}`);
  assert.ok(!/[\r\n]$/.test(out.message), 'trailing terminator must not survive into raw_message');
});

test('no PRI + CRLF: header is still stripped', () => {
  const out = parseSyslogMessage(`${CEF_BODY}\r\n`);

  assert.equal(out.hostname, 'UCG-Max');
  assert.ok(out.message.startsWith('CEF:0|Ubiquiti|'));
  assert.ok(!/[\r\n]$/.test(out.message));
});

test('PRI + trailing newline keeps working (the case that always did)', () => {
  const out = parseSyslogMessage(`<134>${CEF_BODY}\n`);

  assert.equal(out.hostname, 'UCG-Max');
  assert.equal(out.severity, 6);
  assert.ok(out.message.startsWith('CEF:0|Ubiquiti|'));
  assert.ok(!/[\r\n]$/.test(out.message));
});

test('a message that is only a line terminator yields an empty message, not a crash', () => {
  assert.equal(parseSyslogMessage('\n').message, '');
  assert.equal(parseSyslogMessage('\r\n').message, '');
});

test('interior newlines are preserved — only the terminator is stripped', () => {
  // Multi-line payloads (stack traces) must not be silently joined or cut.
  const out = parseSyslogMessage('<134>Jul 28 13:30:45 host app: line one\nline two\n');

  assert.equal(out.message, 'line one\nline two');
});
