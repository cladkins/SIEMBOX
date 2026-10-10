/**
 * The Pwned Passwords k-anonymity check. The property that matters most is
 * what leaves the process: only the first 5 hex characters of the SHA-1 —
 * never the password, the full hash or the suffix — with padding requested so
 * the response size reveals nothing either. Matching happens locally, and the
 * padding rows (count 0) must never count as a hit. Run with `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import {
  checkPassword,
  findSuffixCount,
  PwnedPasswordsError,
  type FetchFn,
} from './pwnedPasswords';

const sha1 = (s: string) => crypto.createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase();

function fakeFetch(respond: () => Response) {
  const calls: Array<{ url: URL; init: RequestInit }> = [];
  const fetchImpl: FetchFn = async (url, init) => {
    calls.push({ url, init });
    return respond();
  };
  return { fetchImpl, calls };
}

// A realistic padded range body: real rows, padding rows (count 0), CRLF endings.
function rangeBody(rows: Array<[string, number]>): string {
  const filler: Array<[string, number]> = [
    ['0018A45C4D1DEF81644B54AB7F969B88D65', 1],
    ['00D4F6E8FA6EECAD2A3AA415EEC418D38EC', 2],
    ['011053FD0102E94D6AE2F8B83D76FAF94F6', 0],
    ['012A7CA357541F0AC487871FEEC1891C49C', 0],
  ];
  return [...filler, ...rows].map(([suffix, count]) => `${suffix}:${count}`).join('\r\n');
}

test('only the 5-char hash prefix is sent, with Add-Padding and a User-Agent', async () => {
  const password = 'correct horse battery staple';
  const hash = sha1(password);
  const { fetchImpl, calls } = fakeFetch(
    () => new Response(rangeBody([[hash.slice(5), 3]]), { status: 200 })
  );

  await checkPassword(password, { fetchImpl });

  assert.equal(calls.length, 1);
  const { url, init } = calls[0];
  assert.equal(url.origin, 'https://api.pwnedpasswords.com');
  assert.equal(url.pathname, `/range/${hash.slice(0, 5)}`);
  assert.equal(url.search, '');
  assert.ok(!url.href.includes(hash.slice(5)), 'the suffix never leaves the process');
  assert.ok(
    !url.href.includes(encodeURIComponent(password)),
    'the password never leaves the process'
  );
  assert.equal(init.body, undefined, 'nothing is sent in a body');
  const headers = new Headers(init.headers);
  assert.equal(headers.get('add-padding'), 'true');
  assert.match(headers.get('user-agent') ?? '', /SIEMBox/);
  assert.equal(init.redirect, 'manual');
});

test('a matching suffix returns pwned with its count', async () => {
  const password = 'P@ssw0rd';
  const hash = sha1(password);
  const { fetchImpl } = fakeFetch(
    () => new Response(rangeBody([[hash.slice(5), 52256]]), { status: 200 })
  );
  assert.deepEqual(await checkPassword(password, { fetchImpl }), { pwned: true, count: 52256 });
});

test('padded zero-count rows are ignored, even if one carries our suffix', async () => {
  const password = 'a-password-that-only-appears-as-padding';
  const hash = sha1(password);
  const { fetchImpl } = fakeFetch(
    () => new Response(rangeBody([[hash.slice(5), 0]]), { status: 200 })
  );
  assert.deepEqual(await checkPassword(password, { fetchImpl }), { pwned: false, count: 0 });
});

test('a password whose suffix is not in the range is not pwned', async () => {
  const { fetchImpl } = fakeFetch(() => new Response(rangeBody([]), { status: 200 }));
  assert.deepEqual(await checkPassword('Xq7#not-in-the-corpus-9vL', { fetchImpl }), {
    pwned: false,
    count: 0,
  });
});

test('suffix matching is case-insensitive and tolerates LF line endings', () => {
  assert.equal(findSuffixCount('aaaaa:1\nabcdef0123:7\n', 'ABCDEF0123'), 7);
  assert.equal(findSuffixCount('ABCDEF0123:0\n', 'ABCDEF0123'), 0);
  assert.equal(findSuffixCount('garbage\n:5\nABCDEF0123:x\n', 'ABCDEF0123'), 0);
});

test('HTTP errors, unreachable hosts and timeouts reject without leaking the hash', async () => {
  const password = 'hunter2';
  const hash = sha1(password);
  const failures: FetchFn[] = [
    async () => new Response('busy', { status: 503 }),
    async () => {
      throw new TypeError('fetch failed');
    },
    (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener('abort', () =>
          reject(new DOMException('aborted', 'AbortError'))
        );
      }),
  ];
  for (const fetchImpl of failures) {
    await assert.rejects(checkPassword(password, { fetchImpl, timeoutMs: 20 }), (err: unknown) => {
      assert.ok(err instanceof PwnedPasswordsError);
      assert.ok(!err.message.includes(hash.slice(0, 5)) && !err.message.includes(hash.slice(5)));
      assert.ok(!err.message.includes(password));
      return true;
    });
  }
});

test('an empty password is refused before any request is made', async () => {
  const { fetchImpl, calls } = fakeFetch(() => new Response('', { status: 200 }));
  await assert.rejects(checkPassword('', { fetchImpl }), PwnedPasswordsError);
  assert.equal(calls.length, 0);
});
