/**
 * The SigmaHQ download, against a fake GitHub (no network): the redirect chain
 * names the tag, an unchanged tag downloads nothing, redirects off GitHub's
 * hosts are refused, and the size cap and timeout hold. Run with `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fetchSigmaRelease, tagFromDownloadUrl, type SigmaFetcher } from './sigmaFetch';
import { SIGMA_ZIP_LIMITS } from './sigmaLibrary';
import { fixtureArchive } from './sigmaFixture.test';

const ASSET = 'sigma_core+.zip';
const LATEST = 'https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core%2B.zip';
const TAGGED = 'https://github.com/SigmaHQ/sigma/releases/download/r2099-01-01/sigma_core+.zip';
const STORAGE = 'https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?sig=x';

function redirect(location: string): Response {
  return new Response(null, { status: 302, headers: { location } });
}

/** A fake GitHub: latest -> tagged -> storage -> the archive. Records each URL asked for. */
function fakeGitHub(body: Buffer | Uint8Array = fixtureArchive('fx'), overrides: Record<string, () => Response> = {}) {
  const asked: string[] = [];
  const fetcher: SigmaFetcher = async (url, init) => {
    asked.push(url);
    assert.equal(init.redirect, 'manual');
    if (overrides[url]) return overrides[url]();
    if (url === LATEST) return redirect(TAGGED);
    if (url === TAGGED) return redirect(STORAGE);
    if (url === STORAGE) return new Response(body, { status: 200 });
    return new Response('not found', { status: 404 });
  };
  return { fetcher, asked };
}

test('follows the release redirects, names the tag and returns the archive', async () => {
  const gh = fakeGitHub();
  const r = await fetchSigmaRelease(ASSET, { fetcher: gh.fetcher });
  assert.equal(r.tag, 'r2099-01-01');
  assert.ok(r.archive && r.archive.readUInt32LE(0) === 0x04034b50);
  assert.deepEqual(gh.asked, [LATEST, TAGGED, STORAGE]);
});

test('an unchanged release downloads nothing (one request)', async () => {
  const gh = fakeGitHub();
  const r = await fetchSigmaRelease(ASSET, { fetcher: gh.fetcher, currentTag: 'r2099-01-01' });
  assert.deepEqual(r, { tag: 'r2099-01-01' });
  assert.deepEqual(gh.asked, [LATEST]);
});

test('a redirect off GitHub, or off HTTPS, is refused before it is followed', async () => {
  for (const evil of ['https://evil.example/x.zip', 'http://release-assets.githubusercontent.com/x', 'https://github.com.evil.example/x']) {
    const gh = fakeGitHub(undefined, { [TAGGED]: () => redirect(evil) });
    await assert.rejects(fetchSigmaRelease(ASSET, { fetcher: gh.fetcher }), /refused a redirect/);
    assert.ok(!gh.asked.includes(evil));
  }
});

test('the archive size cap holds with and without a Content-Length', async () => {
  const big = new Uint8Array(SIGMA_ZIP_LIMITS.maxArchiveBytes + 1);
  const declared = fakeGitHub(undefined, {
    [STORAGE]: () => new Response(null, { status: 200, headers: { 'content-length': String(big.length) } }),
  });
  await assert.rejects(fetchSigmaRelease(ASSET, { fetcher: declared.fetcher }), /the limit is/);
  const streamed = fakeGitHub(big);
  await assert.rejects(fetchSigmaRelease(ASSET, { fetcher: streamed.fetcher }), /over the \d+-byte limit/);
});

test('not a zip, a missing asset, and an unknown release are errors', async () => {
  await assert.rejects(fetchSigmaRelease(ASSET, { fetcher: fakeGitHub(Buffer.from('<html>')).fetcher }), /not a zip/);
  const missing = fakeGitHub(undefined, { [LATEST]: () => new Response('', { status: 404 }) });
  await assert.rejects(fetchSigmaRelease(ASSET, { fetcher: missing.fetcher }), /no asset sigma_core\+\.zip/);
  const untagged = fakeGitHub(undefined, { [LATEST]: () => redirect(STORAGE) });
  await assert.rejects(fetchSigmaRelease(ASSET, { fetcher: untagged.fetcher }), /could not tell which release/);
});

test('a stalled download times out', async () => {
  const stalled: SigmaFetcher = (_url, init) =>
    new Promise((_resolve, reject) => init.signal!.addEventListener('abort', () => reject(new Error('aborted'))));
  await assert.rejects(fetchSigmaRelease(ASSET, { fetcher: stalled, timeoutMs: 50 }), /timed out/);
});

test('the tag is read only from a SigmaHQ download URL', () => {
  assert.equal(tagFromDownloadUrl(new URL(TAGGED), ASSET), 'r2099-01-01');
  assert.equal(tagFromDownloadUrl(new URL('https://github.com/other/repo/releases/download/r1/sigma_core+.zip'), ASSET), null);
  assert.equal(tagFromDownloadUrl(new URL('https://github.com/SigmaHQ/sigma/releases/download/r1/other.zip'), ASSET), null);
  assert.equal(tagFromDownloadUrl(new URL('https://github.com/SigmaHQ/sigma/releases/download/..%2F/sigma_core+.zip'), ASSET), null);
});
