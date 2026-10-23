/**
 * Download the SigmaHQ release archive.
 *
 * Not the GitHub REST API (unauthenticated it allows 60 requests an hour per
 * address): the release asset's own "latest" link,
 *   https://github.com/SigmaHQ/sigma/releases/latest/download/<asset>
 * answers 302 to /releases/download/<tag>/<asset>, which names the release
 * tag, and that answers 302 to GitHub's asset storage. Each redirect is
 * followed by hand and must stay on HTTPS and on GITHUB_ASSET_HOSTS, so the
 * download can never be pointed anywhere else. When the tag is the one already
 * cached, nothing is downloaded (the daily check costs one small request).
 *
 * Bounded: one timeout covers the whole exchange, the body is read with a
 * running byte cap (a missing or false Content-Length changes nothing), and
 * the archive must start with a zip signature.
 */
import { SIGMAHQ_REPO, SIGMA_ZIP_LIMITS } from './sigmaLibrary';

/** The only hosts a SigmaHQ download may touch (DEPLOYMENT.md lists them). */
export const GITHUB_ASSET_HOSTS = new Set([
  'github.com',
  'release-assets.githubusercontent.com',
  'objects.githubusercontent.com',
]);

export const SIGMA_FETCH_TIMEOUT_MS = 60_000;
const MAX_REDIRECTS = 4;
const TAG_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export type SigmaFetcher = (url: string, init: RequestInit) => Promise<Response>;

export class SigmaFetchError extends Error {}

export function latestAssetUrl(asset: string): string {
  return `https://github.com/${SIGMAHQ_REPO}/releases/latest/download/${encodeURIComponent(asset)}`;
}

/** The release tag in a /<repo>/releases/download/<tag>/<asset> URL, or null. */
export function tagFromDownloadUrl(url: URL, asset: string): string | null {
  if (url.hostname !== 'github.com') return null;
  const parts = url.pathname.split('/').filter(Boolean).map((p) => decodeURIComponent(p));
  const [owner, repo, releases, download, tag, file] = parts;
  if (parts.length !== 6 || `${owner}/${repo}`.toLowerCase() !== SIGMAHQ_REPO.toLowerCase()) return null;
  if (releases !== 'releases' || download !== 'download' || file !== asset) return null;
  return TAG_RE.test(tag) ? tag : null;
}

function allowedUrl(raw: string, base?: URL): URL {
  let url: URL;
  try {
    url = new URL(raw, base);
  } catch {
    throw new SigmaFetchError('SigmaHQ download: a redirect has an unreadable location');
  }
  if (url.protocol !== 'https:' || !GITHUB_ASSET_HOSTS.has(url.hostname) || url.username || url.password || url.port) {
    throw new SigmaFetchError(`SigmaHQ download: refused a redirect to ${url.protocol}//${url.hostname} (only GitHub release hosts are allowed)`);
  }
  return url;
}

async function readCapped(res: Response, cap: number): Promise<Buffer> {
  const declared = Number(res.headers.get('content-length') ?? '');
  if (Number.isFinite(declared) && declared > cap) {
    throw new SigmaFetchError(`SigmaHQ download: the archive is ${declared} bytes; the limit is ${cap}`);
  }
  if (!res.body) return Buffer.alloc(0);
  const chunks: Buffer[] = [];
  let total = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) {
      await reader.cancel().catch(() => undefined);
      throw new SigmaFetchError(`SigmaHQ download: the archive is over the ${cap}-byte limit`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

/**
 * Resolve the latest release of `asset` and download it, unless its tag is
 * `currentTag` (then `archive` is absent). Throws SigmaFetchError (or the
 * fetch's own network error) on any failure.
 */
export async function fetchSigmaRelease(
  asset: string,
  opts: { currentTag?: string | null; fetcher?: SigmaFetcher; timeoutMs?: number } = {}
): Promise<{ tag: string; archive?: Buffer }> {
  const fetcher = opts.fetcher ?? ((url, init) => fetch(url, init));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? SIGMA_FETCH_TIMEOUT_MS);
  try {
    let url = allowedUrl(latestAssetUrl(asset));
    let tag: string | null = null;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const res = await fetcher(url.toString(), {
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': 'SIEMBox', Accept: 'application/octet-stream' },
      });
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get('location');
        await res.body?.cancel().catch(() => undefined);
        if (!location) throw new SigmaFetchError(`SigmaHQ download: HTTP ${res.status} without a location`);
        url = allowedUrl(location, url);
        tag ??= tagFromDownloadUrl(url, asset);
        if (tag && opts.currentTag && tag === opts.currentTag) return { tag };
        continue;
      }
      if (res.status === 404) {
        await res.body?.cancel().catch(() => undefined);
        throw new SigmaFetchError(`SigmaHQ download: the latest release has no asset ${asset}`);
      }
      if (res.status !== 200) {
        await res.body?.cancel().catch(() => undefined);
        throw new SigmaFetchError(`SigmaHQ download: HTTP ${res.status}`);
      }
      if (!tag) {
        await res.body?.cancel().catch(() => undefined);
        throw new SigmaFetchError('SigmaHQ download: could not tell which release the archive belongs to');
      }
      const archive = await readCapped(res, SIGMA_ZIP_LIMITS.maxArchiveBytes);
      if (archive.length < 4 || archive.readUInt32LE(0) !== 0x04034b50) {
        throw new SigmaFetchError('SigmaHQ download: the asset is not a zip archive');
      }
      return { tag, archive };
    }
    throw new SigmaFetchError('SigmaHQ download: too many redirects');
  } catch (error) {
    if (controller.signal.aborted) throw new SigmaFetchError(`SigmaHQ download: timed out after ${Math.round((opts.timeoutMs ?? SIGMA_FETCH_TIMEOUT_MS) / 1000)} s`);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
