/**
 * The one HTTP client the domain-monitor collectors use (crt.sh, IANA's RDAP
 * bootstrap file, registry RDAP servers). Every request:
 *  - is HTTPS only, a single GET, and never follows a redirect (a 3xx comes
 *    back to the caller as a status, so nothing is replayed to another host);
 *  - has a hard deadline (the whole exchange, not just socket idleness);
 *  - is capped in size: a Content-Length over the cap is refused before the
 *    body is read, and a body that grows past it is cut off;
 *  - asks for an uncompressed body, so the cap measures what is parsed;
 *  - can be pinned: `resolve` vets the host's addresses (netSafety.ts) at
 *    connect time and the socket connects only to those, with a fresh agent per
 *    request so no pooled socket skips the check.
 * Bodies are only read for 2xx responses.
 */
import https from 'https';
import type { IncomingHttpHeaders } from 'http';
import type { LookupFunction } from 'net';
import type { ResolvedAddress } from './netSafety';

export const DOMAIN_MONITOR_USER_AGENT =
  'SIEMBox-DomainMonitor/1.0 (+https://github.com/cladkins/siembox)';

export type HttpErrorKind = 'timeout' | 'network' | 'too_large' | 'blocked';

export class HttpError extends Error {
  readonly kind: HttpErrorKind;

  constructor(kind: HttpErrorKind, message: string) {
    super(message);
    this.name = 'HttpError';
    this.kind = kind;
  }
}

export interface HttpGetOptions {
  timeoutMs: number;
  maxBytes: number;
  headers?: Record<string, string>;
  /** Vetted resolution for the connection (see netSafety.resolvePublicAddresses). */
  resolve?: (hostname: string) => Promise<ResolvedAddress[]>;
  /** Test seam: replaces https.request. */
  request?: typeof https.request;
}

export interface HttpGetResult {
  status: number;
  headers: IncomingHttpHeaders;
  /** Empty for non-2xx responses (they are not read). */
  body: Buffer;
}

export type HttpGet = (url: URL, options: HttpGetOptions) => Promise<HttpGetResult>;

function pinnedLookup(resolve: NonNullable<HttpGetOptions['resolve']>): LookupFunction {
  return (hostname, options, callback) => {
    resolve(hostname).then(
      (addresses) => {
        const wanted =
          options.family === 4 || options.family === 'IPv4'
            ? 4
            : options.family === 6 || options.family === 'IPv6'
              ? 6
              : 0;
        const usable = wanted ? addresses.filter((a) => a.family === wanted) : addresses;
        if (usable.length === 0) {
          const err: NodeJS.ErrnoException = new Error(`no usable address for ${hostname}`);
          err.code = 'ENOTFOUND';
          callback(err, '', 0);
        } else if (options.all) {
          callback(null, usable);
        } else {
          callback(null, usable[0].address, usable[0].family);
        }
      },
      (err: NodeJS.ErrnoException) => callback(err, '', 0)
    );
  };
}

/** A refusal from the vetted lookup: 'blocked' by the rules, or 'network' when DNS merely failed. */
function unsafeTargetKind(err: unknown): HttpErrorKind | null {
  const e = err as { code?: unknown; retryable?: unknown } | null;
  if (e?.code !== 'ERR_UNSAFE_TARGET') return null;
  return e.retryable === true ? 'network' : 'blocked';
}

export const httpsGet: HttpGet = async (url, options) => {
  if (url.protocol !== 'https:') {
    throw new HttpError('blocked', `refusing a non-HTTPS URL (${url.protocol})`);
  }
  let deadline: NodeJS.Timeout | undefined;
  try {
    return await exchange(url, options, (timer) => {
      deadline = timer;
    });
  } finally {
    clearTimeout(deadline);
  }
};

function exchange(
  url: URL,
  options: HttpGetOptions,
  armDeadline: (timer: NodeJS.Timeout) => void
): Promise<HttpGetResult> {
  return new Promise<HttpGetResult>((resolvePromise, rejectPromise) => {
    let settled = false;
    const finish = (err: Error | null, result?: HttpGetResult) => {
      if (settled) return;
      settled = true;
      if (err) rejectPromise(err);
      else resolvePromise(result as HttpGetResult);
    };
    const tooLarge = () =>
      new HttpError('too_large', `the response is larger than ${options.maxBytes} bytes`);

    const request = options.request ?? https.request;
    const req = request(
      url,
      {
        method: 'GET',
        headers: {
          'User-Agent': DOMAIN_MONITOR_USER_AGENT,
          Accept: 'application/json',
          'Accept-Encoding': 'identity',
          ...options.headers,
        },
        agent: false,
        ...(options.resolve ? { lookup: pinnedLookup(options.resolve) } : {}),
      },
      (res) => {
        const status = res.statusCode ?? 0;
        if (status < 200 || status > 299) {
          finish(null, { status, headers: res.headers, body: Buffer.alloc(0) });
          res.destroy();
          return;
        }
        const declared = Number(res.headers['content-length']);
        if (Number.isFinite(declared) && declared > options.maxBytes) {
          finish(tooLarge());
          res.destroy();
          return;
        }
        const chunks: Buffer[] = [];
        let received = 0;
        res.on('data', (chunk: Buffer) => {
          received += chunk.length;
          if (received > options.maxBytes) {
            finish(tooLarge());
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () =>
          finish(null, { status, headers: res.headers, body: Buffer.concat(chunks) })
        );
        res.on('error', (err) => finish(new HttpError('network', err.message || 'read failed')));
        res.on('close', () => {
          if (!res.complete) finish(new HttpError('network', 'the response was cut off'));
        });
      }
    );

    // The deadline covers the whole exchange (connect, headers and body), not just idleness.
    armDeadline(
      setTimeout(() => {
        const err = new HttpError('timeout', `no complete response within ${options.timeoutMs} ms`);
        finish(err);
        req.destroy(err);
      }, options.timeoutMs)
    );

    req.on('error', (err) => {
      const refused = unsafeTargetKind(err);
      if (refused) finish(new HttpError(refused, err.message));
      else if (err instanceof HttpError) finish(err);
      else finish(new HttpError('network', err.message || 'the request failed'));
    });
    req.end();
  });
}
