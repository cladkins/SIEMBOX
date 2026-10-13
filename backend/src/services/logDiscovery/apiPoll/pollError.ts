// Errors a poll adapter throws when it knows what went wrong and what the admin
// should do about it. The message is what lands in the source's last_error (and
// so in the Log Discovery and Shippers UI); human/resolution feed the
// dashboard's error log instead of the poller's generic "couldn't reach" text.
// Any other thrown error is reported as before.

export type PollErrorCategory = 'authentication' | 'configuration' | 'network';

export interface PollErrorDetails {
  /** One-line summary for the dashboard's error log. */
  human: string;
  /** What to do about it, for the dashboard's error log. */
  resolution: string;
  category: PollErrorCategory;
}

export class PollError extends Error {
  readonly human: string;
  readonly resolution: string;
  readonly category: PollErrorCategory;

  constructor(message: string, details: PollErrorDetails) {
    super(message);
    this.name = 'PollError';
    this.human = details.human;
    this.resolution = details.resolution;
    this.category = details.category;
  }
}

// Socket and TLS failures an admin can fix from the source's settings (address,
// port, HTTPS switch), keyed by Node's error code.
const CONNECT_HINTS: Record<string, string> = {
  ECONNREFUSED: 'connection refused; check the address and port',
  EHOSTUNREACH: 'host unreachable; check the address',
  ENETUNREACH: 'network unreachable; check the address',
  EHOSTDOWN: 'host is down; check that the device is online',
  ETIMEDOUT: 'connection timed out; check the address and that the device is online',
  ECONNRESET: 'connection reset; if this port serves HTTPS, turn HTTPS on',
  EPROTO: 'TLS handshake failed; if this port serves plain HTTP, turn HTTPS off',
  ERR_SSL_WRONG_VERSION_NUMBER: 'TLS handshake failed; if this port serves plain HTTP, turn HTTPS off',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'the HTTPS certificate is self-signed and not trusted',
  SELF_SIGNED_CERT_IN_CHAIN: 'the HTTPS certificate chain is not trusted',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'the HTTPS certificate could not be verified',
  CERT_HAS_EXPIRED: 'the HTTPS certificate has expired',
  ERR_TLS_CERT_ALTNAME_INVALID: 'the HTTPS certificate does not match the address',
};

/**
 * Message for a poll that never got an HTTP answer (refused, unreachable, timed
 * out, TLS mismatch), naming the URL it tried so a wrong port or HTTPS switch is
 * obvious. `url` must not carry a credential: callers pass an adapter's
 * describeUrl(). Returns null for anything that isn't such a failure.
 */
export function describeConnectFailure(err: unknown, url: string): string | null {
  const e = err as { code?: unknown; message?: unknown; name?: unknown } | null;
  const message = typeof e?.message === 'string' ? e.message : '';
  if (e?.name === 'AbortError' || message === 'Fetch timed out') {
    return `Couldn't connect to ${url}: no answer within the poll timeout; check the address, port and HTTPS setting`;
  }
  const code = typeof e?.code === 'string' ? e.code : '';
  const hint = CONNECT_HINTS[code] || (/wrong version number/i.test(message) ? CONNECT_HINTS.EPROTO : '');
  return hint ? `Couldn't connect to ${url}: ${hint} (${message || code})` : null;
}
