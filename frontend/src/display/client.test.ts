import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { classify, tokenFromHash } from './client.ts';

describe('the link token in the fragment', () => {
  it('is read from #k=', () => {
    assert.equal(tokenFromHash('#k=sbd1_abc'), 'sbd1_abc');
    assert.equal(tokenFromHash('#x=1&k=sbd1_abc'), 'sbd1_abc');
    assert.equal(tokenFromHash(''), null);
    assert.equal(tokenFromHash('#k='), null);
  });
});

describe('answers', () => {
  const refusal = (status: number, code: string, extra = {}) => classify(status, { status: 'error', code, ...extra }, null);

  it('map each refusal code to what the screen does', () => {
    assert.deepEqual(refusal(401, 'DISPLAY_TOKEN_REQUIRED'), { ok: false, error: 'token_required' });
    assert.deepEqual(refusal(401, 'DISPLAY_LINK_INVALID'), { ok: false, error: 'invalid' });
    assert.deepEqual(refusal(401, 'DISPLAY_LINK_REVOKED'), { ok: false, error: 'revoked' });
    assert.deepEqual(refusal(401, 'DISPLAY_LINK_EXPIRED', { expires_at: '2026-11-03T00:00:00.000Z' }), {
      ok: false,
      error: 'expired',
      expiresAt: '2026-11-03T00:00:00.000Z',
    });
    assert.deepEqual(refusal(403, 'DISPLAY_LINK_PAUSED'), { ok: false, error: 'paused' });
    assert.deepEqual(refusal(403, 'DISPLAY_NETWORK_NOT_ALLOWED'), { ok: false, error: 'not_allowed' });
  });

  it('treat 429 as a wait for Retry-After', () => {
    assert.deepEqual(classify(429, { code: 'RATE_LIMITED' }, '120'), { ok: false, error: 'rate_limited', retryAfter: 120 });
    assert.deepEqual(classify(429, null, null), { ok: false, error: 'rate_limited', retryAfter: 60 });
  });

  it('treat anything else that is not 200 as "keep showing and retry", never as a sign-out', () => {
    assert.deepEqual(classify(503, { code: 'DISPLAY_UNAVAILABLE' }, '5'), { ok: false, error: 'unavailable' });
    assert.deepEqual(classify(500, { code: 'DISPLAY_CONFIG_INVALID' }, null), { ok: false, error: 'unavailable' });
    // A 401 without a display code (a session-style answer) is not a refusal either.
    assert.deepEqual(classify(401, { code: 'TOKEN_EXPIRED' }, null), { ok: false, error: 'unavailable' });
    assert.deepEqual(classify(404, '<html>', null), { ok: false, error: 'unavailable' });
    assert.equal(classify(200, {}, null), null);
  });
});
