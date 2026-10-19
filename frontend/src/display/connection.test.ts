import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { FetchResult } from './client.ts';
import type { DisplaySnapshot } from './types.ts';
import {
  OFFLINE_AFTER_MS,
  freshness,
  initialState,
  nextDelay,
  onResult,
  refusalMessage,
  retryNowOnWake,
  type ConnectionState,
} from './connection.ts';

const ok: FetchResult = { ok: true, snapshot: {} as DisplaySnapshot, sentAt: 0, receivedAt: 0 };
const fail = (error: Extract<FetchResult, { ok: false }>['error'], extra = {}): FetchResult => ({ ok: false, error, ...extra });
const MID = 0.5; // no jitter

function after(results: FetchResult[], start: ConnectionState = initialState()): ConnectionState {
  return results.reduce((s, r, i) => onResult(s, r, 1000 * (i + 1)), start);
}

describe('connection state', () => {
  it('is connecting until the first snapshot, then live', () => {
    assert.equal(freshness(initialState(), 0, 30), 'connecting');
    const s = onResult(initialState(), ok, 10_000);
    assert.equal(freshness(s, 10_000 + 59_000, 30), 'live');
  });

  it('lags after 2× refresh and is offline after 5 minutes', () => {
    const s = onResult(initialState(), ok, 0);
    assert.equal(freshness(s, 60_001, 30), 'lagging');
    assert.equal(freshness(s, OFFLINE_AFTER_MS, 30), 'lagging');
    assert.equal(freshness(s, OFFLINE_AFTER_MS + 1, 30), 'offline');
  });

  it('keeps the last success through errors, and clears errors on success', () => {
    const s = after([ok, fail('network'), fail('unavailable')]);
    assert.equal(s.lastSuccessAt, 1000);
    assert.equal(s.failures, 2);
    assert.equal(s.lastError, 'unavailable');
    const back = onResult(s, ok, 9000);
    assert.deepEqual(back, { ...initialState(), lastSuccessAt: 9000 });
  });
});

describe('when to fetch again', () => {
  it('polls at the refresh rate ±10 % while healthy', () => {
    const s = onResult(initialState(), ok, 0);
    assert.equal(nextDelay(s, 30, MID), 30_000);
    assert.equal(nextDelay(s, 30, 0), 27_000);
    assert.equal(nextDelay(s, 30, 0.999_999), 33_000);
  });

  it('backs off 5, 10, 20, 40 s, then every 60 s (±20 %)', () => {
    let s = initialState();
    const delays: Array<number | null> = [];
    for (let i = 0; i < 7; i += 1) {
      s = onResult(s, fail(i % 2 ? 'network' : 'unavailable'), i);
      delays.push(nextDelay(s, 30, MID));
    }
    assert.deepEqual(delays, [5000, 10_000, 20_000, 40_000, 60_000, 60_000, 60_000]);
    assert.equal(nextDelay(s, 30, 0), 48_000);
    assert.equal(nextDelay(s, 30, 0.999_999), 72_000);
  });

  it('waits for Retry-After on 429', () => {
    const s = onResult(initialState(), fail('rate_limited', { retryAfter: 90 }), 0);
    assert.equal(nextDelay(s, 30, MID), 90_000);
    assert.equal(freshness(s, 0, 30), 'connecting');
  });

  it('checks a refused link again on its own schedule, and stops only when revoked or missing', () => {
    const delay = (error: 'invalid' | 'revoked' | 'expired' | 'paused' | 'not_allowed' | 'token_required') =>
      nextDelay(onResult(initialState(), fail(error), 0), 30, MID);
    assert.equal(delay('paused'), 60_000);
    assert.equal(delay('not_allowed'), 300_000);
    assert.equal(delay('invalid'), 600_000);
    assert.equal(delay('expired'), 600_000);
    assert.equal(delay('revoked'), null);
    assert.equal(delay('token_required'), null);
  });

  it('a paused link resumes by itself on the next good answer', () => {
    const paused = onResult(onResult(initialState(), ok, 0), fail('paused'), 1000);
    assert.equal(paused.refusal, 'paused');
    assert.equal(paused.lastSuccessAt, 0);
    const resumed = onResult(paused, ok, 61_000);
    assert.equal(resumed.refusal, null);
    assert.equal(nextDelay(resumed, 30, MID), 30_000);
  });

  it('retries at once on wake only after a transient error', () => {
    assert.equal(retryNowOnWake(onResult(initialState(), ok, 0)), false);
    assert.equal(retryNowOnWake(onResult(initialState(), fail('network'), 0)), true);
    assert.equal(retryNowOnWake(onResult(initialState(), fail('revoked'), 0)), false);
  });
});

describe('refusal messages', () => {
  it('say what happened, with no sign-in prompt and no input box', () => {
    assert.equal(refusalMessage('token_required', null).title, 'This page needs a display link.');
    assert.match(refusalMessage('invalid', null).title, /isn't valid any more/);
    assert.equal(refusalMessage('revoked', null).title, 'This display link was revoked.');
    assert.equal(refusalMessage('expired', '3 Nov').title, 'This display link expired on 3 Nov.');
    assert.equal(refusalMessage('paused', null).title, 'Paused by an administrator.');
    assert.match(refusalMessage('not_allowed', null).title, /network isn't allowed/);
    for (const r of ['token_required', 'invalid', 'revoked', 'expired', 'paused', 'not_allowed'] as const) {
      const m = refusalMessage(r, null);
      assert.doesNotMatch(`${m.title} ${m.detail}`, /sign in|log in|password/i);
    }
  });

  it('keeps the expiry date on the expired state', () => {
    const s = onResult(initialState(), fail('expired', { expiresAt: '2026-11-03T00:00:00Z' }), 0);
    assert.equal(s.expiresAt, '2026-11-03T00:00:00Z');
  });
});
