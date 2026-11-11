/**
 * TAXII login (middleware/taxiiAuth.ts): a TAXII client token in a Bearer or
 * Basic header, else the normal session check. A Basic header without a token
 * is refused (no user passwords over Basic). Hermetic: the token and session
 * lookups are stubbed.
 */
import { test, mock, before } from 'node:test';
import assert from 'node:assert/strict';
import type { Request, Response, NextFunction } from 'express';
import { TaxiiTokenModel, hashToken } from '../services/hunting/taxiiTokens';
import { SessionModel } from '../models/Session';
import { taxiiAuthenticate } from './taxiiAuth';

const GOOD = 'sbx_taxii_goodtoken123';

before(() => {
  mock.method(TaxiiTokenModel, 'findForAuth', async (hash: string) =>
    hash === hashToken(GOOD)
      ? { id: 5, name: 'opencti', token_prefix: 'sbx_taxii_good', created_by: 1, created_at: new Date(), last_used_at: null, revoked_at: null }
      : null
  );
  mock.method(SessionModel, 'findUserByToken', async () => null);
});

async function run(authorization?: string) {
  const req = { headers: authorization ? { authorization } : {} } as unknown as Request;
  let status = 0;
  let nextArg: unknown = 'not-called';
  const res = {
    status(code: number) {
      status = code;
      return this;
    },
    set() {
      return this;
    },
    type() {
      return this;
    },
    send() {
      return this;
    },
    json() {
      return this;
    },
  } as unknown as Response;
  await new Promise<void>((resolve) => {
    const next: NextFunction = (arg?: unknown) => {
      nextArg = arg;
      resolve();
    };
    void Promise.resolve(taxiiAuthenticate(req, res, next)).then(() => setTimeout(resolve, 20));
  });
  return { req, status, nextArg };
}

const basic = (user: string, pass: string) => `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;

test('a TAXII token as Bearer or as the Basic password gets in', async () => {
  for (const header of [`Bearer ${GOOD}`, basic('anything', GOOD), basic(GOOD, '')]) {
    const r = await run(header);
    assert.equal(r.nextArg, undefined, header);
    assert.deepEqual(r.req.taxiiClient, { tokenId: 5, name: 'opencti' });
  }
});

test('a wrong or revoked TAXII token is refused with 401', async () => {
  const r = await run('Bearer sbx_taxii_wrong');
  assert.equal(r.status, 401);
  assert.equal(r.req.taxiiClient, undefined);
});

test('Basic with a user password is refused, never checked as a login', async () => {
  const r = await run(basic('admin', 'hunter2'));
  assert.equal(r.status, 401);
});

test('anything else goes to the session check', async () => {
  const r = await run('Bearer some-session-token');
  assert.ok(r.nextArg instanceof Error);
  assert.match(String((r.nextArg as Error).message), /Invalid or expired session/);
  const anon = await run();
  assert.match(String((anon.nextArg as Error).message), /Authentication required/);
});
