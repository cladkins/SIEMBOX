import { Request, Response, NextFunction } from 'express';
import { authenticate } from './auth';
import { hashToken, looksLikeTaxiiToken, TaxiiTokenModel } from '../services/hunting/taxiiTokens';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- augmenting @types/express's global Express.Request requires namespace declaration merging
  namespace Express {
    interface Request {
      /** Set when a TAXII client token (not a login) authenticated the request. */
      taxiiClient?: { tokenId: number; name: string };
    }
  }
}

const TAXII_CONTENT_TYPE = 'application/taxii+json;version=2.1';

/** The TAXII token in the request: `Authorization: Bearer sbx_taxii_...`, or Basic with the token as the password (or user name). */
function presentedToken(req: Request): string | null {
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) {
    const token = header.slice(7).trim();
    return looksLikeTaxiiToken(token) ? token : null;
  }
  if (header.startsWith('Basic ')) {
    let decoded: string;
    try {
      decoded = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8');
    } catch {
      return null;
    }
    const colon = decoded.indexOf(':');
    const user = colon >= 0 ? decoded.slice(0, colon) : decoded;
    const pass = colon >= 0 ? decoded.slice(colon + 1) : '';
    if (looksLikeTaxiiToken(pass)) return pass;
    if (looksLikeTaxiiToken(user)) return user;
    return '';
  }
  return null;
}

function unauthorized(res: Response, description: string): void {
  res
    .status(401)
    .set('WWW-Authenticate', 'Basic realm="SIEMBox TAXII", charset="UTF-8"')
    .type(TAXII_CONTENT_TYPE)
    .send(JSON.stringify({ title: 'Unauthorized', description, http_status: '401' }));
}

/**
 * The TAXII routes' login check: a TAXII client token (taxiiTokens.ts), or
 * else a signed-in user's session exactly as `authenticate` checks it (any
 * role may read the collection). A Basic header that carries no TAXII token
 * is refused: SIEMBox never takes a user's password over Basic auth.
 */
export const taxiiAuthenticate = async function taxiiAuthenticate(req: Request, res: Response, next: NextFunction) {
  const token = presentedToken(req);
  if (token === null) {
    authenticate(req, res, next);
    return;
  }
  if (!token) {
    unauthorized(res, 'Use a TAXII token (Settings in Threat Hunting) as the Basic auth password.');
    return;
  }
  try {
    const row = await TaxiiTokenModel.findForAuth(hashToken(token));
    if (!row) {
      unauthorized(res, 'The TAXII token is not valid or was revoked.');
      return;
    }
    req.taxiiClient = { tokenId: row.id, name: row.name };
    next();
  } catch (err) {
    next(err);
  }
};
