import type { NextFunction, Request, Response } from 'express';

/**
 * 415 for a request whose Content-Encoding includes `br`, before any body
 * parser can hand it to the Brotli decoder (CVE-2026-111497). The header is a
 * comma-separated list of codings (RFC 9110 §8.4), compared case-insensitively;
 * any other coding, or none, passes through untouched. The body is not read.
 */
export function rejectBrotliBodies(req: Request, res: Response, next: NextFunction): void {
  const header = req.headers['content-encoding'];
  const value = Array.isArray(header) ? header.join(',') : header;
  if (value && value.split(',').some((coding) => coding.trim().toLowerCase() === 'br')) {
    res.setHeader('Connection', 'close'); // the unread body must not be parsed as the next request
    res.status(415).json({
      error: 'Unsupported Media Type',
      message: 'Brotli-encoded request bodies are not accepted; send the body uncompressed or gzip-encoded.',
    });
    return;
  }
  next();
}
