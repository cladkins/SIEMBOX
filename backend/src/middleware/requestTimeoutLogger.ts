import { Request, Response, NextFunction } from 'express';
import { ErrorLogService } from '../services/errors/errorLogService';

/**
 * Make client-side request timeouts visible in the Admin dashboard's Recent
 * Errors panel.
 *
 * The gap this closes: when an endpoint is merely SLOW, the browser's HTTP
 * client aborts at its timeout and shows a "Request timed out" banner — but the
 * server never threw, so nothing reached the error handler and nothing was
 * logged. The failure the operator saw was invisible to the very panel meant to
 * surface failures.
 *
 * This detects the exact event behind that banner: the client closing the
 * connection while the response was still in flight (`res` closes before the
 * handler finished writing it). It records that as a timeout error — throttled
 * per method+path by ErrorLogService so a repeatedly-slow endpoint collapses to
 * one counted row, and gated by a minimum age so instant navigations/cancels
 * (which never show a timeout banner) are ignored.
 */
export function requestTimeoutLogger(minElapsedMs = 5000) {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Only API traffic; static/asset aborts are noise and never show a banner.
    if (!req.path.startsWith('/api')) return next();

    const start = Date.now();
    res.on('close', () => {
      // A finished response has writableEnded === true. If it's false, the
      // socket closed before the server sent the reply — the client gave up.
      if (res.writableEnded) return;
      const elapsed = Date.now() - start;
      if (elapsed < minElapsedMs) return; // fast cancel/navigation, not a timeout

      const err = new Error(
        `Request timeout: client closed the connection after ${elapsed}ms before ` +
          `${req.method} ${req.path} responded (the endpoint was too slow).`
      );
      err.name = 'RequestTimeoutError';
      // 'timeout' in the message → categorized network/warning, not a crash.
      ErrorLogService.logBackgroundError('http', err, {
        dedupeKey: `client-timeout:${req.method} ${req.path}`,
        endpoint: req.path,
        method: req.method,
        userId: req.user?.id,
      });
    });

    next();
  };
}
