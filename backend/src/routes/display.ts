/**
 * A wall screen's own read (docs/architecture/BIG-DISPLAY.md §4, §7.6).
 *
 * The only route a display link opens, and the only credential it takes: the
 * link's secret in X-Display-Token (middleware/displayAuth.ts). A session in
 * Authorization is neither needed nor read. Nothing here writes anything but
 * the throttled record of the screen's use.
 *
 * The snapshot carries the link's layout (`display`), the server's clock and
 * version (for the screen's clock offset and its reload on upgrade), and the
 * panels' data at the link's privacy level, built by
 * services/display/snapshot.ts from caches every screen shares.
 */
import { Router, type NextFunction, type Request, type Response } from 'express';
import { authenticateDisplay, displayTokenLimiter } from '../middleware/displayAuth';
import { parseDisplayConfig } from '../services/display/config';
import { snapshotBuilder } from '../services/display/snapshot';
import { logger } from '../utils/logger';

const router = Router();

/** Nothing a screen reads may be cached: refusals and data alike. */
router.use(function noStore(_req: Request, res: Response, next: NextFunction) {
  res.set('Cache-Control', 'no-store');
  next();
});

/** linkId -> when its invalid stored config was last logged. */
const invalidConfigLogged = new Map<number, number>();
const INVALID_CONFIG_LOG_MS = 60 * 60 * 1000;

router.get('/snapshot', displayTokenLimiter, authenticateDisplay, async (req: Request, res: Response) => {
  const link = req.displayLink!;
  // The row's config was validated when it was saved; read it back the same
  // way, so a row changed by hand (or left by a newer version with a panel
  // kind this one doesn't know) can't put something unchecked on a screen.
  // Answered here, and logged at most hourly per link: a screen polling every
  // 30 s must not add an application_errors row each time.
  const config = parseDisplayConfig(link.config);
  if (!config.ok) {
    const now = Date.now();
    const last = invalidConfigLogged.get(link.id);
    if (last === undefined || now - last >= INVALID_CONFIG_LOG_MS) {
      if (invalidConfigLogged.size >= 5000) invalidConfigLogged.clear();
      invalidConfigLogged.set(link.id, now);
      logger.error('Display link has a stored config that does not validate', { linkId: link.id, field: config.field });
    }
    res.status(500).json({
      status: 'error',
      statusCode: 500,
      code: 'DISPLAY_CONFIG_INVALID',
      message: "This display link's configuration is not valid. Ask an administrator to save it again.",
    });
    return;
  }
  res.json(await snapshotBuilder.build({ name: link.name, configVersion: link.config_version, config: config.value }));
});

export default router;
