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
 * panels' data. Panel data is built by the snapshot builder, which arrives
 * separately (Big Display PR 3): until then `panels`, `alarms` and
 * `attributions` are empty.
 */
import { Router, type NextFunction, type Request, type Response } from 'express';
import { authenticateDisplay, displayTokenLimiter } from '../middleware/displayAuth';
import { ApiError } from '../middleware/errorHandler';
import { describeDisplay, parseDisplayConfig } from '../services/display/config';
import { APP_VERSION } from '../utils/appVersion';
import { logger } from '../utils/logger';

const router = Router();

/** Nothing a screen reads may be cached: refusals and data alike. */
router.use(function noStore(_req: Request, res: Response, next: NextFunction) {
  res.set('Cache-Control', 'no-store');
  next();
});

router.get('/snapshot', displayTokenLimiter, authenticateDisplay, (req: Request, res: Response) => {
  const link = req.displayLink!;
  // The row's config was validated when it was saved; read it back the same
  // way, so a row changed by hand can't put something unchecked on a screen.
  const config = parseDisplayConfig(link.config);
  if (!config.ok) {
    logger.error('Display link has a stored config that does not validate', { linkId: link.id, field: config.field });
    throw new ApiError(500, "This display link's configuration is not valid. Ask an administrator to save it again.");
  }
  const now = new Date().toISOString();
  res.json({
    generated_at: now,
    server_time: now,
    app_version: APP_VERSION,
    display: describeDisplay(link.name, link.config_version, config.value),
    alarms: [],
    attributions: [],
    panels: {},
  });
});

export default router;
