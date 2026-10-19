/**
 * Big Display while signed in (docs/architecture/BIG-DISPLAY.md §7.10): the
 * same board a display link shows, on the user's own session and role.
 * Mounted behind authenticate in app.ts, so a session that must change its
 * password is refused there (403 PASSWORD_CHANGE_REQUIRED) like any other.
 *
 * GET /snapshot builds the signed-in default views (SOC overview, Threats,
 * Health) in operations privacy, since the user can already read those labels
 * in the app. A panel the user's role may not see (endpoint health, for
 * anyone but an admin) comes back { state: 'forbidden' }, and no alarm comes
 * from it.
 */
import { Router, type NextFunction, type Request, type Response } from 'express';
import { SIGNED_IN_CONFIG, SIGNED_IN_NAME, snapshotBuilder } from '../services/display/snapshot';

const router = Router();

router.use(function noStore(_req: Request, res: Response, next: NextFunction) {
  res.set('Cache-Control', 'no-store');
  next();
});

router.get('/snapshot', async (req: Request, res: Response) => {
  res.json(await snapshotBuilder.build({ name: SIGNED_IN_NAME, configVersion: 1, config: SIGNED_IN_CONFIG, role: req.user!.role }));
});

export default router;
