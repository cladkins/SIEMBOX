import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';
import { hasRequiredRole, UserRole } from '../middleware/scanPermissions';
import { listPacksWithStatus, installPack, PackError } from '../services/packs/packsService';

const router = Router();

// List content packs (from the catalog, or the bundled fallback), each with
// which of its parsers, detections and Sigma rules are installed, its install
// record and what the catalog added since. ?refresh=true re-reads the catalog
// (analyst and up; a viewer's call answers from the cache, as the catalog
// browse does).
router.get('/', async (req: Request, res: Response) => {
  try {
    const refresh = req.query.refresh === 'true' && hasRequiredRole(req.user?.role ?? '', UserRole.Analyst);
    res.json(await listPacksWithStatus({ refresh }));
  } catch (error) {
    throw new ApiError(500, `Failed to list content packs: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

async function install(req: Request, res: Response, onlyNew: boolean): Promise<void> {
  try {
    const user = req.user ? { id: req.user.id, username: req.user.username } : undefined;
    res.json(await installPack(req.params.id as string, { onlyNew, user }));
  } catch (error) {
    if (error instanceof PackError) {
      res.status(error.status).json({ code: error.code, message: error.message });
      return;
    }
    throw new ApiError(500, `Failed to install pack: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

// Install (or update) every item of a pack. Admin only.
router.post('/:id/install', authorize('admin'), (req: Request, res: Response) => install(req, res, false));

// Install only the items the catalog added to the pack since it was installed. Admin only.
router.post('/:id/install-new', authorize('admin'), (req: Request, res: Response) => install(req, res, true));

export default router;
