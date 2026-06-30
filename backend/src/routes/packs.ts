import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';
import { listPacksWithStatus, installPack } from '../services/packs/packsService';

const router = Router();

// List content packs, each annotated with how many of its parsers + detections
// are already installed (so the UI can show not-installed / partial / installed).
router.get('/', async (_req: Request, res: Response) => {
  try {
    const packs = await listPacksWithStatus();
    res.json(packs);
  } catch (error) {
    throw new ApiError(500, `Failed to list content packs: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Install (or update) every parser + detection a pack references. Admin only.
router.post('/:id/install', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const result = await installPack(req.params.id);
    res.json(result);
  } catch (error) {
    if (error instanceof Error && /Unknown content pack/.test(error.message)) {
      throw new ApiError(404, error.message);
    }
    throw new ApiError(500, `Failed to install pack: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

export default router;
