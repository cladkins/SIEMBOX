import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { explain } from '../services/ai/aiService';

const router = Router();

// "Explain this" assistant. Available to any authenticated user (read-only
// analysis), unlike the admin-only parser/detection generators. Reuses the
// configured provider/key; requires AI to be configured (Settings -> AI Builder).
router.post('/explain', async (req: Request, res: Response) => {
  try {
    const { kind, data, question } = req.body ?? {};
    const empty =
      data === undefined ||
      data === null ||
      (typeof data === 'string' && data.trim() === '');
    if (empty) {
      throw new ApiError(400, 'data is required');
    }
    const result = await explain({
      kind: typeof kind === 'string' && kind.trim() ? kind : 'artifact',
      data,
      question: typeof question === 'string' ? question : undefined,
    });
    res.json(result);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      500,
      `AI explain failed: ${error instanceof Error ? error.message : 'unknown error'}`
    );
  }
});

export default router;
