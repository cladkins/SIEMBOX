import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { TrivyScanner } from '../services/scanner/trivyScanner';
import { DockerDiscovery } from '../services/scanner/dockerDiscovery';

const router = Router();

// Enumerate images already present on the Docker host (if the socket is mounted)
// so the operator can scan one without typing the reference. Always 200: when the
// socket isn't available the body carries { available: false, reason } so the UI
// can show guidance rather than treating it as an error.
router.get('/discovered', async (_req: Request, res: Response) => {
  try {
    res.json(await DockerDiscovery.discoverImages());
  } catch (error) {
    throw new ApiError(500, 'Failed to enumerate Docker images');
  }
});

// Start a container image scan (Trivy). Body: { image_ref: "nginx:latest" }.
router.post('/scan', async (req: Request, res: Response) => {
  try {
    const imageRef = (req.body?.image_ref ?? req.body?.imageRef ?? '').toString().trim();
    if (!imageRef) {
      throw new ApiError(400, 'image_ref is required');
    }
    if (!TrivyScanner.isValidImageRef(imageRef)) {
      throw new ApiError(400, 'Invalid image reference');
    }
    const userId = (req as any).user?.id || 1;
    const scanId = await TrivyScanner.scan(imageRef, userId);
    res.status(202).json({ scanId, status: 'queued' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to start container scan');
  }
});

// List recent container scans
router.get('/scans', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(Math.max(parseInt(String(req.query.limit)) || 20, 1), 100);
    res.json(await TrivyScanner.getRecentScans(limit));
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch container scans');
  }
});

// Get a single scan with its vulnerabilities
router.get('/scans/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      throw new ApiError(400, 'Invalid scan id');
    }
    const scan = await TrivyScanner.getScan(id);
    if (!scan) {
      throw new ApiError(404, 'Scan not found');
    }
    res.json(scan);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch container scan');
  }
});

export default router;
