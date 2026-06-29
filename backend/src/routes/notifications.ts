import { Router, Request, Response } from 'express';
import { NotificationChannelModel } from '../models/NotificationChannel';
import { NotificationService } from '../services/notifications/notificationService';
import { ApiError } from '../middleware/errorHandler';
import { query } from '../config/database';

const router = Router();

const CHANNEL_TYPES = ['slack', 'email', 'ntfy'];
const PREF_KEYS = [
  'notify_alerts_enabled',
  'notify_alerts_min_severity',
  'notify_vuln_enabled',
  'notify_vuln_min_severity',
  'notify_ingestion_enabled',
  'notify_ingestion_stall_minutes',
];

// ---- Channels ----

router.get('/channels', async (_req: Request, res: Response) => {
  res.json(await NotificationChannelModel.findAll());
});

router.post('/channels', async (req: Request, res: Response) => {
  const { name, channel_type, enabled, config } = req.body;
  if (!name || typeof name !== 'string') throw new ApiError(400, 'name is required');
  if (!CHANNEL_TYPES.includes(channel_type)) throw new ApiError(400, "channel_type must be 'slack', 'email', or 'ntfy'");
  const created = await NotificationChannelModel.create({ name, channel_type, enabled, config: config || {} });
  res.status(201).json(created);
});

router.put('/channels/:id', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) throw new ApiError(400, 'Invalid id');
  const existing = await NotificationChannelModel.findById(id);
  if (!existing) throw new ApiError(404, 'Channel not found');
  const { name, channel_type, enabled, config } = req.body;
  if (channel_type !== undefined && !CHANNEL_TYPES.includes(channel_type)) {
    throw new ApiError(400, "channel_type must be 'slack', 'email', or 'ntfy'");
  }
  res.json(await NotificationChannelModel.update(id, { name, channel_type, enabled, config }));
});

router.delete('/channels/:id', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) throw new ApiError(400, 'Invalid id');
  const ok = await NotificationChannelModel.delete(id);
  if (!ok) throw new ApiError(404, 'Channel not found');
  res.json({ message: 'Channel deleted' });
});

router.post('/channels/:id/test', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) throw new ApiError(400, 'Invalid id');
  const channel = await NotificationChannelModel.findById(id);
  if (!channel) throw new ApiError(404, 'Channel not found');
  try {
    await NotificationService.testChannel(channel);
    res.json({ message: 'Test notification sent' });
  } catch (err: any) {
    throw new ApiError(400, `Test failed: ${err.message}`);
  }
});

// Preview the real new-alert email: dispatches a sample alert (in the exact
// new-alert format) to every enabled channel and reports per-channel outcomes.
router.post('/test-alert', async (_req: Request, res: Response) => {
  const results = await NotificationService.sendTestAlert();
  if (results.length === 0) {
    res.json({ message: 'No enabled notification channels — add and enable one first.', results });
    return;
  }
  const ok = results.filter((r) => r.ok).length;
  const failed = results.filter((r) => !r.ok);
  res.json({
    message: failed.length
      ? `Test alert: ${ok}/${results.length} channel(s) sent. Failed: ${failed.map((f) => `${f.name} (${f.error})`).join('; ')}`
      : `Test alert sent to ${ok} channel(s) — check your inbox.`,
    results,
  });
});

// ---- Per-event preferences (stored in system_settings) ----

router.get('/settings', async (_req: Request, res: Response) => {
  const r = await query(`SELECT key, value FROM system_settings WHERE key = ANY($1)`, [PREF_KEYS]);
  const out: Record<string, string> = {};
  r.rows.forEach((row: { key: string; value: string }) => {
    out[row.key] = row.value;
  });
  res.json(out);
});

router.put('/settings', async (req: Request, res: Response) => {
  const updates = req.body || {};
  const keys = Object.keys(updates).filter((k) => PREF_KEYS.includes(k));
  for (const k of keys) {
    await query(
      `INSERT INTO system_settings (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [k, String(updates[k])]
    );
  }
  res.json({ message: 'Settings updated', updated: keys });
});

export default router;
