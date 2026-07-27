import { Router, Request, Response } from 'express';
import { isIP } from 'net';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';
import { FeedService } from '../services/threatintel/feedService';
import { ReputationService, ProviderName } from '../services/threatintel/reputationService';
import { query } from '../config/database';

const router = Router();

// At-a-glance health of the threat-intel pipeline: is it fetching, and is
// anything acting on it? Answers "is threat intel actually working?" without
// scrolling the feeds table or querying the DB. Any authenticated user.
router.get('/summary', async (_req: Request, res: Response) => {
  try {
    const feeds = await FeedService.getFeeds();
    const enabled = feeds.filter((f) => f.enabled);
    const errored = enabled.filter((f) => f.last_status === 'error');
    const totalIndicators = enabled.reduce((n, f) => n + (f.indicator_count || 0), 0);
    const lastFetched = enabled
      .map((f) => f.last_fetched_at)
      .filter((t): t is string => !!t)
      .sort()
      .pop() || null;

    // How many alerts in the last 30 days were actually raised by a threat-feed
    // rule — i.e. is the intel being consumed, not just downloaded? Detected by
    // the {threat_feeds} enrichment the engine writes onto such alerts.
    const consumed = await query(
      `SELECT COUNT(*)::int AS alerts_30d
         FROM alerts
        WHERE created_at >= NOW() - INTERVAL '30 days'
          AND matched_data ? 'threat_feeds'`
    );

    res.json({
      feeds_enabled: enabled.length,
      feeds_total: feeds.length,
      feeds_errored: errored.length,
      total_indicators: totalIndicators,
      last_fetched_at: lastFetched,
      threat_feed_alerts_30d: consumed.rows[0]?.alerts_30d ?? 0,
    });
  } catch (error) {
    throw new ApiError(500, 'Failed to load threat-intel summary');
  }
});

// Overview: configured blocklist feeds (with status) + reputation providers
// (configured/enabled flags, never the keys). Any authenticated user may read.
router.get('/', async (_req: Request, res: Response) => {
  try {
    const [feeds, providers] = await Promise.all([
      FeedService.getFeeds(),
      ReputationService.getProvidersPublic(),
    ]);
    res.json({ feeds, providers });
  } catch (error) {
    throw new ApiError(500, 'Failed to load threat-intel configuration');
  }
});

// Enable/disable a feed or change its refresh interval (admin only).
router.put('/feeds/:id', authorize('admin'), async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) throw new ApiError(400, 'Invalid feed id');
  try {
    let feed = await FeedService.getFeed(id);
    if (!feed) throw new ApiError(404, 'Feed not found');
    if (typeof req.body?.enabled === 'boolean') {
      feed = (await FeedService.setFeedEnabled(id, req.body.enabled)) || feed;
    }
    if (req.body?.refresh_interval_minutes !== undefined) {
      const n = parseInt(String(req.body.refresh_interval_minutes), 10);
      if (Number.isNaN(n)) throw new ApiError(400, 'refresh_interval_minutes must be a number');
      feed = (await FeedService.setRefreshInterval(id, n)) || feed;
    }
    res.json(feed);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update feed');
  }
});

// Refresh one feed now (admin or operator).
router.post('/feeds/:id/refresh', authorize('admin', 'operator'), async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) throw new ApiError(400, 'Invalid feed id');
  const result = await FeedService.refreshFeed(id);
  res.json(result);
});

// Refresh all enabled feeds now (admin or operator).
router.post('/refresh', authorize('admin', 'operator'), async (_req: Request, res: Response) => {
  const result = await FeedService.refreshAllEnabled(true);
  res.json(result);
});

// Configure a reputation provider's key/enabled flag (admin only).
router.put('/providers/:name', authorize('admin'), async (req: Request, res: Response) => {
  const name = req.params.name as ProviderName;
  if (!['abuseipdb', 'otx'].includes(name)) throw new ApiError(400, 'Unknown provider');
  try {
    await ReputationService.saveProvider(name, {
      apiKey: req.body?.apiKey,
      enabled: req.body?.enabled,
    });
    const providers = await ReputationService.getProvidersPublic();
    res.json(providers.find((p) => p.name === name));
  } catch (error: any) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      500,
      error?.message?.includes('CREDENTIAL_ENCRYPTION_KEY')
        ? 'Set CREDENTIAL_ENCRYPTION_KEY to store a provider API key.'
        : 'Failed to save provider'
    );
  }
});

// Combined lookup for an IP: which feeds flag it + live reputation results.
router.get('/lookup/:ip', async (req: Request, res: Response) => {
  const ip = (req.params.ip || '').trim();
  if (!isIP(ip)) throw new ApiError(400, 'Invalid IP address');
  try {
    const [feeds, reputation] = await Promise.all([
      FeedService.lookupIp(ip),
      ReputationService.lookupIp(ip),
    ]);
    res.json({ ip, feeds, reputation });
  } catch (error) {
    throw new ApiError(500, 'Failed to look up IP reputation');
  }
});

export default router;
