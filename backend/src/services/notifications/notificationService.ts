/**
 * Notification Service
 *
 * Sends notifications to configured channels (Slack / Email / NTFY) for alerts,
 * vulnerability findings, and log-ingestion health. Per-event preferences
 * (enabled + minimum severity) live in system_settings; channels live in the
 * notification_channels table. All sends are best-effort — a failing channel is
 * logged and never blocks the others or the calling code.
 */

import nodemailer from 'nodemailer';
import { NotificationChannelModel, NotificationChannel } from '../../models/NotificationChannel';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { ErrorLogService } from '../errors/errorLogService';

const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface NotificationMessage {
  title: string;
  body: string;
  severity?: string;
}

export interface ChannelResult {
  name: string;
  type: string;
  ok: boolean;
  error?: string;
}

/** Build the exact message a real new-alert notification produces (shared by the
 *  live alert path and the test-alert preview so the email is identical). */
export function buildAlertMessage(params: { severity: string; ruleName: string; title: string; description?: string }): NotificationMessage {
  return {
    title: `[SIEMBox] ${params.severity.toUpperCase()} alert: ${params.title}`,
    body: `Rule: ${params.ruleName}\nSeverity: ${params.severity}\n${params.description || ''}`.trim(),
    severity: params.severity,
  };
}

/**
 * One message for several rules that all fired on the SAME event.
 *
 * Detection rules are independent hypotheses about one piece of evidence, so a
 * single nasty request routinely satisfies more than one — `;cat /etc/passwd`
 * is both suspicious punctuation (PROXY-001) and a command-injection signature
 * (PROXY-002). Sending one notification per rule pages the operator three times
 * for one event and reads as three problems instead of one seen three ways.
 *
 * The worst severity leads, because that is what decides how urgently someone
 * has to look; the rest are listed as corroboration.
 */
export function buildAlertGroupMessage(
  alerts: Array<{ severity: string; ruleName: string; title: string; description?: string }>
): NotificationMessage {
  // One alert is not a group: fall through to the original message rather than
  // emitting "1 detection rules matched" and "(+0 more)". Held here rather than
  // in the caller so the guarantee cannot be lost by a future call site.
  if (alerts.length === 1) return buildAlertMessage(alerts[0]);

  const worst = [...alerts].sort(
    (a, b) => (SEVERITY_RANK[b.severity?.toLowerCase()] ?? 0) - (SEVERITY_RANK[a.severity?.toLowerCase()] ?? 0)
  )[0];

  const lines = [
    `${alerts.length} detection rules matched a single event.`,
    '',
    ...alerts.map((a) => `- [${(a.severity || '').toUpperCase()}] ${a.ruleName}: ${a.title}`),
  ];
  if (worst.description) lines.push('', worst.description);

  return {
    title: `[SIEMBox] ${worst.severity.toUpperCase()} alert: ${worst.title} (+${alerts.length - 1} more)`,
    body: lines.join('\n').trim(),
    severity: worst.severity,
  };
}

async function getSetting(key: string, fallback: string): Promise<string> {
  try {
    const r = await query(`SELECT value FROM system_settings WHERE key = $1`, [key]);
    return r.rows[0]?.value ?? fallback;
  } catch {
    return fallback;
  }
}

export function severityPasses(eventSeverity: string | undefined, minSeverity: string): boolean {
  const ev = SEVERITY_RANK[(eventSeverity || 'info').toLowerCase()] ?? 0;
  const min = SEVERITY_RANK[(minSeverity || 'info').toLowerCase()] ?? 0;
  return ev >= min;
}

// ---- Per-channel senders ----

async function sendSlack(channel: NotificationChannel, msg: NotificationMessage): Promise<void> {
  const url = channel.config.webhook_url;
  if (!url) throw new Error('Slack channel is missing webhook_url');
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: `*${msg.title}*\n${msg.body}` }),
  });
  if (!res.ok) throw new Error(`Slack webhook returned HTTP ${res.status}`);
}

async function sendNtfy(channel: NotificationChannel, msg: NotificationMessage): Promise<void> {
  const server = String(channel.config.server_url || 'https://ntfy.sh').replace(/\/+$/, '');
  const topic = channel.config.topic;
  if (!topic) throw new Error('NTFY channel is missing topic');
  const headers: Record<string, string> = { Title: msg.title };
  if (msg.severity) {
    const priority: Record<string, string> = { info: '2', low: '2', medium: '3', high: '4', critical: '5' };
    headers.Priority = priority[msg.severity.toLowerCase()] || '3';
    headers.Tags = 'warning';
  }
  if (channel.config.token) headers.Authorization = `Bearer ${channel.config.token}`;
  const res = await fetch(`${server}/${topic}`, { method: 'POST', headers, body: msg.body });
  if (!res.ok) throw new Error(`NTFY returned HTTP ${res.status}`);
}

async function sendEmail(channel: NotificationChannel, msg: NotificationMessage): Promise<void> {
  const c = channel.config;
  if (!c.host || !c.to) throw new Error('Email channel is missing host or to');
  const port = c.port ? Number(c.port) : 587;
  const transport = nodemailer.createTransport({
    host: c.host,
    port,
    secure: c.secure === true || c.secure === 'true' || port === 465,
    auth: c.user ? { user: c.user, pass: c.password } : undefined,
  });
  await transport.sendMail({
    from: c.from || c.user || 'siembox@localhost',
    to: c.to,
    subject: msg.title,
    text: msg.body,
  });
}

async function sendToChannel(channel: NotificationChannel, msg: NotificationMessage): Promise<void> {
  switch (channel.channel_type) {
    case 'slack': return sendSlack(channel, msg);
    case 'ntfy': return sendNtfy(channel, msg);
    case 'email': return sendEmail(channel, msg);
    default: throw new Error(`Unknown channel type: ${channel.channel_type}`);
  }
}

// Fan out to every enabled channel; isolate failures per channel and report the
// per-channel outcome (used by the test-alert preview so the UI can show what sent).
async function dispatchWithResults(msg: NotificationMessage): Promise<ChannelResult[]> {
  const channels = await NotificationChannelModel.findEnabled();
  return Promise.all(
    channels.map(async (ch): Promise<ChannelResult> => {
      try {
        await sendToChannel(ch, msg);
        return { name: ch.name, type: ch.channel_type, ok: true };
      } catch (err) {
        const error = err instanceof Error ? err.message : String(err);
        logger.error(`[Notifications] ${ch.channel_type} channel "${ch.name}" failed:`, err);
        return { name: ch.name, type: ch.channel_type, ok: false, error };
      }
    })
  );
}

// Best-effort fan-out for real events. Per-channel failures don't stop the
// others, but they DO get surfaced: a notification channel that silently stops
// delivering means alerts stop reaching anyone, which is the one failure an
// operator must not have to find by reading container logs. Deduped per
// channel by errorLogService so a persistently broken webhook logs once a
// minute, not once per alert. The interactive "Test" path is excluded — the
// route already reports those failures straight back to the user.
async function dispatch(msg: NotificationMessage): Promise<void> {
  const results = await dispatchWithResults(msg);
  for (const result of results.filter((r) => !r.ok)) {
    ErrorLogService.logBackgroundError(
      'notifications',
      `${result.type} channel "${result.name}" failed: ${result.error}`,
      { dedupeKey: `${result.type}:${result.name}`, channel: result.name, channelType: result.type }
    );
  }
}

export const NotificationService = {
  // Used by the "Test" button — throws so the route can report the failure.
  async testChannel(channel: NotificationChannel): Promise<void> {
    await sendToChannel(channel, {
      title: 'SIEMBox test notification',
      body: `This is a test from SIEMBox for the "${channel.name}" channel.`,
      severity: 'info',
    });
  },

  async notifyAlert(params: { severity: string; ruleName: string; title: string; description?: string }): Promise<void> {
    return NotificationService.notifyAlertGroup([params]);
  },

  /**
   * Notify about every alert raised by ONE event, as a single message.
   *
   * The min-severity gate is applied per alert, exactly as it is for a lone
   * alert, and only the survivors are reported — so grouping never causes an
   * alert to be announced that would have been filtered out on its own. A group
   * of one produces the identical message `notifyAlert` always sent, which is
   * what the EDR path and every single-rule event still get.
   */
  async notifyAlertGroup(
    alerts: Array<{ severity: string; ruleName: string; title: string; description?: string }>
  ): Promise<void> {
    try {
      if (alerts.length === 0) return;
      if ((await getSetting('notify_alerts_enabled', 'false')) !== 'true') return;

      const minSeverity = await getSetting('notify_alerts_min_severity', 'high');
      const passing = alerts.filter((a) => severityPasses(a.severity, minSeverity));
      if (passing.length === 0) return;

      await dispatch(buildAlertGroupMessage(passing));
    } catch (err) {
      logger.error('[Notifications] notifyAlert failed:', err);
      ErrorLogService.logBackgroundError('notifications', err, { dedupeKey: 'notifyAlert' });
    }
  },

  // Explicit admin preview of the new-alert email. Uses the exact alert format and
  // the configured channels, but bypasses the enabled / min-severity gates so the
  // email can be previewed regardless of the current notification preferences.
  async sendTestAlert(): Promise<ChannelResult[]> {
    return dispatchWithResults(
      buildAlertMessage({
        severity: 'high',
        ruleName: 'SIEMBox Test Rule',
        title: 'Test alert — multiple failed logins from 203.0.113.10',
        description:
          'This is a TEST alert sent from Settings -> Notifications to preview the new-alert email. No real detection occurred.',
      })
    );
  },

  async notifyVulnScan(params: { target: string; severityCounts: Record<string, number> }): Promise<void> {
    try {
      if ((await getSetting('notify_vuln_enabled', 'false')) !== 'true') return;
      const min = await getSetting('notify_vuln_min_severity', 'high');
      const counts = params.severityCounts || {};
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      const passing = order.filter((s) => (counts[s] || 0) > 0 && severityPasses(s, min));
      if (passing.length === 0) return;
      const summary = order.filter((s) => (counts[s] || 0) > 0).map((s) => `${counts[s]} ${s}`).join(', ');
      await dispatch({
        title: `[SIEMBox] Vulnerabilities found on ${params.target}`,
        body: `Scan of ${params.target} found: ${summary}.`,
        severity: passing[0],
      });
    } catch (err) {
      logger.error('[Notifications] notifyVulnScan failed:', err);
      ErrorLogService.logBackgroundError('notifications', err, { dedupeKey: 'notifyVulnScan' });
    }
  },

  async notifyIngestion(params: { healthy: boolean; stallMinutes: number }): Promise<void> {
    try {
      if ((await getSetting('notify_ingestion_enabled', 'false')) !== 'true') return;
      await dispatch(
        params.healthy
          ? { title: '[SIEMBox] Log ingestion resumed', body: 'Logs are being received again.', severity: 'info' }
          : {
              title: '[SIEMBox] Log ingestion stalled',
              body: `No logs received in the last ${params.stallMinutes} minutes.`,
              severity: 'high',
            }
      );
    } catch (err) {
      logger.error('[Notifications] notifyIngestion failed:', err);
      ErrorLogService.logBackgroundError('notifications', err, { dedupeKey: 'notifyIngestion' });
    }
  },
};
