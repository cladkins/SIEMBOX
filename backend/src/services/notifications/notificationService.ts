/**
 * Notification Service
 *
 * Sends notifications to configured channels (Slack / Email / NTFY) for alerts,
 * vulnerability findings, exposure findings, and log-ingestion health. Per-event preferences
 * (enabled + minimum severity) live in system_settings; channels live in the
 * notification_channels table. All sends are best-effort — a failing channel is
 * logged and never blocks the others or the calling code.
 */

import nodemailer from 'nodemailer';
import { NotificationChannelModel, NotificationChannel } from '../../models/NotificationChannel';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { ErrorLogService } from '../errors/errorLogService';
import { formatAlertRef } from '../alerts/alertRef';
import { getPublicUrl } from '../settings/publicUrl';
import {
  NotificationLink,
  alertLink,
  appLink,
  compactLinks,
  emailHtml,
  plainTextWithLinks,
  slackText,
} from './notificationLinks';

const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface NotificationMessage {
  title: string;
  body: string;
  severity?: string;
  /**
   * Links into the web UI, built from the public URL (none when it is unset).
   * Each channel renders them its own way; the first is the primary one
   * (ntfy's Click action).
   */
  links?: NotificationLink[];
}

/** `links` on the message only when there are some, so an unset public URL leaves the message as it was. */
function withLinks(msg: NotificationMessage, links: Array<NotificationLink | null>): NotificationMessage {
  const compact = compactLinks(links);
  return compact.length > 0 ? { ...msg, links: compact } : msg;
}

export interface ChannelResult {
  name: string;
  type: string;
  ok: boolean;
  error?: string;
}

/** One alert to announce. `id` is the alert's id, so the message can carry its
 *  ALR-#### reference; only the test-alert preview (no real alert) omits it. */
export interface AlertNotification {
  id?: number;
  severity: string;
  ruleName: string;
  title: string;
  description?: string;
}

/** `ALR-4821 ` (with the trailing space) or '' when the alert has no id. */
function refPrefix(a: AlertNotification): string {
  return a.id ? `${formatAlertRef(a.id)} ` : '';
}

/** Build the exact message a real new-alert notification produces (shared by the
 *  live alert path and the test-alert preview so the email is identical). With a
 *  public URL it links to the alert (or, for the preview, which has no alert, to
 *  the Alerts list). */
export function buildAlertMessage(params: AlertNotification, publicUrl?: string | null): NotificationMessage {
  const ref = params.id ? `Alert: ${formatAlertRef(params.id)}\n` : '';
  return withLinks(
    {
      title: `[SIEMBox] ${params.severity.toUpperCase()} alert ${refPrefix(params)}`.trimEnd() + `: ${params.title}`,
      body: `${ref}Rule: ${params.ruleName}\nSeverity: ${params.severity}\n${params.description || ''}`.trim(),
      severity: params.severity,
    },
    [params.id ? alertLink(publicUrl, params.id) : appLink(publicUrl, 'alerts', 'All alerts')]
  );
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
export function buildAlertGroupMessage(alerts: AlertNotification[], publicUrl?: string | null): NotificationMessage {
  // One alert is not a group: fall through to the original message rather than
  // emitting "1 detection rules matched" and "(+0 more)". Held here rather than
  // in the caller so the guarantee cannot be lost by a future call site.
  if (alerts.length === 1) return buildAlertMessage(alerts[0], publicUrl);

  const worst = [...alerts].sort(
    (a, b) => (SEVERITY_RANK[b.severity?.toLowerCase()] ?? 0) - (SEVERITY_RANK[a.severity?.toLowerCase()] ?? 0)
  )[0];

  const lines = [
    `${alerts.length} detection rules matched a single event.`,
    '',
    ...alerts.map((a) => `- ${refPrefix(a)}[${(a.severity || '').toUpperCase()}] ${a.ruleName}: ${a.title}`),
  ];
  if (worst.description) lines.push('', worst.description);

  // The worst alert first (the primary link), then the rest in listed order,
  // then the Alerts list.
  return withLinks(
    {
      title: `[SIEMBox] ${worst.severity.toUpperCase()} alert ${refPrefix(worst)}`.trimEnd() + `: ${worst.title} (+${alerts.length - 1} more)`,
      body: lines.join('\n').trim(),
      severity: worst.severity,
    },
    [
      alertLink(publicUrl, worst.id),
      ...alerts.map((a) => alertLink(publicUrl, a.id)),
      appLink(publicUrl, 'alerts', 'All alerts'),
    ]
  );
}

/** A new exposure finding (leaked credential, domain-monitor hit) to announce. */
export interface ExposureNotice {
  /** The alert the finding raised, for its ALR-#### reference. */
  alertId?: number;
  source: string;
  severity: string;
  title: string;
  description?: string;
}

// A grouped message lists at most this many findings; the rest are counted.
const EXPOSURE_GROUP_LIST_LIMIT = 10;

/**
 * One message for the exposure findings a check produced. A single finding
 * reads like an alert; several (a monitored email domain can surface many
 * accounts at once) become ONE message led by the worst finding, so a large
 * first run cannot fan out into a burst of Slack/email/ntfy messages.
 */
export function buildExposureMessage(findings: ExposureNotice[], publicUrl?: string | null): NotificationMessage {
  const rank = (f: ExposureNotice) => SEVERITY_RANK[f.severity?.toLowerCase()] ?? 0;
  const sorted = [...findings].sort((a, b) => rank(b) - rank(a));
  const worst = sorted[0];

  const digitalRisk = appLink(publicUrl, 'digitalRisk', 'Digital Risk');
  if (findings.length === 1) {
    // The alert the finding raised, or the Digital Risk page when it raised none.
    return withLinks(
      {
        title: `[SIEMBox] ${worst.severity.toUpperCase()} exposure: ${worst.title}`,
        body: `${worst.alertId ? `Alert: ${formatAlertRef(worst.alertId)}\n` : ''}Source: ${worst.source}\nSeverity: ${worst.severity}\n${worst.description || ''}`.trim(),
        severity: worst.severity,
      },
      [worst.alertId ? alertLink(publicUrl, worst.alertId) : digitalRisk]
    );
  }

  const shown = sorted.slice(0, EXPOSURE_GROUP_LIST_LIMIT);
  const lines = [
    `${findings.length} new exposure findings.`,
    '',
    ...shown.map((f) => `- ${f.alertId ? `${formatAlertRef(f.alertId)} ` : ''}[${f.severity.toUpperCase()}] ${f.title}`),
  ];
  if (findings.length > shown.length) lines.push(`- ...and ${findings.length - shown.length} more`);
  if (worst.description) lines.push('', worst.description);

  return withLinks(
    {
      title: `[SIEMBox] ${worst.severity.toUpperCase()} exposure: ${worst.title} (+${findings.length - 1} more)`,
      body: lines.join('\n').trim(),
      severity: worst.severity,
    },
    [...shown.map((f) => (f.alertId ? alertLink(publicUrl, f.alertId) : null)), digitalRisk]
  );
}

/** A vulnerability scan's findings, linking to Vulnerability Management. */
export function buildVulnScanMessage(
  params: { target: string; summary: string; severity: string },
  publicUrl?: string | null
): NotificationMessage {
  return withLinks(
    {
      title: `[SIEMBox] Vulnerabilities found on ${params.target}`,
      body: `Scan of ${params.target} found: ${params.summary}.`,
      severity: params.severity,
    },
    [appLink(publicUrl, 'vulnerabilities', 'Vulnerability Management')]
  );
}

/** Log ingestion stalled or resumed, linking to Settings -> System (receiver health). */
export function buildIngestionMessage(
  params: { healthy: boolean; stallMinutes: number },
  publicUrl?: string | null
): NotificationMessage {
  const msg: NotificationMessage = params.healthy
    ? { title: '[SIEMBox] Log ingestion resumed', body: 'Logs are being received again.', severity: 'info' }
    : {
        title: '[SIEMBox] Log ingestion stalled',
        body: `No logs received in the last ${params.stallMinutes} minutes.`,
        severity: 'high',
      };
  return withLinks(msg, [appLink(publicUrl, 'system', 'System status')]);
}

/** The per-channel "Test" message, linking back to Settings -> Notifications. */
export function buildChannelTestMessage(channelName: string, publicUrl?: string | null): NotificationMessage {
  return withLinks(
    {
      title: 'SIEMBox test notification',
      body: `This is a test from SIEMBox for the "${channelName}" channel.`,
      severity: 'info',
    },
    [appLink(publicUrl, 'notifications', 'Open SIEMBox')]
  );
}

/** The public URL, or null when it is unset or cannot be read (links are then left out). */
async function publicUrlOrNull(): Promise<string | null> {
  try {
    return await getPublicUrl();
  } catch {
    return null;
  }
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

// ---- Per-channel payloads (pure, so tests can pin exactly what is sent) ----

/** The Slack webhook body: escaped title and body, then `<url|label>` links. */
export function slackPayload(msg: NotificationMessage): { text: string } {
  return { text: slackText(msg.title, msg.body, msg.links) };
}

/** ntfy: the request headers (without Authorization) and the plain-text body. Links
 *  are listed in the body; the first is the Click action (tapping the notification). */
export function ntfyRequest(msg: NotificationMessage): { headers: Record<string, string>; body: string } {
  // HTTP headers are bytes: a title with a character beyond ASCII (the test
  // alert's em dash, a non-English alert title) made fetch throw, so the message
  // never went out. ntfy decodes RFC 2047 encoded-words in headers.
  const asciiTitle = /^[\x20-\x7e]*$/.test(msg.title);
  const headers: Record<string, string> = {
    Title: asciiTitle ? msg.title : `=?UTF-8?B?${Buffer.from(msg.title, 'utf8').toString('base64')}?=`,
  };
  if (msg.severity) {
    const priority: Record<string, string> = { info: '2', low: '2', medium: '3', high: '4', critical: '5' };
    headers.Priority = priority[msg.severity.toLowerCase()] || '3';
    headers.Tags = 'warning';
  }
  if (msg.links && msg.links.length > 0) headers.Click = msg.links[0].url;
  return { headers, body: plainTextWithLinks(msg.body, msg.links) };
}

/** Email: subject, text part (links as plain URLs) and, only when there are links, an HTML part. */
export function emailContent(msg: NotificationMessage): { subject: string; text: string; html?: string } {
  const content: { subject: string; text: string; html?: string } = {
    subject: msg.title,
    text: plainTextWithLinks(msg.body, msg.links),
  };
  if (msg.links && msg.links.length > 0) content.html = emailHtml(msg.title, msg.body, msg.links);
  return content;
}

// ---- Per-channel senders ----

async function sendSlack(channel: NotificationChannel, msg: NotificationMessage): Promise<void> {
  const url = channel.config.webhook_url;
  if (!url) throw new Error('Slack channel is missing webhook_url');
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(slackPayload(msg)),
  });
  if (!res.ok) throw new Error(`Slack webhook returned HTTP ${res.status}`);
}

async function sendNtfy(channel: NotificationChannel, msg: NotificationMessage): Promise<void> {
  const server = String(channel.config.server_url || 'https://ntfy.sh').replace(/\/+$/, '');
  const topic = channel.config.topic;
  if (!topic) throw new Error('NTFY channel is missing topic');
  const { headers, body } = ntfyRequest(msg);
  if (channel.config.token) headers.Authorization = `Bearer ${channel.config.token}`;
  const res = await fetch(`${server}/${topic}`, { method: 'POST', headers, body });
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
    ...emailContent(msg),
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
  // Answers the link the message carried (null when no public URL is set), so the
  // Settings page can show it.
  async testChannel(channel: NotificationChannel): Promise<{ link: string | null }> {
    const msg = buildChannelTestMessage(channel.name, await publicUrlOrNull());
    await sendToChannel(channel, msg);
    return { link: msg.links?.[0]?.url ?? null };
  },

  async notifyAlert(params: AlertNotification): Promise<void> {
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
  async notifyAlertGroup(alerts: AlertNotification[]): Promise<void> {
    try {
      if (alerts.length === 0) return;
      if ((await getSetting('notify_alerts_enabled', 'false')) !== 'true') return;

      const minSeverity = await getSetting('notify_alerts_min_severity', 'high');
      const passing = alerts.filter((a) => severityPasses(a.severity, minSeverity));
      if (passing.length === 0) return;

      await dispatch(buildAlertGroupMessage(passing, await publicUrlOrNull()));
    } catch (err) {
      logger.error('[Notifications] notifyAlert failed:', err);
      ErrorLogService.logBackgroundError('notifications', err, { dedupeKey: 'notifyAlert' });
    }
  },

  // Explicit admin preview of the new-alert email. Uses the exact alert format and
  // the configured channels, but bypasses the enabled / min-severity gates so the
  // email can be previewed regardless of the current notification preferences.
  // Also answers the link the message carried (null when no public URL is set).
  async sendTestAlert(): Promise<{ results: ChannelResult[]; link: string | null }> {
    const msg = buildAlertMessage(
      {
        severity: 'high',
        ruleName: 'SIEMBox Test Rule',
        title: 'Test alert — multiple failed logins from 203.0.113.10',
        description:
          'This is a TEST alert sent from Settings -> Notifications to preview the new-alert email. No real detection occurred.',
      },
      await publicUrlOrNull()
    );
    return { results: await dispatchWithResults(msg), link: msg.links?.[0]?.url ?? null };
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
      await dispatch(buildVulnScanMessage({ target: params.target, summary, severity: passing[0] }, await publicUrlOrNull()));
    } catch (err) {
      logger.error('[Notifications] notifyVulnScan failed:', err);
      ErrorLogService.logBackgroundError('notifications', err, { dedupeKey: 'notifyVulnScan' });
    }
  },

  /**
   * New exposure findings (Digital Risk). Opt-in like every other event:
   * gated on notify_exposure_enabled, then each finding is held to
   * notify_exposure_min_severity and only the survivors are announced, as one
   * message (see buildExposureMessage).
   */
  async notifyExposure(findings: ExposureNotice[]): Promise<void> {
    try {
      if (findings.length === 0) return;
      if ((await getSetting('notify_exposure_enabled', 'false')) !== 'true') return;
      const min = await getSetting('notify_exposure_min_severity', 'medium');
      const passing = findings.filter((f) => severityPasses(f.severity, min));
      if (passing.length === 0) return;
      await dispatch(buildExposureMessage(passing, await publicUrlOrNull()));
    } catch (err) {
      logger.error('[Notifications] notifyExposure failed:', err);
      ErrorLogService.logBackgroundError('notifications', err, { dedupeKey: 'notifyExposure' });
    }
  },

  async notifyIngestion(params: { healthy: boolean; stallMinutes: number }): Promise<void> {
    try {
      if ((await getSetting('notify_ingestion_enabled', 'false')) !== 'true') return;
      await dispatch(buildIngestionMessage(params, await publicUrlOrNull()));
    } catch (err) {
      logger.error('[Notifications] notifyIngestion failed:', err);
      ErrorLogService.logBackgroundError('notifications', err, { dedupeKey: 'notifyIngestion' });
    }
  },
};
