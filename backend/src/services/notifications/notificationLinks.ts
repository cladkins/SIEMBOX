/**
 * Links in notifications, and how each channel renders them.
 *
 * A link is only ever the validated public URL (services/settings/publicUrl.ts)
 * plus one of the fixed in-app paths below, plus an alert number that has been
 * parsed as an integer. Nothing from the alert's title, the request or the
 * channel config reaches a URL, so a notification cannot be made to link
 * anywhere else.
 */
import { formatAlertRef, parseAlertRef } from '../alerts/alertRef';

export interface NotificationLink {
  label: string;
  url: string;
}

/** The in-app pages a notification may link to (frontend/src/router/index.ts). */
export const APP_PATHS = {
  alerts: '/alerts',
  digitalRisk: '/digital-risk',
  vulnerabilities: '/vulnerability-management',
  system: '/settings/system',
  notifications: '/settings/notifications',
} as const;

export type AppPage = keyof typeof APP_PATHS;

/** `${publicUrl}${path}` for a fixed page, or null when no public URL is set. */
export function appLink(publicUrl: string | null | undefined, page: AppPage, label: string): NotificationLink | null {
  if (!publicUrl) return null;
  return { label, url: `${publicUrl}${APP_PATHS[page]}` };
}

/** `${publicUrl}/alerts?alert=ALR-<id>`, or null without a public URL or a valid alert id. */
export function alertLink(publicUrl: string | null | undefined, alertId: unknown): NotificationLink | null {
  if (!publicUrl) return null;
  const id = parseAlertRef(alertId);
  if (id === null) return null;
  const ref = formatAlertRef(id);
  return { label: `Open ${ref}`, url: `${publicUrl}${APP_PATHS.alerts}?alert=${ref}` };
}

/** The non-null links, in order, without duplicate URLs. */
export function compactLinks(links: Array<NotificationLink | null>): NotificationLink[] {
  const seen = new Set<string>();
  const out: NotificationLink[] = [];
  for (const link of links) {
    if (!link || seen.has(link.url)) continue;
    seen.add(link.url);
    out.push(link);
  }
  return out;
}

// ---- Rendering ----

/** Plain text (email text part, ntfy body): the body, then one `label: url` line per link. */
export function plainTextWithLinks(body: string, links: NotificationLink[] | undefined): string {
  if (!links || links.length === 0) return body;
  return `${body}\n\n${links.map((l) => `${l.label}: ${l.url}`).join('\n')}`;
}

/** Slack mrkdwn escaping: &, < and > are the control characters (api.slack.com/reference/surfaces/formatting#escaping). */
export function escapeSlack(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** A Slack link `<url|label>`. `|` would end the URL early, so it is percent-encoded. */
export function slackLink(link: NotificationLink): string {
  return `<${escapeSlack(link.url).replace(/\|/g, '%7C')}|${escapeSlack(link.label)}>`;
}

/** The Slack message text: bold title, body, then one link per line. Title and body are escaped. */
export function slackText(title: string, body: string, links: NotificationLink[] | undefined): string {
  const text = `*${escapeSlack(title)}*\n${escapeSlack(body)}`;
  if (!links || links.length === 0) return text;
  return `${text}\n\n${links.map(slackLink).join('\n')}`;
}

/** HTML-escape text or an attribute value (double-quoted). */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** The email HTML part: escaped title and body (newlines kept) and one escaped link per line. */
export function emailHtml(title: string, body: string, links: NotificationLink[]): string {
  const anchors = links.map((l) => `<a href="${escapeHtml(l.url)}">${escapeHtml(l.label)}</a>`).join('<br>\n');
  return [
    '<!doctype html><html><body style="font-family:sans-serif">',
    `<p><strong>${escapeHtml(title)}</strong></p>`,
    `<div style="white-space:pre-wrap">${escapeHtml(body)}</div>`,
    `<p>${anchors}</p>`,
    '</body></html>',
  ].join('\n');
}
