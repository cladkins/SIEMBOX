import type { Component } from 'vue';
import type { RouteRecordSingleView } from 'vue-router';
import { Bell, Clock, Connection, Download, Filter, Lock, MagicStick, Monitor, Odometer, Search, User, View } from '@element-plus/icons-vue';

/**
 * One functional area of the Settings hub.
 *
 * `settingsAreas` is the single source for both the hub's secondary nav
 * (SettingsLayout.vue) and the /settings/* child routes (router/index.ts):
 * adding an area is one entry below plus its page component in this folder.
 */
export interface SettingsArea {
  /** Stable id; also derives the route name ('ai' -> 'SettingsAi'). */
  key: string;
  /** URL segment under /settings, without a leading slash. */
  path: string;
  /** Nav label and page heading. */
  title: string;
  /** Element Plus icon component shown in the nav. */
  icon: Component;
  /** One-line summary shown under the page heading. */
  description: string;
  /**
   * Admin-only areas get `meta.requiresAdmin` on their route (the router guard
   * sends non-admins to the dashboard) and are left out of non-admins' nav.
   */
  adminOnly: boolean;
  /** Lazily loaded page component. */
  component: RouteRecordSingleView['component'];
}

// In nav order.
export const settingsAreas: SettingsArea[] = [
  {
    key: 'account',
    path: 'account',
    title: 'Account',
    icon: User,
    description: 'Sign-in security for your own account: your password and two-factor authentication.',
    adminOnly: false,
    component: () => import('./AccountSettings.vue'),
  },
  {
    key: 'sign-in-protection',
    path: 'sign-in-protection',
    title: 'Sign-in protection',
    icon: Lock,
    description:
      'Paused sign-ins and failed-attempt counters (clear them here), how SIEMBox sees your address, and the limits in effect.',
    adminOnly: true,
    component: () => import('./SignInProtectionSettings.vue'),
  },
  {
    key: 'retention',
    path: 'retention',
    title: 'Data Retention',
    icon: Clock,
    description: 'How long logs and alerts are kept, on-demand cleanup, and current table sizes.',
    adminOnly: true,
    component: () => import('./RetentionSettings.vue'),
  },
  {
    key: 'context-graph',
    path: 'context-graph',
    title: 'Context Graph',
    icon: Connection,
    description: 'The relationships seen in logs behind the Context Graph: on or off, how long they are kept, and the daily cap.',
    adminOnly: true,
    component: () => import('./ContextGraphSettings.vue'),
  },
  {
    key: 'applications',
    path: 'applications',
    title: 'Application Monitoring',
    icon: Monitor,
    description: 'The software inventory behind Application Monitoring: on or off, and how long an application stays listed after it was last seen.',
    adminOnly: true,
    component: () => import('./ApplicationSettings.vue'),
  },
  {
    key: 'ingestion',
    path: 'ingestion',
    title: 'Log Ingestion',
    icon: Download,
    description: 'The syslog host and port that log shippers send to.',
    adminOnly: true,
    component: () => import('./IngestionSettings.vue'),
  },
  {
    key: 'ai',
    path: 'ai',
    title: 'AI',
    icon: MagicStick,
    description: 'Providers, models and API keys for the AI Builder, the AI Analyst chat and automatic AI Triage.',
    adminOnly: true,
    component: () => import('./AiSettings.vue'),
  },
  {
    key: 'notifications',
    path: 'notifications',
    title: 'Notifications',
    icon: Bell,
    description: 'Delivery channels (Slack, Email, NTFY) and the events that trigger them.',
    adminOnly: true,
    component: () => import('./NotificationSettings.vue'),
  },
  {
    key: 'detections',
    path: 'detections',
    title: 'Detections',
    icon: Filter,
    description: 'Trusted IPs and CIDR ranges whose traffic never raises detection alerts.',
    adminOnly: true,
    component: () => import('./DetectionSettings.vue'),
  },
  {
    key: 'discovery',
    path: 'discovery',
    title: 'Asset Discovery',
    icon: Search,
    description: 'Automatic asset inventory built from the hosts seen in incoming logs, and how long a scan queued for a log shipper waits before it expires.',
    adminOnly: true,
    component: () => import('./AssetDiscoverySettings.vue'),
  },
  {
    key: 'digital-risk',
    path: 'digital-risk',
    title: 'Digital Risk',
    icon: View,
    description:
      'Configuration: watched and lookalike domains, breach-monitored identities, the Have I Been Pwned key, notifications and check schedules. Findings and the password check are on the Digital Risk page.',
    adminOnly: true,
    component: () => import('./DigitalRiskSettings.vue'),
  },
  {
    key: 'display-links',
    path: 'display-links',
    title: 'Display links',
    icon: Monitor,
    description: 'Read-only links for wall screens and TVs',
    adminOnly: true,
    component: () => import('./DisplayLinksSettings.vue'),
  },
  {
    key: 'system',
    path: 'system',
    title: 'System',
    icon: Odometer,
    description: 'The public URL notifications link to, syslog receiver health and database statistics for this instance.',
    adminOnly: true,
    component: () => import('./SystemSettings.vue'),
  },
];

/** Full URL of an area, e.g. '/settings/ai'. */
export function settingsAreaPath(area: SettingsArea): string {
  return `/settings/${area.path}`;
}

/** Route name of an area: 'ai' -> 'SettingsAi', 'digital-risk' -> 'SettingsDigitalRisk'. */
export function settingsRouteName(area: SettingsArea): string {
  const pascal = area.key
    .split('-')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join('');
  return `Settings${pascal}`;
}
