import type { Component } from 'vue';
import type { RouteRecordSingleView } from 'vue-router';
import { Bell, Clock, Download, Filter, MagicStick, Odometer, Search, User, View } from '@element-plus/icons-vue';

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
    description: 'Sign-in security for your own account, such as two-factor authentication.',
    adminOnly: false,
    component: () => import('./AccountSettings.vue'),
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
    description: 'Automatic asset inventory built from the hosts seen in incoming logs.',
    adminOnly: true,
    component: () => import('./AssetDiscoverySettings.vue'),
  },
  {
    key: 'digital-risk',
    path: 'digital-risk',
    title: 'Digital Risk',
    icon: View,
    description:
      'Leaked-credential monitoring with Have I Been Pwned, watched and lookalike domains, and an on-demand password breach check.',
    adminOnly: true,
    component: () => import('./DigitalRiskSettings.vue'),
  },
  {
    key: 'system',
    path: 'system',
    title: 'System',
    icon: Odometer,
    description: 'Syslog receiver health and database statistics for this instance.',
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
