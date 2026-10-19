import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { settingsAreas, settingsRouteName } from '@/views/settings/areas';
import { safeRedirect } from '@/utils/safeRedirect';

// The meta fields the guard below reads, merged into vue-router's RouteMeta:
// the guard needs no casts, and a wrong value type in a route fails type-check.
declare module 'vue-router' {
  interface RouteMeta {
    requiresAuth?: boolean;
    requiresAdmin?: boolean;
    allowedRoles?: string[];
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue'),
    meta: { requiresAuth: false },
  },
  // Outside Layout (no navigation): an account that must change its password
  // can do nothing else, and the guard below keeps it here until it does.
  {
    path: '/change-password',
    name: 'ChangePassword',
    component: () => import('@/views/ChangePassword.vue'),
    meta: { requiresAuth: true },
  },
  // Big Display on the user's own session and role (BIG-DISPLAY.md §8.4):
  // full screen, outside Layout. Admins add ?link=<id> to see a display link's board.
  {
    path: '/big-display',
    name: 'BigDisplay',
    component: () => import('@/views/BigDisplay.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/',
    component: () => import('@/views/Layout.vue'),
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        name: 'Dashboard',
        component: () => import('@/views/Dashboard.vue'),
      },
      {
        path: 'alerts',
        name: 'Alerts',
        component: () => import('@/views/Alerts.vue'),
      },
      {
        path: 'soc-triage',
        name: 'SocTriage',
        component: () => import('@/views/SocTriage.vue'),
        meta: { allowedRoles: ['admin', 'analyst', 'operator'] },
      },
      {
        path: 'threat-intel',
        name: 'ThreatIntel',
        component: () => import('@/views/ThreatIntel.vue'),
      },
      {
        // Context Graph: every role (the API decides what each role's graph holds).
        path: 'graph',
        name: 'ContextGraph',
        component: () => import('@/views/graph/ContextGraph.vue'),
      },
      {
        // Every signed-in role: each request it makes is open to all of them,
        // and the admin-only controls on it are hidden from the rest.
        path: 'digital-risk',
        name: 'DigitalRisk',
        component: () => import('@/views/digital-risk/DigitalRiskDashboard.vue'),
      },
      {
        path: 'ai-analyst',
        name: 'AIAnalyst',
        component: () => import('@/views/AIAnalyst.vue'),
        meta: { allowedRoles: ['admin', 'analyst', 'operator'] },
      },
      {
        path: 'logs',
        name: 'Logs',
        component: () => import('@/views/Logs.vue'),
      },
      {
        path: 'parsers',
        name: 'Parsers',
        component: () => import('@/views/Parsers.vue'),
      },
      {
        path: 'rules',
        name: 'Rules',
        component: () => import('@/views/Rules.vue'),
      },
      {
        path: 'content-packs',
        name: 'ContentPacks',
        component: () => import('@/views/ContentPacks.vue'),
      },
      {
        path: 'getting-started',
        name: 'Onboarding',
        component: () => import('@/views/Onboarding.vue'),
      },
      {
        path: 'shippers',
        name: 'Shippers',
        component: () => import('@/views/Shippers.vue'),
      },
      {
        path: 'endpoints',
        name: 'Endpoints',
        component: () => import('@/views/Endpoints.vue'),
        meta: { requiresAdmin: true },
      },
      {
        // Settings hub: one child page per functional area, generated from
        // settingsAreas (the list that also drives the hub's nav). Admin-only
        // areas carry meta.requiresAdmin, so the guard below treats them like
        // the other admin pages. A bare /settings lands on Account, which
        // every role can open.
        path: 'settings',
        name: 'Settings',
        component: () => import('@/views/settings/SettingsLayout.vue'),
        redirect: '/settings/account',
        children: settingsAreas.map((area) => ({
          path: area.path,
          name: settingsRouteName(area),
          component: area.component,
          meta: area.adminOnly ? { requiresAdmin: true } : {},
        })),
      },
      {
        path: 'users',
        name: 'Users',
        component: () => import('@/views/Users.vue'),
        meta: { requiresAdmin: true },
      },
      {
        path: 'asset-inventory',
        name: 'Assets',
        component: () => import('@/views/Assets.vue'),
        meta: { allowedRoles: ['admin', 'analyst', 'operator'] },
      },
      {
        path: 'log-discovery',
        name: 'LogDiscovery',
        component: () => import('@/views/LogDiscovery.vue'),
        meta: { allowedRoles: ['admin', 'operator'] },
      },
      {
        path: 'vulnerability-scanning',
        name: 'VulnerabilityScanning',
        component: () => import('@/views/VulnerabilityScanning.vue'),
        meta: { allowedRoles: ['admin', 'operator'] },
      },
      {
        path: 'vulnerability-management',
        name: 'VulnerabilityManagement',
        component: () => import('@/views/VulnerabilityManagement.vue'),
        meta: { allowedRoles: ['admin', 'operator'] },
      },
      {
        path: 'container-scanning',
        name: 'ContainerScanning',
        component: () => import('@/views/ContainerScanning.vue'),
        meta: { allowedRoles: ['admin', 'operator'] },
      },
      {
        path: 'scheduled-scans',
        name: 'ScheduledScans',
        component: () => import('@/views/ScheduledScans.vue'),
        meta: { allowedRoles: ['admin', 'operator'] },
      },
      {
        path: 'templates',
        name: 'Templates',
        component: () => import('@/views/Templates.vue'),
        meta: { allowedRoles: ['admin', 'analyst', 'operator'] },
      },
      {
        path: 'admin',
        name: 'AdminDashboard',
        component: () => import('@/views/AdminDashboard.vue'),
        meta: { requiresAdmin: true },
      },
    ],
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

/**
 * `value` (a ?redirect= or a held target) as an in-app path to go to after
 * signing in, or null: utils/safeRedirect.ts refuses other origins, the
 * sign-in and password-change pages, and paths no route matches.
 */
export function redirectTarget(value: unknown): string | null {
  return safeRedirect(value, (path) => router.resolve(path));
}

// Navigation guard for authentication. It returns where to go instead of
// calling the third `next` argument, which vue-router 5 deprecates: a returned
// path redirects, and returning nothing lets the navigation through.
// The page load's first navigation reads the profile once (stores/auth.ts
// refreshProfile), so the checks below see a password-change requirement the
// stored profile predates before any page mounts.
let profileRefreshed = false;

router.beforeEach(async (to) => {
  const authStore = useAuthStore();
  if (!profileRefreshed) {
    profileRefreshed = true;
    await authStore.refreshProfile();
  }
  const requiresAuth = to.matched.some((record) => record.meta.requiresAuth);
  const requiresAdmin = to.matched.some((record) => record.meta.requiresAdmin);
  const allowedRoles = to.matched.find((record) => record.meta.allowedRoles)?.meta.allowedRoles;

  if (requiresAuth && !authStore.isAuthenticated) {
    // Come back here after signing in (a link opened while signed out).
    const redirect = to.fullPath !== '/' ? redirectTarget(to.fullPath) : null;
    return redirect ? { path: '/login', query: { redirect } } : '/login';
  } else if (authStore.isAuthenticated && authStore.mustChangePassword && to.name !== 'ChangePassword') {
    return { name: 'ChangePassword' }; // /login too: nothing else works until the password is changed
  } else if (to.name === 'ChangePassword' && !authStore.mustChangePassword) {
    return '/';
  } else if (to.path === '/login' && authStore.isAuthenticated) {
    return redirectTarget(to.query.redirect) ?? '/';
  } else if (requiresAdmin && authStore.user?.role !== 'admin') {
    return '/'; // Redirect non-admins to dashboard
  } else if (allowedRoles && !allowedRoles.includes(authStore.user?.role || '')) {
    return '/'; // Redirect users without proper role to dashboard
  }
});

export default router;
