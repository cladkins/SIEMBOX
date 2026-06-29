import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router';
import { useAuthStore } from '@/stores/auth';

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue'),
    meta: { requiresAuth: false },
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
        path: 'threat-intel',
        name: 'ThreatIntel',
        component: () => import('@/views/ThreatIntel.vue'),
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
        path: 'settings',
        name: 'Settings',
        component: () => import('@/views/Settings.vue'),
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

// Navigation guard for authentication
router.beforeEach((to, _from, next) => {
  const authStore = useAuthStore();
  const requiresAuth = to.matched.some((record) => record.meta.requiresAuth);
  const requiresAdmin = to.matched.some((record) => record.meta.requiresAdmin);
  const allowedRoles = to.matched.find((record) => record.meta.allowedRoles)?.meta.allowedRoles as string[] | undefined;

  if (requiresAuth && !authStore.isAuthenticated) {
    next('/login');
  } else if (to.path === '/login' && authStore.isAuthenticated) {
    next('/');
  } else if (requiresAdmin && authStore.user?.role !== 'admin') {
    next('/'); // Redirect non-admins to dashboard
  } else if (allowedRoles && !allowedRoles.includes(authStore.user?.role || '')) {
    next('/'); // Redirect users without proper role to dashboard
  } else {
    next();
  }
});

export default router;
