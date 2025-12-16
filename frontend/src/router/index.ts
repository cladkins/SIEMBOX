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

  if (requiresAuth && !authStore.isAuthenticated) {
    next('/login');
  } else if (to.path === '/login' && authStore.isAuthenticated) {
    next('/');
  } else if (requiresAdmin && authStore.user?.role !== 'admin') {
    next('/'); // Redirect non-admins to dashboard
  } else {
    next();
  }
});

export default router;
