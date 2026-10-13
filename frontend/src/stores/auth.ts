import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { api } from '@/services/api';
import router from '@/router';

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string | null>(localStorage.getItem('token'));
  const userJson = localStorage.getItem('user');
  const user = ref<any>(userJson ? JSON.parse(userJson) : null);

  const isAuthenticated = computed(() => !!token.value);
  // Admin-only UI (the Settings hub's admin areas and the links that point at
  // them) shares this one role check.
  const isAdmin = computed(() => user.value?.role === 'admin');
  // Analyst and up (analyst, operator, admin): viewers are read-only. The API
  // requires this role for parser and rule changes, alert triage and the AI
  // Analyst, so controls for those hide or disable themselves with this check.
  const canAnalyst = computed(() => ['admin', 'operator', 'analyst'].includes(user.value?.role));

  const login = async (username: string, password: string, code?: string) => {
    const response = await api.login(username, password, code);
    token.value = response.data.token;
    user.value = response.data.user;
    localStorage.setItem('token', token.value!);
    localStorage.setItem('user', JSON.stringify(user.value));
    router.push('/');
  };

  const logout = () => {
    token.value = null;
    user.value = null;
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    router.push('/login');
  };

  return {
    token,
    user,
    isAuthenticated,
    isAdmin,
    canAnalyst,
    login,
    logout,
  };
});
