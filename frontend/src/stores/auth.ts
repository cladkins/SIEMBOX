import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { api } from '@/services/api';
import router from '@/router';

/**
 * Recognized-browser tokens, by username: the API hands one out on every
 * successful sign-in, and a sign-in that sends it back counts against this
 * browser's own counter instead of the account's and the network's, so
 * someone else's failed attempts can't lock this browser out. The token never
 * replaces the password or MFA. Kept on logout, for at most 5 usernames.
 */
const BROWSER_TOKENS_KEY = 'siembox.recognizedBrowsers';
const MAX_REMEMBERED_USERNAMES = 5;

function readBrowserTokens(): Record<string, string> {
  try {
    const parsed = JSON.parse(localStorage.getItem(BROWSER_TOKENS_KEY) || '{}');
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return Object.fromEntries(
      Object.entries(parsed).filter((entry): entry is [string, string] => typeof entry[1] === 'string')
    );
  } catch {
    return {};
  }
}

function rememberBrowserToken(username: string, token: string): void {
  try {
    const tokens = readBrowserTokens();
    delete tokens[username];
    tokens[username] = token; // most recent last
    const usernames = Object.keys(tokens);
    for (const old of usernames.slice(0, Math.max(0, usernames.length - MAX_REMEMBERED_USERNAMES))) {
      delete tokens[old];
    }
    localStorage.setItem(BROWSER_TOKENS_KEY, JSON.stringify(tokens));
  } catch {
    // Storage full or blocked: this browser just stays unrecognized.
  }
}

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
    const response = await api.login(username, password, code, readBrowserTokens()[username]);
    if (typeof response.data.browserToken === 'string') rememberBrowserToken(username, response.data.browserToken);
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
