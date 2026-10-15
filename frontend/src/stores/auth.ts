import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { api } from '@/services/api';
import router from '@/router';

/** Why the account must change its password (backend services/auth/passwordChange.ts). */
export type PasswordChangeReason = 'initial' | 'default' | 'admin' | 'cli';

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
  // The account must choose a new password before anything else (the API
  // answers every other request with 403 PASSWORD_CHANGE_REQUIRED): its
  // initial or a temporary password, or SIEMBox's default. The router keeps
  // it on the ChangePassword view until it does.
  const mustChangePassword = computed(() => !!user.value?.must_change_password);
  const passwordChangeReason = computed<PasswordChangeReason | null>(() =>
    mustChangePassword.value ? (user.value?.must_change_password_reason ?? null) : null
  );

  const login = async (username: string, password: string, code?: string) => {
    const response = await api.login(username, password, code, readBrowserTokens()[username]);
    if (typeof response.data.browserToken === 'string') rememberBrowserToken(username, response.data.browserToken);
    token.value = response.data.token;
    user.value = response.data.user;
    localStorage.setItem('token', token.value!);
    localStorage.setItem('user', JSON.stringify(user.value));
    router.push(response.data.passwordChangeRequired ? { name: 'ChangePassword' } : '/');
  };

  /**
   * The API refused a request because the account must change its password
   * (services/api.ts): flagged since this tab signed in (an upgrade, an
   * admin's reset, or a sign-in elsewhere with the default password).
   */
  const requirePasswordChange = (reason: string | null) => {
    if (!token.value) return;
    user.value = {
      ...(user.value ?? {}),
      must_change_password: true,
      must_change_password_reason: reason,
    };
    localStorage.setItem('user', JSON.stringify(user.value));
    if (router.currentRoute.value.name !== 'ChangePassword') void router.replace({ name: 'ChangePassword' });
  };

  /** The profile from GET /auth/me: kept, and off the change screen once no change is required. */
  const setProfile = (profile: unknown) => {
    if (!token.value || !profile || typeof profile !== 'object') return;
    user.value = { ...(user.value ?? {}), ...profile };
    localStorage.setItem('user', JSON.stringify(user.value));
    if (!mustChangePassword.value && router.currentRoute.value.name === 'ChangePassword') void router.replace('/');
  };

  /**
   * Read the profile again and keep it (best effort: with no answer the stored
   * one stands; a 401 signs out as usual). The router does this once per page
   * load, before the first page mounts, so a requirement set since the stored
   * profile was saved (an upgrade's scan, an admin's reset) sends the user to
   * the change screen before any page makes calls the API refuses.
   */
  const refreshProfile = async () => {
    if (!token.value) return;
    try {
      const { data } = await api.getProfile({ skipErrorToast: true, skipNetworkErrorToast: true, timeout: 5000 });
      setProfile(data);
    } catch {
      // Keep what the store has; the page's own calls still redirect on a refusal.
    }
  };

  const logout = () => {
    token.value = null;
    user.value = null;
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    router.push('/login');
  };

  /** Sign out on the server too (best effort, no toasts), then here. */
  const signOut = async () => {
    if (token.value) await api.logout().catch(() => undefined);
    logout();
  };

  return {
    token,
    user,
    isAuthenticated,
    isAdmin,
    canAnalyst,
    mustChangePassword,
    passwordChangeReason,
    login,
    requirePasswordChange,
    setProfile,
    refreshProfile,
    logout,
    signOut,
  };
});
