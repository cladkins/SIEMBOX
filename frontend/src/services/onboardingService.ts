import apiClient from './api';

/**
 * Getting Started completion, stored server-side and install-wide
 * (GET/PUT /api/settings/onboarding; backend routes/settings.ts).
 *
 * Every role can read it; only admins see who completed it and only admins
 * can change it. Completing it turns the Dashboard reminder off for every
 * administrator; the checklist itself stays in the sidebar.
 *
 * Deliberately not a Pinia store: logout doesn't reload the page, so a store
 * would carry one user's state (including the admin-only completed_by) into
 * the next login in the same tab. Each view loads it on mount instead.
 *
 * Before this was stored server-side, a browser remembered a dismissal in
 * localStorage (`onboarding_dismissed`). reconcileLegacyDismissal() migrates
 * that once: an admin's browser records it on the server, but only if nothing
 * was ever recorded there (so it can't undo an admin's reopen).
 */

export interface OnboardingState {
  completed: boolean;
  /** When an admin first marked setup done (ISO). */
  completed_at: string | null;
  /** That admin's username: admins only, null for everyone else. */
  completed_by: string | null;
}

/** The pre-PR-6 per-browser flag. */
export const LEGACY_DISMISSAL_KEY = 'onboarding_dismissed';

// Callers show their own message (or nothing) for a failure.
const HANDLED = { skipErrorToast: true } as const;

class OnboardingServiceClient {
  async getState(): Promise<OnboardingState> {
    const response = await apiClient.get('/settings/onboarding', HANDLED);
    return response.data;
  }

  /** Mark setup done (true) or bring the reminder back (false). Admin only. */
  async setCompleted(completed: boolean): Promise<OnboardingState> {
    const response = await apiClient.put('/settings/onboarding', { completed }, HANDLED);
    return response.data;
  }

  /** Whether this browser holds the old localStorage dismissal. */
  readLegacyDismissal(): boolean {
    try {
      return localStorage.getItem(LEGACY_DISMISSAL_KEY) === '1';
    } catch {
      return false; // storage blocked: nothing to migrate
    }
  }

  clearLegacyDismissal(): void {
    try {
      localStorage.removeItem(LEGACY_DISMISSAL_KEY);
    } catch {
      // storage blocked: nothing stored either
    }
  }

  /**
   * Migrate this browser's old dismissal, once:
   *  - no flag → nothing to do;
   *  - the server says completed → the flag is moot: remove it (any role);
   *  - not completed, admin → record it ({completed: true, legacy: true},
   *    applied only if nothing was ever recorded), then remove it; on failure
   *    keep it for the next load;
   *  - not completed, anyone else → leave it, so an admin using this browser
   *    later can still migrate it.
   */
  async reconcileLegacyDismissal(state: OnboardingState, isAdmin: boolean): Promise<OnboardingState> {
    if (!this.readLegacyDismissal()) return state;
    if (state.completed) {
      this.clearLegacyDismissal();
      return state;
    }
    if (!isAdmin) return state;
    try {
      const response = await apiClient.put('/settings/onboarding', { completed: true, legacy: true }, HANDLED);
      this.clearLegacyDismissal();
      return response.data;
    } catch {
      return state;
    }
  }

  /** getState() followed by the legacy migration. */
  async load(isAdmin: boolean): Promise<OnboardingState> {
    return this.reconcileLegacyDismissal(await this.getState(), isAdmin);
  }
}

export default new OnboardingServiceClient();
