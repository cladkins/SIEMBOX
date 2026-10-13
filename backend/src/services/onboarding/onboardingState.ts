/**
 * Whether an administrator has marked the Getting Started setup done:
 * install-wide, in ONE system_settings row so each change is a single atomic
 * statement. The row is created on the first write; there is no migration.
 *
 *   missing row          → never recorded, not completed
 *   ''                   → recorded, not completed (an admin reopened it)
 *   {"at": ISO, "by": u} → completed (any other non-empty value counts too)
 *
 * Completion only turns the Dashboard reminder off for administrators; the
 * checklist itself is always reachable. Nothing here is secret: the value is a
 * timestamp and an admin's username, and the username is only returned to
 * admins (toPublicOnboardingState).
 */
import { query } from '../../config/database';

export const ONBOARDING_SETTING_KEY = 'onboarding_completed';

const MAX_USERNAME_LENGTH = 255;

export interface OnboardingState {
  completed: boolean;
  /** When it was first marked done (ISO); null if not completed or unreadable. */
  completed_at: string | null;
  /** The admin who marked it done; null if not completed, unreadable, or a legacy flag without one. */
  completed_by: string | null;
  /** False while the row has never been written (nothing was ever recorded). */
  recorded: boolean;
}

/** GET /api/settings/onboarding's body. */
export interface PublicOnboardingState {
  completed: boolean;
  completed_at: string | null;
  /** null for non-admins: it would reveal an admin's username. */
  completed_by: string | null;
}

/** The stored value (undefined: no row) as a state. Never throws. */
export function parseOnboardingState(raw: string | null | undefined): OnboardingState {
  if (raw === undefined || raw === null) {
    return { completed: false, completed_at: null, completed_by: null, recorded: false };
  }
  if (raw === '') return { completed: false, completed_at: null, completed_by: null, recorded: true };
  let at: string | null = null;
  let by: string | null = null;
  try {
    const value: unknown = JSON.parse(raw);
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      const record = value as Record<string, unknown>;
      if (typeof record.at === 'string') {
        const ms = Date.parse(record.at);
        if (!Number.isNaN(ms)) at = new Date(ms).toISOString();
      }
      if (typeof record.by === 'string' && record.by.length > 0 && record.by.length <= MAX_USERNAME_LENGTH) {
        by = record.by;
      }
    }
  } catch {
    // Any non-empty value means "completed"; its details are just unknown.
  }
  return { completed: true, completed_at: at, completed_by: by, recorded: true };
}

export function toPublicOnboardingState(state: OnboardingState, isAdmin: boolean): PublicOnboardingState {
  return {
    completed: state.completed,
    completed_at: state.completed ? state.completed_at : null,
    completed_by: state.completed && isAdmin ? state.completed_by : null,
  };
}

/** The value written on completion. */
export function completionValue(username: string, now = new Date()): string {
  return JSON.stringify({ at: now.toISOString(), by: username.slice(0, MAX_USERNAME_LENGTH) });
}

export async function getOnboardingState(): Promise<OnboardingState> {
  const r = await query('SELECT value FROM system_settings WHERE key = $1', [ONBOARDING_SETTING_KEY]);
  return parseOnboardingState(r.rows[0]?.value);
}

/**
 * Mark setup done. Atomic and idempotent: only a missing or reopened ('') row
 * is written, so the first completion's time and admin survive later or
 * concurrent calls.
 */
export async function completeOnboarding(username: string): Promise<OnboardingState> {
  await query(
    `INSERT INTO system_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
      WHERE system_settings.value = ''`,
    [ONBOARDING_SETTING_KEY, completionValue(username)]
  );
  return getOnboardingState();
}

/** Bring the Dashboard reminder back for every administrator. */
export async function reopenOnboarding(): Promise<OnboardingState> {
  await query(
    `INSERT INTO system_settings (key, value) VALUES ($1, '')
     ON CONFLICT (key) DO UPDATE SET value = '', updated_at = NOW()`,
    [ONBOARDING_SETTING_KEY]
  );
  return getOnboardingState();
}

/**
 * A browser's pre-server-side dismissal (localStorage), migrated once: applied
 * only when nothing was ever recorded, so a stale browser can never undo an
 * admin's reopen. Returns the state, and whether this call wrote it.
 */
export async function completeOnboardingIfNeverRecorded(
  username: string
): Promise<{ state: OnboardingState; applied: boolean }> {
  const r = await query(
    `INSERT INTO system_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO NOTHING`,
    [ONBOARDING_SETTING_KEY, completionValue(username)]
  );
  return { state: await getOnboardingState(), applied: (r.rowCount ?? 0) > 0 };
}
