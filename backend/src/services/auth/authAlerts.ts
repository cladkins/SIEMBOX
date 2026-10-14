/**
 * Alerts SIEMBox raises about attacks on its own sign-in (AUTH_ALERTS, on by
 * default). They are ordinary alerts (source 'siembox-auth', no rule) inserted
 * the way EDR detections are (edrService.ts), so they show on the Alerts page,
 * reach the notification channels through notifyAlert and can be triaged.
 *
 * | Trigger                                                         | Severity                        |
 * |-----------------------------------------------------------------|---------------------------------|
 * | a network pause starts                                          | medium                          |
 * | an account pause starts, for an account that exists             | high (critical for an admin)    |
 * | an MFA pause starts                                             | critical                        |
 * | success from a new browser while the account key has paused     | high                            |
 * |   in its current streak                                         |                                 |
 * | success after the key it resets held 5 or more failures         | medium                          |
 * | a recognized browser is forgotten after 20 failures             | high                            |
 * | more than 100 checked failures in 10 minutes                    | high, at most once an hour      |
 *
 * Deduplicated: event_id is siembox-auth:<trigger>:<sha256(key), 16 hex>:<epoch
 * of the streak's first failure>, so a streak raises its alert once however
 * many pauses it goes through (the alerts table's unique index on event_id
 * drops the rest), and the spike alert's is siembox-auth:spike:<UTC hour>. At
 * most 20 are raised an hour. Raising never blocks or fails a sign-in.
 */
import crypto from 'node:crypto';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { NotificationService } from '../notifications/notificationService';
import { maybeTriageAlert } from '../ai/triageService';
import { signInSettings } from './signInPolicy';

export type AuthAlertTrigger =
  | 'network-pause'
  | 'account-pause'
  | 'mfa-pause'
  | 'success-during-attack'
  | 'success-after-failures'
  | 'browser-revoked'
  | 'spike';

export type AlertSeverity = 'medium' | 'high' | 'critical';

export interface AuthAlert {
  trigger: AuthAlertTrigger;
  severity: AlertSeverity;
  /** The throttle key the alert is about (hashed into event_id). */
  key: string;
  /** Epoch seconds of the first failure of the key's streak. */
  streakStartedAt: number;
  title: string;
  description: string;
  matched: Record<string, unknown>;
}

export const ALERT_SOURCE = 'siembox-auth';
const RULE_NAME = 'SIEMBox sign-in protection';
const MAX_ALERTS_PER_HOUR = 20;
const SPIKE_WINDOW_MS = 10 * 60 * 1000;
const SPIKE_THRESHOLD = 100;

const state = {
  raised: [] as number[],
  capWarnedAt: 0,
  failures: [] as number[],
  spikeHour: '',
};

/** Clear the in-memory caps (tests). */
export function resetAuthAlertState(): void {
  state.raised = [];
  state.capWarnedAt = 0;
  state.failures = [];
  state.spikeHour = '';
}

export function authAlertEventId(trigger: AuthAlertTrigger, key: string, streakStartedAt: number): string {
  const keyHash = crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
  return `${ALERT_SOURCE}:${trigger}:${keyHash}:${Math.floor(streakStartedAt)}`;
}

function underHourlyCap(now: number): boolean {
  state.raised = state.raised.filter((at) => now - at < 60 * 60 * 1000);
  if (state.raised.length < MAX_ALERTS_PER_HOUR) return true;
  if (now - state.capWarnedAt > 60 * 60 * 1000) {
    state.capWarnedAt = now;
    logger.warn(`Sign-in alerts: ${MAX_ALERTS_PER_HOUR} raised in the last hour; further ones are skipped for now`);
  }
  return false;
}

async function insert(alert: AuthAlert, eventId: string): Promise<boolean> {
  const now = Date.now();
  if (!underHourlyCap(now)) return false;
  const res = await query(
    `INSERT INTO alerts (rule_id, parsed_log_id, severity, title, description, matched_data, status, source, event_id)
     VALUES (NULL, NULL, $1, $2, $3, $4, 'new', $5, $6)
     ON CONFLICT (event_id) WHERE event_id IS NOT NULL DO NOTHING
     RETURNING id`,
    [alert.severity, alert.title.slice(0, 255), alert.description, JSON.stringify(alert.matched), ALERT_SOURCE, eventId]
  );
  if ((res.rowCount ?? 0) === 0) return false;
  state.raised.push(now);
  logger.warn('Sign-in alert raised', { trigger: alert.trigger, severity: alert.severity, alertId: res.rows[0].id });
  void NotificationService.notifyAlert({
    severity: alert.severity,
    ruleName: RULE_NAME,
    title: alert.title,
    description: alert.description,
  });
  maybeTriageAlert({ id: res.rows[0].id, severity: alert.severity, source: ALERT_SOURCE });
  return true;
}

/**
 * Raise an alert (deduplicated, capped) and resolve to whether a new one was
 * created. Never rejects; callers normally don't await it.
 */
export async function raiseAuthAlert(alert: AuthAlert): Promise<boolean> {
  if (!signInSettings().alerts) return false;
  try {
    return await insert(alert, authAlertEventId(alert.trigger, alert.key, alert.streakStartedAt));
  } catch (error) {
    logger.warn('Sign-in alert could not be raised', {
      trigger: alert.trigger,
      error: error instanceof Error ? error.message : String(error),
    });
    return false;
  }
}

/**
 * Count one checked failure (a wrong password or code that reached its check)
 * and raise the spike alert when more than 100 fell within 10 minutes.
 */
export function noteCheckedFailure(now = Date.now()): Promise<boolean> {
  state.failures.push(now);
  while (state.failures.length > 0 && now - state.failures[0] > SPIKE_WINDOW_MS) state.failures.shift();
  if (state.failures.length > SPIKE_THRESHOLD * 2) state.failures.splice(0, state.failures.length - SPIKE_THRESHOLD * 2);
  if (state.failures.length <= SPIKE_THRESHOLD || !signInSettings().alerts) return Promise.resolve(false);
  const hour = new Date(now).toISOString().slice(0, 13);
  if (state.spikeHour === hour) return Promise.resolve(false);
  state.spikeHour = hour;
  const count = state.failures.length;
  return (async () => {
    try {
      return await insert(
        {
          trigger: 'spike',
          severity: 'high',
          key: 'spike',
          streakStartedAt: 0,
          title: 'Burst of failed sign-ins to SIEMBox',
          description: `More than ${SPIKE_THRESHOLD} failed sign-in checks (${count}) in the last 10 minutes, across all accounts and networks.`,
          matched: { trigger: 'spike', failures: count, window_minutes: 10 },
        },
        `${ALERT_SOURCE}:spike:${hour}`
      );
    } catch (error) {
      logger.warn('Sign-in spike alert could not be raised', {
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  })();
}
