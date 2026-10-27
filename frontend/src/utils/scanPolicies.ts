/**
 * Endpoint scan policies (Endpoints page → Scan policies, and the details
 * pane's Scan policy tab): the editor's form for one scan type's entry, the
 * entry it saves, the one-line descriptions, and the role and capability
 * checks. Pure, so it is unit-tested (scanPolicies.test.ts).
 *
 * The server owns the rules and computes every run
 * (backend/src/services/edr/scanPolicies.ts); the editor's "Next runs" ask it
 * (POST /api/edr/scan-policies/preview). Timing reuses Scheduled Scans' form
 * model (scheduleTiming.ts).
 */
import {
  defaultTimingForm,
  describeSchedule,
  scheduleFromForm,
  timingFormFromRow,
  timingFormProblem,
  type CalendarSchedule,
  type TimingForm,
} from './scheduleTiming.ts';
import type { PolicyPerformance } from './endpointPerformance.ts';

export type PolicyScanType = 'vuln' | 'yara' | 'packages' | 'inventory';

export const POLICY_SCAN_TYPES: { value: PolicyScanType; label: string; help: string }[] = [
  { value: 'vuln', label: 'Vulnerability scan', help: 'grype over the installed packages.' },
  {
    value: 'yara',
    label: 'YARA file scan',
    help: 'A full pass over every file. While enabled, the agent also checks changed files every minute.',
  },
  { value: 'packages', label: 'Package inventory', help: 'The installed-software list.' },
  { value: 'inventory', label: 'System inventory', help: 'Host facts: OS, addresses, programs.' },
];

/** First agent release that follows scan policies (MIN_POLICY_AGENT_VERSION on the server). */
export const MIN_POLICY_AGENT_VERSION = '0.0.22';
/** Fixed-interval bounds, minutes (MIN/MAX_POLICY_INTERVAL_MINUTES on the server). */
export const MIN_POLICY_INTERVAL = 15;
export const MAX_POLICY_INTERVAL = 30 * 24 * 60;

export const POLICY_INTERVAL_PRESETS: Array<{ label: string; value: number }> = [
  { label: 'Every 15 minutes', value: 15 },
  { label: 'Every 30 minutes', value: 30 },
  { label: 'Every hour', value: 60 },
  { label: 'Every 6 hours', value: 360 },
  { label: 'Every 12 hours', value: 720 },
  { label: 'Every 24 hours', value: 1440 },
  { label: 'Every 7 days', value: 10080 },
];

export interface ScanWindow {
  start: string;
  end: string;
  timezone: string;
}

export interface ScanSpec {
  enabled: boolean;
  schedule: CalendarSchedule | null;
  interval_minutes: number | null;
  window: ScanWindow | null;
}

export type PolicyScans = Record<PolicyScanType, ScanSpec>;

export interface ScanPolicy {
  id: number;
  name: string;
  description: string | null;
  is_default: boolean;
  scans: PolicyScans;
  /** Performance metrics, process sampling and alert thresholds (endpointPerformance.ts); absent from an older server. */
  performance?: PolicyPerformance;
  endpoint_count?: number;
}

/** One scan type's editor state. */
export interface SpecForm {
  enabled: boolean;
  timing: TimingForm;
  /** "Only start between …" */
  useWindow: boolean;
  window: ScanWindow;
}

/** The default policy's starting entries (BUILTIN_DEFAULT_SCANS on the server). */
export function defaultPolicyScans(): PolicyScans {
  const every = (m: number): ScanSpec => ({ enabled: true, schedule: null, interval_minutes: m, window: null });
  return { vuln: every(1440), yara: every(1440), packages: every(360), inventory: every(60) };
}

export function defaultWindow(timezone: string): ScanWindow {
  return { start: '22:00', end: '06:00', timezone };
}

/** The editor state for an entry. */
export function specFormFromSpec(spec: ScanSpec, zone: string): SpecForm {
  const timing = timingFormFromRow({ schedule: spec.schedule, interval_minutes: spec.interval_minutes }, zone);
  return {
    enabled: spec.enabled,
    timing,
    useWindow: !!spec.window,
    window: spec.window ? { ...spec.window } : defaultWindow(spec.schedule?.timezone || zone),
  };
}

/** The entry an editor state saves. */
export function specFromForm(form: SpecForm): ScanSpec {
  const schedule = scheduleFromForm(form.timing);
  return {
    enabled: form.enabled,
    schedule,
    interval_minutes: schedule ? null : form.timing.interval_minutes,
    window: form.useWindow ? { ...form.window } : null,
  };
}

/** A new form: daily at 02:00 in the viewer's zone, enabled. */
export function newSpecForm(zone: string): SpecForm {
  return { enabled: true, timing: defaultTimingForm(zone), useWindow: false, window: defaultWindow(zone) };
}

const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/;

/** A problem the editor can see before saving, or null. The server checks again. */
export function specFormProblem(form: SpecForm): string | null {
  if (form.timing.frequency === 'interval') {
    const m = form.timing.interval_minutes;
    if (!Number.isInteger(m) || m < MIN_POLICY_INTERVAL || m > MAX_POLICY_INTERVAL) {
      return `Interval must be ${MIN_POLICY_INTERVAL} minutes to 30 days`;
    }
  } else {
    const p = timingFormProblem(form.timing);
    if (p) return p;
  }
  if (form.useWindow) {
    if (!HHMM.test(form.window.start) || !HHMM.test(form.window.end)) return 'Choose the window start and end';
    if (form.window.start === form.window.end) return 'The window start and end must differ';
    if (!form.window.timezone) return 'Choose the window time zone';
  }
  return null;
}

const minutesOf = (hhmm: string) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5));

/** Whether HH:MM falls in the window (start inclusive, end exclusive; may wrap midnight). */
export function timeInWindow(hhmm: string, w: Pick<ScanWindow, 'start' | 'end'>): boolean {
  const m = minutesOf(hhmm);
  const s = minutesOf(w.start);
  const e = minutesOf(w.end);
  return s < e ? m >= s && m < e : m >= s || m < e;
}

/**
 * A calendar entry whose set time is outside its own window (same zone): each
 * run would wait for the next window opening. The editor warns about it.
 */
export function windowMissesSchedule(spec: ScanSpec): boolean {
  const s = spec.schedule;
  const w = spec.window;
  if (!s || !w || s.timezone !== w.timezone) return false;
  if (s.frequency === 'hourly') {
    const every = s.every_hours ?? 1;
    for (let h = 0; h < 24; h += every) {
      if (timeInWindow(`${String(h).padStart(2, '0')}:${String(s.minute ?? 0).padStart(2, '0')}`, w)) return false;
    }
    return true;
  }
  return !!s.time && !timeInWindow(s.time, w);
}

export function describeWindow(w: ScanWindow | null | undefined): string {
  if (!w) return '';
  const wraps = minutesOf(w.end) < minutesOf(w.start);
  return `only ${w.start}–${w.end}${wraps ? ' (overnight)' : ''} (${w.timezone})`;
}

/** One line for an entry: "Off", "Every 24 hours", "Daily at 02:00 (UTC), only 22:00–06:00 (overnight) (UTC)". */
export function describeSpec(spec: ScanSpec | null | undefined): string {
  if (!spec) return '-';
  if (!spec.enabled) return 'Off';
  const timing = describeSchedule({ schedule: spec.schedule, interval_minutes: spec.interval_minutes });
  return spec.window ? `${timing}, ${describeWindow(spec.window)}` : timing;
}

/** Editing policies, assigning them and overriding them: operators and admins (as Scheduled Scans). */
export function canEditPolicies(role: string | null | undefined): boolean {
  return role === 'admin' || role === 'operator';
}

/** Whether the agent follows scan policies (it reports the capability in its heartbeat). */
export function supportsPolicyScans(agent: { capabilities?: string[] | null } | null | undefined): boolean {
  return Array.isArray(agent?.capabilities) && agent.capabilities.includes('policy_scans');
}

/** History trigger text for a policy run: "policy · Servers", "override · Servers". */
export function policyRunLabel(row: { trigger: string; policy_name?: string | null; policy_source?: string | null }): string {
  if (row.trigger !== 'policy') return '';
  const what = row.policy_source === 'override' ? 'endpoint override' : 'policy';
  return row.policy_name ? `${what} · ${row.policy_name}` : what;
}

function humanSeconds(sec: number): string {
  if (sec % 86400 === 0) return sec === 86400 ? 'daily' : `every ${sec / 86400} days`;
  if (sec % 3600 === 0) return sec === 3600 ? 'hourly' : `every ${sec / 3600} hours`;
  return `every ${Math.round(sec / 60)} minutes`;
}

/** What an agent that predates policies runs on its own, in one line. */
export function describeLocalIntervals(li: {
  inventory_seconds: number;
  vuln_seconds: number;
  packages_seconds: number;
  yara: string;
} | null | undefined): string {
  if (!li) return '';
  return (
    `system inventory ${humanSeconds(li.inventory_seconds)}, vulnerabilities ${humanSeconds(li.vuln_seconds)}, ` +
    `packages ${humanSeconds(li.packages_seconds)} (its own defaults), YARA ${li.yara}`
  );
}

/** How many scan types a policy enables, for the list: "3 of 4 scans on". */
export function enabledCount(scans: PolicyScans): number {
  return POLICY_SCAN_TYPES.filter((t) => scans[t.value]?.enabled).length;
}
