/**
 * Which view a screen shows (BIG-DISPLAY.md §5.7, §5.10). Pure.
 *
 * The automatic index comes from the server-corrected clock,
 * floor((now + offset) / 1000 / dwell) % views, so every screen on one link
 * rotates in step, and it keeps turning on cached data while offline. The
 * arrow keys shift it, and Space pauses it on the current view.
 */

export interface RotationControl {
  paused: boolean;
  /** The view a paused (or non-rotating) screen holds. */
  held: number;
  /** Views added to the automatic index by the arrow keys. */
  shift: number;
}

export interface RotationInput {
  /** Device ms plus the server offset. */
  serverNow: number;
  dwellSeconds: number;
  views: number;
  /** The link's rotation setting; ignored with one view. */
  enabled: boolean;
}

export function initialControl(): RotationControl {
  return { paused: false, held: 0, shift: 0 };
}

function mod(n: number, m: number): number {
  return ((n % m) + m) % m;
}

function autoTick(input: RotationInput): number {
  return Math.floor(input.serverNow / 1000 / Math.max(1, input.dwellSeconds));
}

export function isRotating(control: RotationControl, input: RotationInput): boolean {
  return input.enabled && input.views > 1 && !control.paused;
}

export function viewIndex(control: RotationControl, input: RotationInput): number {
  if (input.views <= 1) return 0;
  if (!isRotating(control, input)) return mod(control.held, input.views);
  return mod(autoTick(input) + control.shift, input.views);
}

/** How far through the current view's dwell the screen is, 0..1 (null when not rotating). */
export function dwellProgress(control: RotationControl, input: RotationInput): number | null {
  if (!isRotating(control, input)) return null;
  const dwellMs = Math.max(1, input.dwellSeconds) * 1000;
  return mod(input.serverNow, dwellMs) / dwellMs;
}

/** ← / →: move one view, keeping rotation (if any) going from there. */
export function step(control: RotationControl, input: RotationInput, direction: 1 | -1): RotationControl {
  if (input.views <= 1) return control;
  if (isRotating(control, input)) return { ...control, shift: control.shift + direction };
  return { ...control, held: mod(viewIndex(control, input) + direction, input.views) };
}

/** Space / OK: hold the current view, or resume rotating from it. */
export function togglePause(control: RotationControl, input: RotationInput): RotationControl {
  const current = viewIndex(control, input);
  if (control.paused) {
    // Resume from the held view: shift the automatic index onto it.
    return { paused: false, held: current, shift: current - autoTick(input) };
  }
  return { ...control, paused: true, held: current };
}

/**
 * Burn-in shift: every 10 minutes the whole board moves to the next point of
 * an 8-step cycle around a 4 px square, so static edges don't sit on the same
 * pixels for days.
 */
const BURN_IN_CYCLE: ReadonlyArray<readonly [number, number]> = [
  [0, 0],
  [2, 0],
  [4, 0],
  [4, 2],
  [4, 4],
  [2, 4],
  [0, 4],
  [0, 2],
];
export const BURN_IN_STEP_MS = 10 * 60 * 1000;

export function burnInOffset(now: number): { x: number; y: number } {
  const [x, y] = BURN_IN_CYCLE[mod(Math.floor(now / BURN_IN_STEP_MS), BURN_IN_CYCLE.length)];
  return { x, y };
}
