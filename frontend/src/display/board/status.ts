import type { Freshness } from '../connection.ts';

/** What the board needs to know about the screen's clock, connection and rotation. */
export interface BoardStatus {
  /** Device clock (ms). */
  deviceNow: number;
  /** Server time minus device time (ms), from the last snapshot. */
  serverOffset: number;
  /** Device ms of the last good snapshot. */
  lastSuccessAt: number | null;
  freshness: Freshness;
  /** Rotation held with Space. */
  paused: boolean;
  /** 0..1 through the current view's dwell, or null when not rotating. */
  progress: number | null;
}
