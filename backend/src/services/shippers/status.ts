/**
 * A shipper's status as the UI shows it, worked out from its last heartbeat:
 * pending until it has checked in once, offline after
 * SHIPPER_OFFLINE_THRESHOLD_MINUTES (3) without one, otherwise online (or
 * error, if the shipper said so). Shared by routes/shippers.ts and the Big
 * Display's shippers panel (services/display/panels.ts), so the two agree.
 */
import { SHIPPER_OFFLINE_THRESHOLD_MINUTES } from '../../models/LogShipper';

export type ShipperStatus = 'pending' | 'online' | 'offline' | 'error';

export function calculateStatus(lastSeen: Date | string | null, currentStatus: string, now: number = Date.now()): ShipperStatus {
  if (!lastSeen) {
    return 'pending';
  }

  const minutesSinceLastSeen = (now - new Date(lastSeen).getTime()) / 1000 / 60;

  // Consider offline if no heartbeat for 3 minutes (2x heartbeat interval + buffer)
  if (minutesSinceLastSeen > SHIPPER_OFFLINE_THRESHOLD_MINUTES) {
    return 'offline';
  }

  return currentStatus === 'error' ? 'error' : 'online';
}
