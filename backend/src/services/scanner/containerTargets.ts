/**
 * "All discovered images" for a scheduled container scan: every scannable
 * image on the SIEMBox host (Docker socket, when mounted) and on each log
 * shipper's host (its reported container inventory), deduplicated -- the same
 * set the Container Scanning page's "Scan all" button queues.
 */
import { DockerDiscovery, type DiscoveryResult } from './dockerDiscovery';
import { ShipperContainerModel, type ShipperHostInventory } from '../../models/ShipperContainer';

/** Most images one scheduled run queues (Trivy scans them one at a time). */
export const MAX_SCHEDULED_IMAGES = 200;

/** Distinct scannable image refs, SIEMBox host first, capped at `max`. Pure. */
export function scannableImageRefs(
  local: Pick<DiscoveryResult, 'images'>,
  shippers: Pick<ShipperHostInventory, 'images'>[],
  max = MAX_SCHEDULED_IMAGES
): { images: string[]; dropped: number } {
  const seen = new Set<string>();
  for (const img of [...(local.images ?? []), ...shippers.flatMap((s) => s.images ?? [])]) {
    const ref = typeof img.image === 'string' ? img.image.trim() : '';
    if (img.scannable && ref) seen.add(ref);
  }
  const all = [...seen];
  return { images: all.slice(0, max), dropped: Math.max(0, all.length - max) };
}

export async function discoverScannableImages(): Promise<{ images: string[]; dropped: number }> {
  const [local, shippers] = await Promise.all([DockerDiscovery.discoverImages(), ShipperContainerModel.findGroupedByShipper()]);
  return scannableImageRefs(local, shippers);
}
