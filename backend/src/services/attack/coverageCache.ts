/**
 * Invalidation for the ATT&CK coverage cache (services/attack/coverageService.ts).
 *
 * Kept dependency-free so DetectionRuleModel can call it on every rule write
 * (create, update, enable/disable, delete: every route, the catalog and
 * content-pack installs and the Sigma import go through the model) without
 * loading the coverage code. Exclusion writes call it too.
 *
 * A generation counter rather than a flag: a computation that started before
 * an invalidation must not store its (stale) result afterwards.
 */
let generation = 0;
const listeners = new Set<() => void>();

export function coverageGeneration(): number {
  return generation;
}

/** Drop every cached coverage result. Cheap; never throws. */
export function invalidateAttackCoverage(): void {
  generation++;
  for (const fn of listeners) {
    try {
      fn();
    } catch {
      /* a listener never breaks a rule write */
    }
  }
}

/** Called on each invalidation (the coverage service drops its snapshot). */
export function onCoverageInvalidated(fn: () => void): void {
  listeners.add(fn);
}
