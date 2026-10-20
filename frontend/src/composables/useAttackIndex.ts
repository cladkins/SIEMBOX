import { shallowRef } from 'vue';
import { api } from '@/services/api';
import { buildTechniqueIndex, type TechniqueIndex } from '@/utils/attack';

/**
 * Every live ATT&CK technique of the bundled dataset (GET /api/attack/matrix
 * ?platforms=all), indexed for names, search and tactic filters. Loaded once
 * per page load and shared by the Rules, catalog and Alerts views; a failure
 * leaves it null (chips then show bare IDs) and the next caller retries.
 */
const index = shallowRef<TechniqueIndex | null>(null);
let pending: Promise<TechniqueIndex | null> | null = null;

export function useAttackIndex() {
  if (!index.value && !pending) {
    pending = api
      .getAttackMatrix('all')
      .then(({ data }) => {
        index.value = buildTechniqueIndex(data);
        return index.value;
      })
      .catch(() => null)
      .finally(() => {
        pending = null;
      });
  }
  return index;
}
