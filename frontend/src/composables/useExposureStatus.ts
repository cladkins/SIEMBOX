import { computed, ref } from 'vue';
import exposureService, { type ExposureStatus } from '@/services/exposureService';
import { apiErrorMessage, domainMonitorState } from '@/utils/exposure';

/**
 * GET /api/exposure/status for one page (the Digital Risk page and Settings →
 * Digital Risk): the latest status, whether a load is in flight, and the last
 * load's error. Loads can overlap (a refresh while an edit reloads it); only
 * the newest one's answer is applied. Callers call refresh() in their own
 * onMounted.
 */
export function useExposureStatus() {
  const status = ref<ExposureStatus | null>(null);
  const loading = ref(false);
  const error = ref<string | null>(null);
  // While the status loads (or if it fails) this is 'on', so no "not checked" note flashes up.
  const domainMonitor = computed(() => domainMonitorState(status.value));

  let latestLoad = 0;

  async function refresh(): Promise<void> {
    const thisLoad = ++latestLoad;
    loading.value = true;
    try {
      const next = await exposureService.getStatus();
      if (thisLoad !== latestLoad) return;
      status.value = next;
      error.value = null;
    } catch (err) {
      if (thisLoad === latestLoad) error.value = apiErrorMessage(err, 'The status request failed.');
    } finally {
      if (thisLoad === latestLoad) loading.value = false;
    }
  }

  return { status, loading, error, refresh, domainMonitor };
}
