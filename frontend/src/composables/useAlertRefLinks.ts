import { useRouter } from 'vue-router';
import { alertIdFromHref, alertRefPath } from '@/utils/alertRef';

/**
 * Click handler for rendered AI output (v-html): an ALR-#### link opens that
 * alert through the router instead of reloading the page. The target is
 * rebuilt from the parsed id, never taken from the clicked element.
 */
export function useAlertRefLinks() {
  const router = useRouter();
  return (event: MouseEvent) => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return;
    const target = event.target as Element | null;
    const anchor = target?.closest?.('a[data-alert-ref]');
    if (!anchor) return;
    const id = alertIdFromHref(anchor.getAttribute('href'));
    if (id === null) return;
    event.preventDefault();
    void router.push(alertRefPath(id));
  };
}
