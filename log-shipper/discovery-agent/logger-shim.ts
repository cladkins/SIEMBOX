// Bundle-time replacement for the backend's winston logger
// (backend/src/utils/logger). passiveDiscovery imports that logger for its
// ARP/mDNS/SSDP warnings; pulling winston into the standalone agent bundle would
// bloat it and add a dependency the shipper doesn't need. The agent has no log
// file or transport anyway, so these go to stderr (the shipper captures them).
// See build-discovery-agent.mjs, which resolves `utils/logger` here.
export const logger = {
  info: (...args: unknown[]) => console.error('[discovery-agent]', ...args),
  warn: (...args: unknown[]) => console.error('[discovery-agent]', ...args),
  error: (...args: unknown[]) => console.error('[discovery-agent]', ...args),
  debug: () => {},
};

export default logger;
