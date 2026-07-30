// Maps a fingerprint id to its poll adapter. This is also how a fingerprint
// with no real api_pull support gets skipped automatically: poller.ts resolves
// via `fingerprint.log_access.find(la => la.method === 'api_pull')`, never via
// `credentials.optional`, so e.g. proxmox's dead `task_log_pull` declaration
// (no matching log_access entry) never reaches this registry at all.
import { ApiPollAdapter } from './types';
import { authentikAdapter } from './adapters/authentik';
import { homeAssistantAdapter } from './adapters/homeAssistant';
import { piholeAdapter } from './adapters/pihole';
import { adguardHomeAdapter } from './adapters/adguardHome';

const ADAPTERS: Record<string, ApiPollAdapter> = {
  authentik: authentikAdapter,
  'home-assistant': homeAssistantAdapter,
  pihole: piholeAdapter,
  'adguard-home': adguardHomeAdapter,
};

export function getAdapter(fingerprintId: string): ApiPollAdapter | undefined {
  return ADAPTERS[fingerprintId];
}

export function listPollableFingerprintIds(): string[] {
  return Object.keys(ADAPTERS);
}
