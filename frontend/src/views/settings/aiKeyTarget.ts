// Where an AI config's API key is sent, compared the way the backend compares
// it (keyTarget and normalizeBaseUrl in backend/src/services/ai/aiService.ts).
// A saved key is only sent to the provider and base URL it was saved for, so
// the AI settings forms ask for the key again when an edit changes either.
// The backend decides; this only lets a form say so before saving.

export const DEFAULT_BASE_URLS: Record<string, string> = {
  openai: 'https://api.openai.com/v1',
  ollama: 'http://localhost:11434',
};

/** The environment variable the backend falls back to for a provider's key. */
export const ENV_KEY_VARS: Record<string, string> = {
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
};

/** Trimmed; scheme and host lower case; default port, fragment and trailing slashes dropped. */
export function normalizeBaseUrl(raw: string): string {
  const s = raw.trim();
  try {
    const u = new URL(s);
    const auth = u.username || u.password ? `${u.username}${u.password ? `:${u.password}` : ''}@` : '';
    return `${u.protocol}//${auth}${u.host}${u.pathname.replace(/\/+$/, '')}${u.search}`;
  } catch {
    return s.replace(/\/+$/, '');
  }
}

/** A config as the API reports it: its provider and the base URL it uses. */
export interface AiEndpoint {
  provider: string;
  baseUrl: string;
}

/**
 * The target of a form's provider and base URL. An empty provider inherits
 * the parent's; a blank base URL is the parent's when the provider is the same,
 * else the provider's default. Anthropic is always called at
 * api.anthropic.com, so its base URL doesn't count.
 */
export function keyTargetOf(provider: string, baseUrl: string, parent?: AiEndpoint): string {
  const p = provider || parent?.provider || 'anthropic';
  if (p === 'anthropic') return 'anthropic';
  const inherited = parent && parent.provider === p ? parent.baseUrl : '';
  return `${p} ${normalizeBaseUrl(baseUrl.trim() || inherited || DEFAULT_BASE_URLS[p] || '')}`;
}
