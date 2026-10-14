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

/** `s` without its trailing slashes, in one pass from the end (no regex: no backtracking on a run of slashes). */
function stripTrailingSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 0x2f /* / */) end--;
  return s.slice(0, end);
}

/** Trimmed; scheme and host lower case; default port, fragment and trailing slashes dropped. Linear. */
export function normalizeBaseUrl(raw: string): string {
  const s = raw.trim();
  try {
    const u = new URL(s);
    const auth = u.username || u.password ? `${u.username}${u.password ? `:${u.password}` : ''}@` : '';
    return `${u.protocol}//${auth}${u.host}${stripTrailingSlashes(u.pathname)}${u.search}`;
  } catch {
    return stripTrailingSlashes(s);
  }
}

/** A config as the API reports it: its provider and the base URL it uses. */
export interface AiEndpoint {
  provider: string;
  baseUrl: string;
}

/**
 * The base URL a blank (or only spaces) Base URL field stands for: the
 * parent's when the provider is the same, else the provider's default. An
 * empty provider inherits the parent's.
 */
export function blankBaseUrl(provider: string, parent?: AiEndpoint): string {
  const p = provider || parent?.provider || 'anthropic';
  return (parent && parent.provider === p ? parent.baseUrl : '') || DEFAULT_BASE_URLS[p] || '';
}

/**
 * The target of a form's provider and base URL (see blankBaseUrl for a blank
 * one). Anthropic is always called at api.anthropic.com, so its base URL
 * doesn't count.
 */
export function keyTargetOf(provider: string, baseUrl: string, parent?: AiEndpoint): string {
  const p = provider || parent?.provider || 'anthropic';
  if (p === 'anthropic') return 'anthropic';
  return `${p} ${normalizeBaseUrl(baseUrl.trim() || blankBaseUrl(p, parent))}`;
}

/** What the API reports of a config's saved key (GET /api/settings/ai, /ai-chat, /ai-triage). */
export interface SavedKeyState {
  /** The config has a key of its own saved. */
  keySaved: boolean;
  /** The provider and base URL that key was saved for; null when it can't be read. */
  keySavedFor?: AiEndpoint | null;
}

/**
 * Saving the form needs the API key (or removing the saved one), as the
 * backend decides it (planAiSave): the config has a key of its own saved and
 * the form changes where its requests go, other than back to where that key
 * was saved for. `current` is where the config sends requests now (provider
 * and base URL as the API reports them); `parent` is what a blank base URL or
 * an empty provider stands for (see keyTargetOf).
 */
export function keyNeeded(
  form: AiEndpoint,
  current: AiEndpoint,
  saved: SavedKeyState,
  parent?: AiEndpoint
): boolean {
  if (!saved.keySaved) return false;
  const target = keyTargetOf(form.provider, form.baseUrl, parent);
  if (target === keyTargetOf(current.provider, current.baseUrl)) return false;
  const savedFor = saved.keySavedFor;
  return !savedFor || target !== keyTargetOf(savedFor.provider, savedFor.baseUrl);
}
