/**
 * MCP servers for the AI Analyst (Settings -> AI -> MCP servers).
 *
 * An admin adds a remote MCP server (URL plus an optional auth header), syncs
 * its tool list, and enables tools one by one. The enabled tools join the
 * analyst's tool menu as `mcp__<server>__<tool>`.
 *
 * Safety model, which differs from the built-in tools (analystTools.ts):
 * - The built-in tools are read-only by construction. An MCP tool does whatever
 *   its server does, so nothing reaches the model until an admin enables it.
 *   On the first sync only tools the server marks read-only start enabled.
 * - The model sees the name, description and argument schema stored at the last
 *   admin-triggered sync, never a live copy, so a server cannot change what an
 *   approved tool says without an admin syncing again. A tool whose definition
 *   changed on a later sync is switched off until an admin enables it again.
 * - Automated triage runs unattended over attacker-influenced alert content. It
 *   gets a server's tools only when that server's "use in triage" switch is on,
 *   and then only the enabled tools whose own triage switch is on. That switch
 *   starts on for tools the server marks read-only and off for the rest; an
 *   admin can override it per tool, in either direction (toolAllowedInTriage).
 * - The auth value is encrypted at rest, never returned, and bound to the URL:
 *   changing the URL requires entering it again. Redirects are refused.
 */
import { query } from '../../config/database';
import { CredentialEncryption } from '../credentials/credentialEncryption';
import { logger } from '../../utils/logger';
import type { AnalystTool } from './analystTools';
import { callMcpTool, listMcpTools, McpCallResult, McpClientDeps, McpEndpoint, McpToolDef } from './mcpClient';

export const MAX_MCP_SERVERS = 10;
export const MAX_TOOLS_PER_SERVER = 100;
/** Enabled MCP tools offered to the model in one run (keeps the system prompt bounded). */
export const MAX_MCP_TOOLS_PER_RUN = 40;
const MAX_URL_LENGTH = 500;
const MAX_AUTH_VALUE_LENGTH = 4000;
const MAX_DESCRIPTION_CHARS = 400;
const MAX_SCHEMA_CHARS = 4000;
const MAX_ARGS_SPEC_CHARS = 300;
const NAME_RE = /^[a-z0-9][a-z0-9_]{0,23}$/;
const TOOL_NAME_RE = /^[A-Za-z0-9_.\-/]{1,64}$/;
const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;
// Headers the client sets itself, or that change how the request is framed.
const RESERVED_HEADERS = new Set([
  'host',
  'content-type',
  'content-length',
  'accept',
  'connection',
  'transfer-encoding',
  'mcp-session-id',
  'mcp-protocol-version',
]);

export interface McpStoredTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  /** The server marks the tool read-only (annotations.readOnlyHint). Self-declared. */
  readOnly: boolean;
  enabled: boolean;
  /**
   * The admin's per-tool triage override. Absent (rows stored before the
   * override existed, or never set): triage follows `readOnly`.
   */
  triage?: boolean;
}

/** Whether triage may use the tool, given its server is on for triage: the override, else the read-only mark. */
export function toolAllowedInTriage(t: Pick<McpStoredTool, 'readOnly' | 'triage'>): boolean {
  return typeof t.triage === 'boolean' ? t.triage : !!t.readOnly;
}

interface McpServerRow {
  id: number;
  name: string;
  url: string;
  auth_header: string | null;
  auth_value: string | null;
  enabled: boolean;
  triage_enabled: boolean;
  tools: McpStoredTool[];
  last_sync_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

/** A server as the admin API returns it: no auth value, only whether one is saved. */
export interface McpServerPublic {
  id: number;
  name: string;
  url: string;
  authHeader: string | null;
  hasAuthValue: boolean;
  enabled: boolean;
  triageEnabled: boolean;
  /** `triage`: the effective per-tool triage switch (toolAllowedInTriage). */
  tools: Array<Pick<McpStoredTool, 'name' | 'description' | 'readOnly' | 'enabled'> & { triage: boolean }>;
  lastSyncAt: string | null;
  lastError: string | null;
}

export class McpValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'McpValidationError';
  }
}
export class McpNotFoundError extends Error {
  constructor() {
    super('MCP server not found');
    this.name = 'McpNotFoundError';
  }
}

export interface McpServerInput {
  name?: unknown;
  url?: unknown;
  authHeader?: unknown;
  /** A string sets it, '' or null removes it, undefined keeps it. */
  authValue?: unknown;
  enabled?: unknown;
  triageEnabled?: unknown;
  /** Per-tool switches: [{ name, enabled?, triage? }]. */
  tools?: unknown;
}

// ---- validation (pure) --------------------------------------------------------

export function validateName(v: unknown): string {
  if (typeof v !== 'string' || !NAME_RE.test(v)) {
    throw new McpValidationError(
      'name must be 1-24 characters: lowercase letters, digits and underscores, starting with a letter or digit'
    );
  }
  if (v.includes('__')) throw new McpValidationError('name must not contain a double underscore');
  return v;
}

export function validateUrl(v: unknown): string {
  if (typeof v !== 'string' || !v.trim()) throw new McpValidationError('url is required');
  const raw = v.trim();
  if (raw.length > MAX_URL_LENGTH) throw new McpValidationError(`url must be at most ${MAX_URL_LENGTH} characters`);
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new McpValidationError('url is not a valid URL');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new McpValidationError('url must start with http:// or https://');
  }
  if (u.username || u.password) {
    throw new McpValidationError('url must not contain credentials; use the auth header instead');
  }
  u.hash = '';
  return u.toString();
}

export function validateAuthHeader(v: unknown): string | null {
  if (v === undefined || v === null || v === '') return null;
  if (typeof v !== 'string' || !HEADER_NAME_RE.test(v)) {
    throw new McpValidationError('authHeader must be a header name (letters, digits and hyphens)');
  }
  if (RESERVED_HEADERS.has(v.toLowerCase())) throw new McpValidationError(`authHeader "${v}" is reserved`);
  return v;
}

function validateAuthValue(v: unknown): string {
  if (typeof v !== 'string') throw new McpValidationError('authValue must be a string, or "" to remove it');
  if (v.length > MAX_AUTH_VALUE_LENGTH) {
    throw new McpValidationError(`authValue must be at most ${MAX_AUTH_VALUE_LENGTH} characters`);
  }
  if (/[\r\n\0]/.test(v)) throw new McpValidationError('authValue must not contain line breaks');
  return v;
}

function validateBool(v: unknown, field: string): boolean {
  if (typeof v !== 'boolean') throw new McpValidationError(`${field} must be a boolean`);
  return v;
}

// ---- tool definitions (pure) ---------------------------------------------------

function clip(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

/** The stored form of one server-reported tool, or null when its name is unusable. */
export function toStoredTool(def: McpToolDef): Omit<McpStoredTool, 'enabled' | 'triage'> | null {
  if (!def || typeof def.name !== 'string' || !TOOL_NAME_RE.test(def.name)) return null;
  let schema: Record<string, unknown> = { type: 'object' };
  if (def.inputSchema && typeof def.inputSchema === 'object' && !Array.isArray(def.inputSchema)) {
    try {
      if (JSON.stringify(def.inputSchema).length <= MAX_SCHEMA_CHARS) {
        schema = def.inputSchema as Record<string, unknown>;
      }
    } catch {
      /* keep the placeholder */
    }
  }
  const description = typeof def.description === 'string' ? def.description : '';
  return {
    name: def.name,
    // One line, bounded: this text goes into the system prompt.
    description: clip(description.replace(/\s+/g, ' ').trim(), MAX_DESCRIPTION_CHARS),
    inputSchema: schema,
    readOnly: def.annotations?.readOnlyHint === true,
  };
}

/**
 * The tool list after a sync. A tool new to the server starts enabled only when
 * the server marks it read-only. A known tool keeps its switches, unless its
 * definition changed, in which case it is switched off for review and its
 * triage override is dropped (triage follows the new read-only mark again).
 */
export function mergeSyncedTools(previous: McpStoredTool[], reported: McpToolDef[]): McpStoredTool[] {
  const before = new Map(previous.map((t) => [t.name, t]));
  const out: McpStoredTool[] = [];
  const seen = new Set<string>();
  for (const def of reported) {
    if (out.length >= MAX_TOOLS_PER_SERVER) break;
    const t = toStoredTool(def);
    if (!t || seen.has(t.name)) continue;
    seen.add(t.name);
    const old = before.get(t.name);
    if (!old) {
      out.push({ ...t, enabled: t.readOnly });
      continue;
    }
    const same =
      old.description === t.description &&
      old.readOnly === t.readOnly &&
      JSON.stringify(old.inputSchema) === JSON.stringify(t.inputSchema);
    out.push({
      ...t,
      enabled: same ? old.enabled : false,
      ...(same && typeof old.triage === 'boolean' ? { triage: old.triage } : {}),
    });
  }
  return out;
}

/** A compact, one-line argument spec for the system prompt, from a JSON Schema. */
export function argsSpec(schema: Record<string, unknown>): string {
  const props = schema && typeof schema.properties === 'object' && schema.properties ? schema.properties : null;
  if (!props || Object.keys(props).length === 0) return 'none';
  const required = new Set(Array.isArray(schema.required) ? (schema.required as unknown[]).map(String) : []);
  const parts = Object.entries(props as Record<string, any>).map(([key, p]) => {
    let type = 'any';
    if (p && Array.isArray(p.enum) && p.enum.length && p.enum.length <= 8) {
      type = p.enum.map((e: unknown) => String(e)).join('|');
    } else if (p && typeof p.type === 'string') {
      type = p.type;
    } else if (p && Array.isArray(p.type)) {
      type = p.type.join('|');
    }
    return `${key}${required.has(key) ? '' : '?'}(${clip(type, 60)})`;
  });
  return clip(parts.join(', '), MAX_ARGS_SPEC_CHARS);
}

/** What the model receives from a tool call: text content joined, structured content as is. */
export function shapeCallResult(res: McpCallResult): any {
  const text = (Array.isArray(res.content) ? res.content : [])
    .filter((c) => c && c.type === 'text' && typeof c.text === 'string')
    .map((c) => c.text as string)
    .join('\n');
  if (res.isError) return { error: clip(text || 'the tool reported an error', 600) };
  const other = (Array.isArray(res.content) ? res.content : []).filter((c) => c && c.type !== 'text').length;
  const out: Record<string, unknown> = {};
  if (res.structuredContent !== undefined && res.structuredContent !== null) out.data = res.structuredContent;
  if (text && out.data === undefined) out.text = text;
  if (other) out.omitted = `${other} non-text content block(s)`;
  if (out.data === undefined && out.text === undefined) out.text = '';
  return out;
}

export function mcpToolName(server: string, tool: string): string {
  return `mcp__${server}__${tool}`;
}

// ---- storage -------------------------------------------------------------------

function toPublic(r: McpServerRow): McpServerPublic {
  return {
    id: r.id,
    name: r.name,
    url: r.url,
    authHeader: r.auth_header,
    hasAuthValue: !!r.auth_value,
    enabled: r.enabled,
    triageEnabled: r.triage_enabled,
    tools: (r.tools || []).map((t) => ({
      name: t.name,
      description: t.description,
      readOnly: !!t.readOnly,
      enabled: !!t.enabled,
      triage: toolAllowedInTriage(t),
    })),
    lastSyncAt: r.last_sync_at,
    lastError: r.last_error,
  };
}

function encryptValue(plain: string): string {
  // Throws when CREDENTIAL_ENCRYPTION_KEY is unset.
  return JSON.stringify(CredentialEncryption.encrypt(plain));
}

function endpointOf(r: McpServerRow): McpEndpoint {
  let authValue: string | null = null;
  if (r.auth_header && r.auth_value) {
    try {
      const { encrypted, iv, authTag } = JSON.parse(r.auth_value);
      authValue = CredentialEncryption.decrypt(encrypted, iv, authTag);
    } catch {
      throw new Error('the saved auth value could not be decrypted; enter it again in Settings → AI');
    }
  }
  return { url: r.url, authHeader: r.auth_header, authValue };
}

async function getRow(id: number): Promise<McpServerRow> {
  const res = await query('SELECT * FROM ai_mcp_servers WHERE id = $1', [id]);
  if (!res.rows[0]) throw new McpNotFoundError();
  return res.rows[0];
}

export async function listMcpServers(): Promise<McpServerPublic[]> {
  const res = await query('SELECT * FROM ai_mcp_servers ORDER BY name');
  return res.rows.map(toPublic);
}

export async function createMcpServer(input: McpServerInput): Promise<McpServerPublic> {
  const name = validateName(input.name);
  const url = validateUrl(input.url);
  const authHeader = validateAuthHeader(input.authHeader);
  const authValue =
    input.authValue === undefined || input.authValue === null || input.authValue === ''
      ? null
      : validateAuthValue(input.authValue);
  if (authValue && !authHeader) throw new McpValidationError('authHeader is required with authValue');
  const enabled = input.enabled === undefined ? true : validateBool(input.enabled, 'enabled');
  const triageEnabled =
    input.triageEnabled === undefined ? false : validateBool(input.triageEnabled, 'triageEnabled');

  const count = await query('SELECT COUNT(*)::int AS n FROM ai_mcp_servers');
  if (count.rows[0].n >= MAX_MCP_SERVERS) {
    throw new McpValidationError(`at most ${MAX_MCP_SERVERS} MCP servers can be configured`);
  }
  const dup = await query('SELECT 1 FROM ai_mcp_servers WHERE name = $1', [name]);
  if (dup.rows.length) throw new McpValidationError(`an MCP server named "${name}" already exists`);

  const res = await query(
    `INSERT INTO ai_mcp_servers (name, url, auth_header, auth_value, enabled, triage_enabled)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
    [name, url, authHeader, authValue ? encryptValue(authValue) : null, enabled, triageEnabled]
  );
  return toPublic(res.rows[0]);
}

export async function updateMcpServer(id: number, input: McpServerInput): Promise<McpServerPublic> {
  const row = await getRow(id);
  const url = input.url === undefined ? row.url : validateUrl(input.url);
  const authHeader = input.authHeader === undefined ? row.auth_header : validateAuthHeader(input.authHeader);
  const enabled = input.enabled === undefined ? row.enabled : validateBool(input.enabled, 'enabled');
  const triageEnabled =
    input.triageEnabled === undefined ? row.triage_enabled : validateBool(input.triageEnabled, 'triageEnabled');

  let authValue = row.auth_value;
  if (input.authValue === '' || input.authValue === null) {
    authValue = null;
  } else if (input.authValue !== undefined) {
    authValue = encryptValue(validateAuthValue(input.authValue));
  } else if (row.auth_value && url !== row.url) {
    // The saved value was entered for the old URL: never send it somewhere new unasked.
    throw new McpValidationError(
      'the saved auth value belongs to the previous URL: send authValue again, or "" to remove it'
    );
  }
  if (!authHeader) authValue = null;
  if (authValue && !authHeader) throw new McpValidationError('authHeader is required with authValue');

  let tools = row.tools || [];
  if (input.tools !== undefined) {
    const shape = 'tools must be an array of { name, enabled?, triage? } with at least one boolean switch';
    if (!Array.isArray(input.tools)) throw new McpValidationError(shape);
    const switches = new Map<string, { enabled?: boolean; triage?: boolean }>();
    for (const t of input.tools) {
      const ok =
        t &&
        typeof t.name === 'string' &&
        (t.enabled === undefined || typeof t.enabled === 'boolean') &&
        (t.triage === undefined || typeof t.triage === 'boolean') &&
        (t.enabled !== undefined || t.triage !== undefined);
      if (!ok) throw new McpValidationError(shape);
      switches.set(t.name, { enabled: t.enabled, triage: t.triage });
    }
    tools = tools.map((t) => {
      const sw = switches.get(t.name);
      if (!sw) return t;
      return {
        ...t,
        ...(sw.enabled !== undefined ? { enabled: sw.enabled } : {}),
        ...(sw.triage !== undefined ? { triage: sw.triage } : {}),
      };
    });
  }
  // A different URL is a different server: its tools need a fresh sync and review.
  if (url !== row.url) tools = [];

  const res = await query(
    `UPDATE ai_mcp_servers
        SET url = $2, auth_header = $3, auth_value = $4, enabled = $5, triage_enabled = $6,
            tools = $7::jsonb, last_sync_at = CASE WHEN $8 THEN NULL ELSE last_sync_at END, updated_at = NOW()
      WHERE id = $1 RETURNING *`,
    [id, url, authHeader, authValue, enabled, triageEnabled, JSON.stringify(tools), url !== row.url]
  );
  return toPublic(res.rows[0]);
}

export async function deleteMcpServer(id: number): Promise<void> {
  const res = await query('DELETE FROM ai_mcp_servers WHERE id = $1', [id]);
  if (!res.rowCount) throw new McpNotFoundError();
}

/**
 * Fetch the server's tool list and store it (mergeSyncedTools). A failure is
 * stored as last_error and returned with the server, not thrown: the row stays
 * as it was, so tools already approved keep working if the server comes back.
 */
export async function syncMcpServer(id: number, deps: McpClientDeps = {}): Promise<McpServerPublic> {
  const row = await getRow(id);
  let reported: McpToolDef[];
  try {
    reported = await listMcpTools(endpointOf(row), deps);
  } catch (e) {
    const message = clip(e instanceof Error ? e.message : String(e), 300);
    const res = await query(
      'UPDATE ai_mcp_servers SET last_error = $2, updated_at = NOW() WHERE id = $1 RETURNING *',
      [id, message]
    );
    return toPublic(res.rows[0] ?? row);
  }
  const tools = mergeSyncedTools(row.tools || [], reported);
  const res = await query(
    `UPDATE ai_mcp_servers SET tools = $2::jsonb, last_sync_at = NOW(), last_error = NULL, updated_at = NOW()
      WHERE id = $1 RETURNING *`,
    [id, JSON.stringify(tools)]
  );
  return toPublic(res.rows[0] ?? row);
}

// ---- tools for the agent loops ---------------------------------------------------

export type McpScope = 'chat' | 'triage';

/** The AnalystTool entries for the enabled tools of the given servers (pure but for `call`). */
export function buildMcpTools(
  rows: Array<Pick<McpServerRow, 'name' | 'enabled' | 'triage_enabled' | 'tools'>>,
  scope: McpScope,
  call: (serverName: string, tool: string, args: Record<string, unknown>) => Promise<McpCallResult>
): AnalystTool[] {
  const out: AnalystTool[] = [];
  for (const row of rows) {
    if (!row.enabled) continue;
    if (scope === 'triage' && !row.triage_enabled) continue;
    for (const t of row.tools || []) {
      if (!t.enabled) continue;
      if (scope === 'triage' && !toolAllowedInTriage(t)) continue;
      if (out.length >= MAX_MCP_TOOLS_PER_RUN) return out;
      out.push({
        name: mcpToolName(row.name, t.name),
        description: `(external MCP server "${row.name}"${t.readOnly ? '' : ', may change that system'}) ${t.description || t.name}`,
        args: argsSpec(t.inputSchema),
        external: true,
        readOnly: t.readOnly,
        run: async (args) => {
          const a = args && typeof args === 'object' && !Array.isArray(args) ? args : {};
          return shapeCallResult(await call(row.name, t.name, a));
        },
      });
    }
  }
  return out;
}

/**
 * The enabled MCP tools for a chat or a triage run. Never throws: with no
 * servers, no table yet, or a database error the analyst runs on its built-in
 * tools alone.
 */
export async function loadMcpTools(scope: McpScope, deps: McpClientDeps = {}): Promise<AnalystTool[]> {
  try {
    const res = await query('SELECT * FROM ai_mcp_servers WHERE enabled = TRUE ORDER BY name');
    const rows: McpServerRow[] = res.rows;
    if (!rows.length) return [];
    const byName = new Map(rows.map((r) => [r.name, r]));
    return buildMcpTools(rows, scope, async (serverName, tool, args) => {
      const row = byName.get(serverName) as McpServerRow;
      return callMcpTool(endpointOf(row), tool, args, deps);
    });
  } catch (e) {
    logger.warn('AI: could not load MCP tools; continuing with built-in tools only', {
      error: e instanceof Error ? e.message : String(e),
    });
    return [];
  }
}
