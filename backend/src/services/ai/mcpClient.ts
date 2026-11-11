/**
 * Minimal MCP client for remote servers over Streamable HTTP: initialize,
 * tools/list and tools/call, nothing else. Every exchange is a JSON-RPC POST to
 * the server's one endpoint; the server answers with JSON or with an SSE stream
 * that carries the response. Each operation opens its own short session (no
 * connection is kept between calls), so a restarted server needs no recovery.
 *
 * Bounds: every request has a timeout, a response is read up to a size cap,
 * and redirects are refused so the auth header is only ever sent to the URL an
 * admin saved.
 */

const PROTOCOL_VERSION = '2025-06-18';
const CLIENT_INFO = { name: 'siembox-ai-analyst', version: '1.0.0' };
export const MCP_REQUEST_TIMEOUT_MS = 20_000;
const MAX_RESPONSE_BYTES = 1_000_000;
const MAX_LIST_PAGES = 10;

export interface McpEndpoint {
  url: string;
  /** Extra request header (name and value) sent with every request, e.g. Authorization. */
  authHeader?: string | null;
  authValue?: string | null;
}

export interface McpToolDef {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: { readOnlyHint?: boolean; title?: string; [k: string]: unknown };
}

export interface McpCallResult {
  content?: Array<{ type: string; text?: string; [k: string]: unknown }>;
  structuredContent?: unknown;
  isError?: boolean;
}

export interface McpClientDeps {
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export class McpError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'McpError';
  }
}

interface Session {
  endpoint: McpEndpoint;
  fetch: typeof fetch;
  timeoutMs: number;
  sessionId?: string;
  protocolVersion?: string;
  nextId: number;
}

function headersFor(s: Session): Record<string, string> {
  const h: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
  };
  if (s.endpoint.authHeader && s.endpoint.authValue) h[s.endpoint.authHeader] = s.endpoint.authValue;
  if (s.sessionId) h['Mcp-Session-Id'] = s.sessionId;
  if (s.protocolVersion) h['MCP-Protocol-Version'] = s.protocolVersion;
  return h;
}

/** Read a body as text, up to the size cap. */
async function readCapped(res: Response): Promise<string> {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let out = '';
  let bytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => undefined);
      throw new McpError(`response larger than ${MAX_RESPONSE_BYTES} bytes`);
    }
    out += decoder.decode(value, { stream: true });
  }
  return out + decoder.decode();
}

/** The JSON-RPC response with `id` from an SSE stream, reading no further than it. */
async function readSseResponse(res: Response, id: number): Promise<any> {
  if (!res.body) throw new McpError('empty event stream');
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (value) {
        bytes += value.byteLength;
        if (bytes > MAX_RESPONSE_BYTES) throw new McpError(`response larger than ${MAX_RESPONSE_BYTES} bytes`);
        buf += decoder.decode(value, { stream: true }).replace(/\r\n?/g, '\n');
      }
      let sep: number;
      while ((sep = buf.indexOf('\n\n')) !== -1 || (done && buf.length > 0)) {
        const block = sep === -1 ? buf : buf.slice(0, sep);
        buf = sep === -1 ? '' : buf.slice(sep + 2);
        const data = block
          .split('\n')
          .filter((l) => l.startsWith('data:'))
          .map((l) => l.slice(5).replace(/^ /, ''))
          .join('\n');
        if (!data) continue;
        let msg: any;
        try {
          msg = JSON.parse(data);
        } catch {
          continue;
        }
        if (msg && msg.id === id && (msg.result !== undefined || msg.error !== undefined)) return msg;
      }
      if (done) break;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  throw new McpError('the event stream ended without a response');
}

async function post(s: Session, body: Record<string, unknown>, expectId?: number): Promise<any> {
  let res: Response;
  try {
    res = await s.fetch(s.endpoint.url, {
      method: 'POST',
      headers: headersFor(s),
      body: JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(s.timeoutMs),
    });
  } catch (e: any) {
    if (e?.name === 'TimeoutError' || e?.name === 'AbortError') {
      throw new McpError(`no response within ${Math.round(s.timeoutMs / 1000)} s`);
    }
    const cause = e?.cause?.code || e?.cause?.message || e?.message || 'request failed';
    throw new McpError(`could not reach the server (${cause})`);
  }
  try {
    const sid = res.headers.get('mcp-session-id');
    if (sid && !s.sessionId) s.sessionId = sid;
    if (!res.ok) {
      const hint = res.status === 401 || res.status === 403 ? ' (check the auth header)' : '';
      await res.body?.cancel().catch(() => undefined);
      throw new McpError(`the server answered HTTP ${res.status}${hint}`);
    }
    if (expectId === undefined) {
      await res.body?.cancel().catch(() => undefined);
      return undefined;
    }
    const type = (res.headers.get('content-type') || '').toLowerCase();
    let msg: any;
    if (type.includes('text/event-stream')) {
      msg = await readSseResponse(res, expectId);
    } else {
      const text = await readCapped(res);
      try {
        msg = JSON.parse(text);
      } catch {
        throw new McpError('the server did not answer with JSON (is this an MCP endpoint?)');
      }
      if (Array.isArray(msg)) msg = msg.find((m) => m && m.id === expectId);
    }
    if (!msg || typeof msg !== 'object') throw new McpError('the server sent no response to the request');
    if (msg.error) {
      throw new McpError(`the server returned an error: ${String(msg.error.message ?? msg.error.code ?? 'unknown')}`.slice(0, 300));
    }
    return msg.result;
  } catch (e: any) {
    if (e instanceof McpError) throw e;
    if (e?.name === 'TimeoutError' || e?.name === 'AbortError') {
      throw new McpError(`no response within ${Math.round(s.timeoutMs / 1000)} s`);
    }
    throw new McpError(`could not read the response (${e?.message || 'unknown error'})`);
  }
}

function request(s: Session, method: string, params?: Record<string, unknown>): Promise<any> {
  const id = s.nextId++;
  return post(s, { jsonrpc: '2.0', id, method, ...(params ? { params } : {}) }, id);
}

async function open(endpoint: McpEndpoint, deps: McpClientDeps): Promise<Session> {
  const s: Session = {
    endpoint,
    fetch: deps.fetch || fetch,
    timeoutMs: deps.timeoutMs ?? MCP_REQUEST_TIMEOUT_MS,
    nextId: 1,
  };
  const init = await request(s, 'initialize', {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: CLIENT_INFO,
  });
  if (!init || typeof init !== 'object') throw new McpError('the server did not complete the MCP handshake');
  s.protocolVersion = typeof init.protocolVersion === 'string' ? init.protocolVersion : PROTOCOL_VERSION;
  await post(s, { jsonrpc: '2.0', method: 'notifications/initialized' });
  return s;
}

/** End the session, best effort (servers without sessions answer 405; ignored). */
async function close(s: Session): Promise<void> {
  if (!s.sessionId) return;
  try {
    const res = await s.fetch(s.endpoint.url, {
      method: 'DELETE',
      headers: headersFor(s),
      redirect: 'error',
      signal: AbortSignal.timeout(3000),
    });
    await res.body?.cancel().catch(() => undefined);
  } catch {
    /* best effort */
  }
}

/** Every tool the server offers (all pages). */
export async function listMcpTools(endpoint: McpEndpoint, deps: McpClientDeps = {}): Promise<McpToolDef[]> {
  const s = await open(endpoint, deps);
  try {
    const tools: McpToolDef[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < MAX_LIST_PAGES; page++) {
      const res = await request(s, 'tools/list', cursor ? { cursor } : undefined);
      for (const t of Array.isArray(res?.tools) ? res.tools : []) {
        if (t && typeof t.name === 'string') tools.push(t);
      }
      cursor = typeof res?.nextCursor === 'string' && res.nextCursor ? res.nextCursor : undefined;
      if (!cursor) break;
    }
    return tools;
  } finally {
    await close(s);
  }
}

/** Call one tool. Resolves with the server's result (which may itself be `isError`). */
export async function callMcpTool(
  endpoint: McpEndpoint,
  name: string,
  args: Record<string, unknown>,
  deps: McpClientDeps = {}
): Promise<McpCallResult> {
  const s = await open(endpoint, deps);
  try {
    const res = await request(s, 'tools/call', { name, arguments: args });
    return res && typeof res === 'object' ? res : {};
  } finally {
    await close(s);
  }
}
