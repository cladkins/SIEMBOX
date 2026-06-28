import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { explain, getChatAiPublicConfig } from '../services/ai/aiService';
import { runAnalystChat } from '../services/ai/analystChat';
import { ChatThreadModel } from '../models/ChatThread';
import type { Role } from '../services/ai/analystTools';

const router = Router();

// "Explain this" assistant. Available to any authenticated user (read-only
// analysis), unlike the admin-only parser/detection generators. Reuses the
// configured provider/key; requires AI to be configured (Settings -> AI Builder).
router.post('/explain', async (req: Request, res: Response) => {
  try {
    const { kind, data, question } = req.body ?? {};
    const empty =
      data === undefined ||
      data === null ||
      (typeof data === 'string' && data.trim() === '');
    if (empty) {
      throw new ApiError(400, 'data is required');
    }
    const result = await explain({
      kind: typeof kind === 'string' && kind.trim() ? kind : 'artifact',
      data,
      question: typeof question === 'string' ? question : undefined,
    });
    res.json(result);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      500,
      `AI explain failed: ${error instanceof Error ? error.message : 'unknown error'}`
    );
  }
});

// ===========================
// AI Security Analyst (chat)
// ===========================

const MAX_MESSAGE_CHARS = 8000;

// In-memory guards (per backend process): one in-flight chat per user, and a
// sliding-window rate limit. Bounds cost for both paid APIs and slow local models.
const inflight = new Set<number>();
const rateHits = new Map<number, number[]>();
const RATE_MAX = 20;
const RATE_WINDOW_MS = 5 * 60 * 1000;

function allowRate(userId: number): boolean {
  const now = Date.now();
  const arr = (rateHits.get(userId) || []).filter((t) => now - t < RATE_WINDOW_MS);
  if (arr.length >= RATE_MAX) {
    rateHits.set(userId, arr);
    return false;
  }
  arr.push(now);
  rateHits.set(userId, arr);
  return true;
}

function titleFrom(message: string): string {
  return message.trim().replace(/\s+/g, ' ').slice(0, 60) || 'New chat';
}

// Public config for the chat model (no secrets) — lets the UI show a
// "not configured" banner before the user types.
router.get('/chat/health', async (_req: Request, res: Response) => {
  try {
    res.json(await getChatAiPublicConfig());
  } catch (error) {
    throw new ApiError(500, 'Failed to read AI analyst config');
  }
});

// List the current user's chat threads.
router.get('/chat/sessions', async (req: Request, res: Response) => {
  if (!req.user) throw new ApiError(401, 'Authentication required');
  try {
    res.json({ sessions: await ChatThreadModel.listSessions(req.user.id) });
  } catch (error) {
    throw new ApiError(500, 'Failed to list chat sessions');
  }
});

// Get one thread's messages (scoped to the owner).
router.get('/chat/sessions/:id', async (req: Request, res: Response) => {
  if (!req.user) throw new ApiError(401, 'Authentication required');
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) throw new ApiError(400, 'invalid session id');
  const session = await ChatThreadModel.getSession(id, req.user.id);
  if (!session) throw new ApiError(404, 'Chat session not found');
  const messages = await ChatThreadModel.getMessages(id, req.user.id);
  res.json({ session, messages });
});

// Rename a thread.
router.patch('/chat/sessions/:id', async (req: Request, res: Response) => {
  if (!req.user) throw new ApiError(401, 'Authentication required');
  const id = parseInt(req.params.id, 10);
  const { title } = req.body ?? {};
  if (!Number.isFinite(id)) throw new ApiError(400, 'invalid session id');
  if (typeof title !== 'string' || !title.trim()) throw new ApiError(400, 'title is required');
  const updated = await ChatThreadModel.renameSession(id, req.user.id, title);
  if (!updated) throw new ApiError(404, 'Chat session not found');
  res.json(updated);
});

// Delete a thread (and its messages, via cascade).
router.delete('/chat/sessions/:id', async (req: Request, res: Response) => {
  if (!req.user) throw new ApiError(401, 'Authentication required');
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) throw new ApiError(400, 'invalid session id');
  const ok = await ChatThreadModel.deleteSession(id, req.user.id);
  if (!ok) throw new ApiError(404, 'Chat session not found');
  res.json({ deleted: true });
});

// Send a message to the analyst. Creates a thread if none is supplied, loads the
// thread's prior turns, runs the read-only tool loop, and persists both turns.
router.post('/chat', async (req: Request, res: Response) => {
  if (!req.user) throw new ApiError(401, 'Authentication required');
  const userId = req.user.id;
  const role = req.user.role as Role;

  const { session_id, message, context } = req.body ?? {};
  if (typeof message !== 'string' || !message.trim()) {
    throw new ApiError(400, 'message is required');
  }
  if (message.length > MAX_MESSAGE_CHARS) {
    throw new ApiError(400, `message too long (max ${MAX_MESSAGE_CHARS} characters)`);
  }
  if (!allowRate(userId)) {
    throw new ApiError(429, 'Too many analyst requests — please wait a moment and try again.');
  }
  if (inflight.has(userId)) {
    throw new ApiError(429, 'An analyst request is already in progress for your account.');
  }
  inflight.add(userId);
  try {
    // Resolve the thread (verify ownership when an id is supplied).
    let session = null as Awaited<ReturnType<typeof ChatThreadModel.getSession>>;
    if (session_id !== undefined && session_id !== null) {
      const sid = parseInt(String(session_id), 10);
      if (!Number.isFinite(sid)) throw new ApiError(400, 'invalid session_id');
      session = await ChatThreadModel.getSession(sid, userId);
      if (!session) throw new ApiError(404, 'Chat session not found');
    } else {
      session = await ChatThreadModel.createSession(userId, titleFrom(message));
    }

    // Prior turns + the new user message form the conversation for this run.
    const prior = await ChatThreadModel.getMessages(session.id, userId);
    const convo = [
      ...prior.map((m) => ({ role: m.role, content: m.content })),
      { role: 'user' as const, content: message },
    ];

    await ChatThreadModel.addMessage(session.id, 'user', message);

    const ctx =
      context && typeof context === 'object' && context.kind
        ? { kind: String(context.kind), id: context.id }
        : undefined;

    let result: Awaited<ReturnType<typeof runAnalystChat>>;
    try {
      result = await runAnalystChat({ messages: convo, user: { id: userId, role }, context: ctx });
    } catch (e) {
      // Keep the persisted thread consistent: record the failure as the assistant
      // turn so a reload doesn't show a dangling user message with no reply. The
      // original message (e.g. "No Anthropic API key…", "Could not reach…") is
      // preserved so the client's not-configured detection still fires.
      const msg = e instanceof Error ? e.message : 'unknown error';
      await ChatThreadModel.addMessage(session.id, 'assistant', `⚠️ ${msg}`).catch(() => undefined);
      throw new ApiError(500, msg);
    }

    await ChatThreadModel.addMessage(session.id, 'assistant', result.answer, result.trace);

    res.json({
      session_id: session.id,
      answer: result.answer,
      trace: result.trace,
      iterations: result.iterations,
      truncated: result.truncated,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      500,
      `AI analyst failed: ${error instanceof Error ? error.message : 'unknown error'}`
    );
  } finally {
    inflight.delete(userId);
  }
});

export default router;
