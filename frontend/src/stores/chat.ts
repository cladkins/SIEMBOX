/**
 * AI Security Analyst chat store. Holds the single active conversation (shared by
 * the dedicated page and the contextual drawer), the user's thread list, and the
 * "not configured" health flag. History is persisted server-side per thread;
 * this store mirrors the current thread for the UI.
 */
import { defineStore } from 'pinia';
import { ref } from 'vue';
import { api } from '@/services/api';

export interface AnalystTraceEntry {
  step: number;
  tool: string;
  args: any;
  ok: boolean;
  ms: number;
  error?: string;
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  trace?: AnalystTraceEntry[];
  truncated?: boolean;
}

export interface ChatSessionMeta {
  id: number;
  title: string;
  updated_at: string;
}

const NOT_CONFIGURED_RE = /api key|configured|provider|ollama|reach/i;

export const useChatStore = defineStore('analystChat', () => {
  const sessions = ref<ChatSessionMeta[]>([]);
  const currentSessionId = ref<number | null>(null);
  const messages = ref<ChatMessage[]>([]);
  const loading = ref(false);
  const notConfigured = ref(false);
  const drawerOpen = ref(false);
  const drawerContext = ref<{ kind: string; id: any } | null>(null);

  async function checkHealth() {
    try {
      const res = await api.getAnalystHealth();
      notConfigured.value = !res.data?.configured;
    } catch {
      notConfigured.value = true;
    }
  }

  async function loadSessions() {
    try {
      const res = await api.listChatSessions();
      sessions.value = res.data?.sessions || [];
    } catch {
      /* non-fatal */
    }
  }

  async function openSession(id: number) {
    loading.value = true;
    try {
      const res = await api.getChatSession(id);
      currentSessionId.value = id;
      messages.value = (res.data?.messages || []).map((m: any) => ({
        role: m.role,
        content: m.content,
        trace: Array.isArray(m.trace) ? m.trace : undefined,
      }));
    } catch {
      /* non-fatal */
    } finally {
      loading.value = false;
    }
  }

  function newSession() {
    currentSessionId.value = null;
    messages.value = [];
  }

  async function send(content: string, context?: { kind: string; id: any }) {
    const text = (content || '').trim();
    if (!text || loading.value) return;
    messages.value.push({ role: 'user', content: text });
    loading.value = true;
    try {
      const res = await api.analystChat(
        currentSessionId.value,
        text,
        context || drawerContext.value || undefined
      );
      const data = res.data || {};
      if (!currentSessionId.value && data.session_id) {
        currentSessionId.value = data.session_id;
        loadSessions();
      } else if (currentSessionId.value) {
        loadSessions(); // refresh ordering/title
      }
      messages.value.push({
        role: 'assistant',
        content: data.answer || '',
        trace: Array.isArray(data.trace) ? data.trace : [],
        truncated: !!data.truncated,
      });
      notConfigured.value = false;
    } catch (e: any) {
      const msg =
        e?.response?.data?.error || e?.response?.data?.message || e?.message || 'Request failed';
      const nc = NOT_CONFIGURED_RE.test(String(msg));
      notConfigured.value = nc;
      messages.value.push({
        role: 'assistant',
        content: nc
          ? '⚠️ The AI Analyst model is not configured or is unreachable. An admin can set it in **Settings → AI Analyst**.'
          : `⚠️ ${msg}`,
      });
    } finally {
      loading.value = false;
    }
  }

  function openWithContext(ctx: { kind: string; id: any }, seed?: string) {
    drawerContext.value = ctx;
    newSession();
    drawerOpen.value = true;
    // Fire the seed question immediately so the drawer shows the answer streaming in.
    if (seed && seed.trim()) send(seed, ctx);
  }

  function clearContext() {
    drawerContext.value = null;
  }

  async function rename(id: number, title: string) {
    try {
      await api.renameChatSession(id, title);
      await loadSessions();
    } catch {
      /* non-fatal */
    }
  }

  async function remove(id: number) {
    try {
      await api.deleteChatSession(id);
      if (currentSessionId.value === id) newSession();
      await loadSessions();
    } catch {
      /* non-fatal */
    }
  }

  return {
    sessions,
    currentSessionId,
    messages,
    loading,
    notConfigured,
    drawerOpen,
    drawerContext,
    checkHealth,
    loadSessions,
    openSession,
    newSession,
    send,
    openWithContext,
    clearContext,
    rename,
    remove,
  };
});
