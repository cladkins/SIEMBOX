<template>
  <div class="analyst-chat" :class="{ embedded }">
    <!-- Thread list (page mode only) -->
    <aside v-if="embedded" class="threads">
      <el-button class="new-btn" type="primary" plain size="small" @click="store.newSession()">
        <el-icon><Plus /></el-icon> New chat
      </el-button>
      <el-scrollbar class="threads-scroll">
        <div
          v-for="s in store.sessions"
          :key="s.id"
          class="thread-row"
          :class="{ active: s.id === store.currentSessionId }"
          @click="store.openSession(s.id)"
        >
          <span class="thread-title">{{ s.title }}</span>
          <el-icon class="thread-del" @click.stop="store.remove(s.id)"><Delete /></el-icon>
        </div>
        <div v-if="!store.sessions.length" class="threads-empty">No conversations yet.</div>
      </el-scrollbar>
    </aside>

    <!-- Conversation -->
    <section class="convo">
      <el-alert
        v-if="store.notConfigured"
        class="cfg-alert"
        type="warning"
        :closable="false"
        show-icon
        title="AI Analyst model not configured"
      >
        An admin can set a provider/model in
        <router-link to="/settings">Settings → AI Analyst</router-link>
        (point it at a local Ollama model or a cloud provider).
      </el-alert>

      <div v-if="store.drawerContext" class="context-chip">
        <el-tag size="small" type="info">context: {{ store.drawerContext.kind }} #{{ store.drawerContext.id }}</el-tag>
      </div>

      <el-scrollbar ref="scrollRef" class="messages">
        <div v-if="!store.messages.length" class="empty">
          <el-icon :size="34"><ChatDotRound /></el-icon>
          <p>Ask about alerts, incidents, vulnerabilities, assets, or threat intel — or what to prioritize.</p>
          <div class="suggestions">
            <el-button
              v-for="q in SUGGESTIONS"
              :key="q"
              size="small"
              plain
              :disabled="store.loading"
              @click="ask(q)"
              >{{ q }}</el-button
            >
          </div>
        </div>

        <div v-for="(m, i) in store.messages" :key="i" class="msg" :class="m.role">
          <div class="msg-role">
            <el-icon v-if="m.role === 'assistant'"><MagicStick /></el-icon>
            <el-icon v-else><User /></el-icon>
            <span>{{ m.role === 'assistant' ? 'Analyst' : 'You' }}</span>
          </div>
          <!-- user content is plain text; assistant content is sanitized markdown -->
          <div v-if="m.role === 'user'" class="msg-body user-body">{{ m.content }}</div>
          <div v-else class="msg-body md-body" v-html="renderMd(m.content)"></div>

          <el-collapse v-if="m.trace && m.trace.length" class="trace">
            <el-collapse-item :title="`Ran ${m.trace.length} tool${m.trace.length > 1 ? 's' : ''}`">
              <div v-for="t in m.trace" :key="t.step" class="trace-row">
                <el-tag size="small" :type="t.ok ? 'success' : 'danger'">{{ t.tool }}</el-tag>
                <code>{{ shortArgs(t.args) }}</code>
                <span class="trace-ms">{{ t.ms }}ms</span>
                <span v-if="t.error" class="trace-err">{{ t.error }}</span>
              </div>
            </el-collapse-item>
          </el-collapse>
          <div v-if="m.truncated" class="truncated">Stopped early at the analysis budget — answer may be partial.</div>
        </div>

        <div v-if="store.loading" class="msg assistant">
          <div class="msg-role"><el-icon><MagicStick /></el-icon><span>Analyst</span></div>
          <div class="msg-body thinking"><el-icon class="spin"><Loading /></el-icon> analyzing…</div>
        </div>
      </el-scrollbar>

      <div class="composer">
        <el-input
          v-model="input"
          type="textarea"
          :rows="2"
          :autosize="{ minRows: 1, maxRows: 5 }"
          resize="none"
          placeholder="Ask the analyst…  (Enter to send, Shift+Enter for a new line)"
          :disabled="store.loading"
          @keydown="onKey"
        />
        <el-button type="primary" :loading="store.loading" :disabled="!input.trim()" @click="sendNow">
          Send
        </el-button>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch, nextTick } from 'vue';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import { ChatDotRound, MagicStick, User, Plus, Delete, Loading } from '@element-plus/icons-vue';
import { useChatStore } from '@/stores/chat';

withDefaults(defineProps<{ embedded?: boolean }>(), { embedded: false });

const store = useChatStore();
const input = ref('');
const scrollRef = ref<any>(null);

const SUGGESTIONS = [
  'What are the top 3 things to fix this week?',
  'Summarize the most critical open alerts.',
  'Which assets are most at risk right now?',
];

// Sanitized markdown for assistant answers. Links open safely; no raw HTML/scripts.
DOMPurify.addHook('afterSanitizeAttributes', (node: any) => {
  if (node.tagName === 'A') {
    node.setAttribute('target', '_blank');
    node.setAttribute('rel', 'noopener noreferrer');
  }
});
function renderMd(text: string): string {
  const html = marked.parse(text || '', { breaks: true, async: false }) as string;
  return DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
}

function shortArgs(args: any): string {
  try {
    const s = JSON.stringify(args || {});
    return s === '{}' ? '' : s.length > 80 ? s.slice(0, 80) + '…' : s;
  } catch {
    return '';
  }
}

function scrollToBottom() {
  nextTick(() => scrollRef.value?.setScrollTop?.(9_999_999));
}

function sendNow() {
  const text = input.value;
  input.value = '';
  store.send(text);
}
function ask(q: string) {
  store.send(q);
}
function onKey(e: KeyboardEvent) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if (input.value.trim() && !store.loading) sendNow();
  }
}

watch(() => store.messages.length, scrollToBottom);
watch(() => store.loading, scrollToBottom);

onMounted(() => {
  store.checkHealth();
  store.loadSessions();
  scrollToBottom();
});
</script>

<style scoped>
.analyst-chat {
  display: flex;
  height: 100%;
  min-height: 0;
  gap: 12px;
}
.threads {
  width: 220px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--el-border-color-lighter);
  padding-right: 8px;
}
.new-btn {
  width: 100%;
  margin-bottom: 8px;
}
.threads-scroll {
  flex: 1;
  min-height: 0;
}
.thread-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 7px 8px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  color: var(--siembox-text-secondary);
}
.thread-row:hover {
  background: var(--el-fill-color-light);
}
.thread-row.active {
  background: var(--el-color-primary-light-9);
  color: var(--siembox-text-color);
}
.thread-title {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.thread-del {
  opacity: 0.5;
}
.thread-del:hover {
  opacity: 1;
  color: var(--el-color-danger);
}
.threads-empty {
  color: var(--siembox-text-secondary);
  font-size: 13px;
  padding: 8px;
}
.convo {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  min-height: 0;
}
.cfg-alert {
  margin-bottom: 8px;
}
.context-chip {
  margin-bottom: 6px;
}
.messages {
  flex: 1;
  min-height: 0;
  padding-right: 6px;
}
.empty {
  text-align: center;
  color: var(--siembox-text-secondary);
  padding: 32px 12px;
}
.empty .suggestions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
  margin-top: 12px;
}
.msg {
  margin-bottom: 14px;
}
.msg-role {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
  font-weight: 600;
  color: var(--siembox-text-secondary);
  margin-bottom: 3px;
}
.msg-body {
  border-radius: 8px;
  padding: 9px 12px;
  font-size: 14px;
  line-height: 1.55;
}
.user-body {
  background: var(--el-color-primary-light-9);
  white-space: pre-wrap;
  word-break: break-word;
}
.md-body {
  background: var(--el-fill-color-light);
  word-break: break-word;
}
.md-body :deep(pre) {
  background: var(--el-fill-color-darker);
  padding: 8px;
  border-radius: 6px;
  overflow-x: auto;
}
.md-body :deep(code) {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 13px;
}
.md-body :deep(table) {
  border-collapse: collapse;
}
.md-body :deep(th),
.md-body :deep(td) {
  border: 1px solid var(--el-border-color);
  padding: 4px 8px;
}
.md-body :deep(p:first-child) {
  margin-top: 0;
}
.md-body :deep(p:last-child) {
  margin-bottom: 0;
}
.thinking {
  color: var(--siembox-text-secondary);
  background: var(--el-fill-color-light);
}
.spin {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
.trace {
  margin-top: 4px;
}
.trace-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  padding: 2px 0;
  color: var(--siembox-text-secondary);
}
.trace-row code {
  font-size: 11px;
}
.trace-ms {
  margin-left: auto;
}
.trace-err {
  color: var(--el-color-danger);
}
.truncated {
  font-size: 12px;
  color: var(--el-color-warning);
  margin-top: 4px;
}
.composer {
  display: flex;
  gap: 8px;
  align-items: flex-end;
  padding-top: 10px;
  border-top: 1px solid var(--el-border-color-lighter);
}
.composer .el-textarea {
  flex: 1;
}
</style>
