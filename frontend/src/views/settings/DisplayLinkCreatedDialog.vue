<template>
  <el-dialog
    :model-value="secret !== null"
    :title="rotated ? `New link for ${secret?.link.name}` : `Display link ${secret?.link.name} created`"
    width="min(720px, 96vw)"
    :close-on-click-modal="false"
    :close-on-press-escape="false"
    :show-close="false"
    class="display-link-created"
  >
    <template v-if="secret">
      <el-alert type="warning" :closable="false" show-icon title="Copy this link now — it won't be shown again" class="block" />
      <div class="url-row">
        <el-input :model-value="url" readonly data-testid="created-url" @focus="($event.target as HTMLInputElement).select()" />
        <el-button type="primary" :icon="CopyDocument" data-testid="copy-url" @click="copy">Copy</el-button>
      </div>

      <div class="body">
        <div class="qr">
          <qrcode-vue :value="url" :size="200" level="M" render-as="svg" />
          <div class="hint">For tablets and TVs with a camera</div>
        </div>
        <div class="tips">
          <h4>Putting it on a screen</h4>
          <ul>
            <li>
              Chromium in kiosk mode (quote the URL: it contains <code>#</code>):
              <pre>chromium --kiosk --noerrdialogs --disable-session-crashed-bubble '{{ url }}'</pre>
            </li>
            <li>Raspberry Pi: put that command in the desktop's autostart, and turn screen blanking off.</li>
            <li>Fire TV (Silk): open the link, bookmark it, then choose full screen.</li>
          </ul>
          <p>One link per screen: to take a screen off, rotate or revoke its link.</p>
        </div>
      </div>

      <el-alert
        type="error"
        :closable="false"
        show-icon
        title="Anyone with this link can see this display. Treat it like a password: keep it out of screenshots, tickets and chat."
        class="block"
      />
    </template>

    <template #footer>
      <el-checkbox v-model="copied" data-testid="copied-check">I've copied the link</el-checkbox>
      <el-button type="primary" :disabled="!copied" class="ml" data-testid="created-done" @click="done">Done</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
/**
 * The link of a new or rotated display link, shown once (BIG-DISPLAY.md
 * §8.3). The secret lives only in this component's props: it is never
 * stored, logged or put in the address bar, and the dialog can only be closed
 * once the admin ticks that they copied it.
 */
import { computed, ref, watch } from 'vue';
import { ElMessage } from 'element-plus';
import { CopyDocument } from '@element-plus/icons-vue';
import QrcodeVue from 'qrcode.vue';
import type { DisplayLinkSecret } from '@/utils/displayLinks';

const props = defineProps<{ secret: DisplayLinkSecret | null; rotated: boolean }>();
const emit = defineEmits<{ close: [] }>();

const copied = ref(false);
watch(
  () => props.secret,
  () => (copied.value = false)
);

/** The server never needs its own public URL: the screen opens this origin's /display. */
const url = computed(() => (props.secret ? `${window.location.origin}${props.secret.path}` : ''));

async function copy() {
  try {
    await navigator.clipboard.writeText(url.value);
    ElMessage.success('Link copied');
  } catch {
    ElMessage.warning('Copying was refused by the browser: select the link and copy it yourself.');
  }
}

function done() {
  if (copied.value) emit('close');
}
</script>

<style scoped>
.url-row {
  display: flex;
  gap: 8px;
  margin-bottom: 16px;
}
.body {
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
}
.qr {
  text-align: center;
  background: #fff;
  padding: 12px;
  border-radius: 6px;
  align-self: flex-start;
}
.qr .hint {
  color: #555;
  font-size: 12px;
  margin-top: 4px;
}
.tips {
  flex: 1 1 280px;
  font-size: 13px;
}
.tips h4 {
  margin: 0 0 8px;
}
.tips ul {
  padding-left: 18px;
  margin: 0 0 8px;
}
.tips pre {
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 12px;
  background: var(--el-fill-color-light);
  padding: 6px 8px;
  border-radius: 4px;
}
.block {
  margin: 12px 0;
}
.ml {
  margin-left: 12px;
}
</style>
