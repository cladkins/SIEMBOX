<template>
  <el-card>
    <template #header>
      <span>
        Password check
        <HelpTip text="An on-demand Pwned Passwords lookup. Nothing is stored or watched: each check is a one-off, and passwords can't be added as monitored identities." />
      </span>
    </template>

    <p class="card-intro">
      Find out whether a password has appeared in a known data breach. This is a
      <strong>k-anonymity</strong> check: the SIEMBox server hashes the password (SHA-1) and sends only the
      first 5 characters of that hash to Pwned Passwords, then looks for a match in the list that comes
      back. The password itself never leaves the server and is never stored or logged; this field is
      cleared as soon as the check is sent.
    </p>

    <el-form inline @submit.prevent="check">
      <el-form-item>
        <el-input
          v-model="password"
          type="password"
          show-password
          autocomplete="new-password"
          maxlength="1024"
          placeholder="Password to check"
          aria-label="Password to check"
          :disabled="checking"
          style="width: 300px"
          @input="result = null"
        />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" native-type="submit" :loading="checking" :disabled="!password">Check</el-button>
      </el-form-item>
    </el-form>

    <el-alert
      v-if="result"
      :type="result.pwned ? 'error' : 'success'"
      :title="result.pwned ? `Found ${result.count.toLocaleString()} ${result.count === 1 ? 'time' : 'times'} in known breaches` : 'Not found in known breaches'"
      :description="
        result.pwned
          ? 'Don’t use this password anywhere. If it is in use, change it everywhere it was used and turn on MFA.'
          : 'This password isn’t in the Pwned Passwords corpus. That doesn’t make it strong: use a long, unique password per account.'
      "
      show-icon
      :closable="false"
      class="result"
    />

    <el-text size="small" type="info">Limited to 30 checks per 15 minutes from one address.</el-text>
    <HibpAttribution />
  </el-card>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { ElMessage } from 'element-plus';
import HelpTip from '@/components/HelpTip.vue';
import HibpAttribution from '@/components/HibpAttribution.vue';
import exposureService, { type PasswordCheckResult } from '@/services/exposureService';
import { apiErrorMessage } from '@/utils/exposure';

// The password lives only in this ref while it is typed, and in one local
// variable until the request is on its way: never a URL, router state, store,
// browser storage or log. The field is cleared as the request goes out.
const password = ref('');
const checking = ref(false);
const result = ref<PasswordCheckResult | null>(null);

async function check() {
  let candidate: string | null = password.value;
  password.value = '';
  if (!candidate) return;
  checking.value = true;
  result.value = null;
  try {
    const pending = exposureService.checkPassword(candidate);
    candidate = null; // the request holds the only copy now
    result.value = await pending;
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, 'The password check failed'));
  } finally {
    checking.value = false;
  }
}
</script>

<style scoped>
.card-intro {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--el-text-color-regular);
}

.result {
  margin-bottom: 10px;
}
</style>
