<template>
  <div class="login-container">
    <el-card class="login-card">
      <template #header>
        <div class="card-header">
          <h1>SIEMBox</h1>
          <p>Security Information and Event Management</p>
        </div>
      </template>

      <el-form ref="loginFormRef" :model="loginForm" :rules="rules" @submit.prevent="handleLogin">
        <el-alert
          v-if="notice"
          class="login-notice"
          :type="notice.type"
          :title="notice.message"
          :closable="false"
          show-icon
          role="alert"
        />

        <el-form-item prop="username">
          <el-input
            v-model="loginForm.username"
            placeholder="Username"
            size="large"
            prefix-icon="User"
            autocomplete="username"
            :disabled="mfaRequired"
          />
        </el-form-item>

        <el-form-item prop="password">
          <el-input
            v-model="loginForm.password"
            type="password"
            placeholder="Password"
            size="large"
            prefix-icon="Lock"
            autocomplete="current-password"
            :disabled="mfaRequired"
            @keyup.enter="handleLogin"
            show-password
          />
        </el-form-item>

        <el-form-item v-if="mfaRequired">
          <el-input
            v-model="loginForm.code"
            placeholder="6-digit code or recovery code"
            size="large"
            prefix-icon="Key"
            autocomplete="one-time-code"
            autofocus
            @keyup.enter="handleLogin"
          />
          <div class="mfa-hint">
            Enter the code from your authenticator app.
            <el-link type="primary" underline="never" @click="useAnotherAccount">Use another account</el-link>
          </div>
        </el-form-item>

        <el-form-item>
          <el-button
            type="primary"
            size="large"
            :loading="loading"
            :disabled="secondsLeft > 0"
            @click="handleLogin"
            style="width: 100%"
          >
            {{ buttonLabel }}
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch, onBeforeUnmount } from 'vue';
import { ElMessage, type FormInstance, type FormRules } from 'element-plus';
import { useAuthStore } from '@/stores/auth';
import { errorBody, errorStatus, formatCountdown, isUnavailable, retryAfterSeconds } from '@/utils/signIn';

const authStore = useAuthStore();
const loginFormRef = ref<FormInstance>();
const loading = ref(false);

const mfaRequired = ref(false);

const loginForm = reactive({
  username: '',
  password: '',
  code: '',
});

const rules: FormRules = {
  username: [{ required: true, message: 'Please enter username', trigger: 'blur' }],
  password: [{ required: true, message: 'Please enter password', trigger: 'blur' }],
};

// Errors and the MFA prompt show here, above the form, instead of as toasts.
const notice = ref<{ type: 'error' | 'warning' | 'info'; message: string } | null>(null);

// A sign-in pause (429): the button counts down and stays disabled until it ends.
const pausedUntil = ref<number | null>(null);
const now = ref(Date.now());
let ticker: ReturnType<typeof setInterval> | null = null;

const secondsLeft = computed(() =>
  pausedUntil.value === null ? 0 : Math.max(0, Math.ceil((pausedUntil.value - now.value) / 1000))
);

const buttonLabel = computed(() => {
  if (secondsLeft.value > 0) return `Try again in ${formatCountdown(secondsLeft.value)}`;
  return mfaRequired.value ? 'Verify' : 'Login';
});

function stopTicker() {
  if (ticker) clearInterval(ticker);
  ticker = null;
}

function startPause(seconds: number) {
  pausedUntil.value = Date.now() + seconds * 1000;
  now.value = Date.now();
  stopTicker();
  ticker = setInterval(() => {
    now.value = Date.now();
    if (secondsLeft.value === 0) {
      stopTicker();
      pausedUntil.value = null;
      if (notice.value?.type === 'warning') notice.value = { type: 'info', message: 'You can try again now.' };
    }
  }, 1000);
}

function clearPause() {
  stopTicker();
  pausedUntil.value = null;
}

// Another account may well not be paused: let the server decide again.
watch(
  () => loginForm.username,
  () => {
    if (pausedUntil.value !== null) {
      clearPause();
      notice.value = null;
    }
  }
);

onBeforeUnmount(stopTicker);

function useAnotherAccount() {
  mfaRequired.value = false;
  loginForm.code = '';
  loginForm.password = '';
  notice.value = null;
  clearPause();
}

function showError(error: unknown) {
  const status = errorStatus(error);
  const body = errorBody(error);

  if (status === 429) {
    // Paused. A pause of MFA codes keeps the code step on screen.
    if (body.mfaRequired || body.reason === 'mfa') mfaRequired.value = true;
    if (mfaRequired.value) loginForm.code = '';
    notice.value = { type: 'warning', message: body.message || 'Too many attempts. Please wait before trying again.' };
    startPause(retryAfterSeconds(error));
    return;
  }
  if (status === 401 && body.mfaRequired) {
    // The password was right; ask for (or again for) the second factor.
    const firstPrompt = !mfaRequired.value;
    mfaRequired.value = true;
    loginForm.code = '';
    notice.value = firstPrompt
      ? { type: 'info', message: 'Enter the code from your authenticator app to continue.' }
      : { type: 'error', message: body.message || 'Invalid MFA code' };
    return;
  }
  if (isUnavailable(error)) {
    notice.value = { type: 'error', message: 'Sign-in is temporarily unavailable. Please try again shortly.' };
    return;
  }
  // 400, 401, 403 (a disabled account): the server's own words.
  notice.value = { type: 'error', message: body.message || 'Login failed' };
}

const handleLogin = async () => {
  // Enter pressed twice, or Enter and a click: one request at a time.
  if (loading.value || secondsLeft.value > 0 || !loginFormRef.value) return;
  loading.value = true;
  try {
    const valid = await loginFormRef.value.validate().catch(() => false);
    if (!valid) return;
    if (mfaRequired.value && !loginForm.code.trim()) {
      notice.value = { type: 'error', message: 'Enter your MFA code.' };
      return;
    }
    await authStore.login(
      loginForm.username,
      loginForm.password,
      mfaRequired.value ? loginForm.code.trim() : undefined
    );
    notice.value = null;
    clearPause();
    ElMessage.success('Login successful');
  } catch (error) {
    showError(error);
  } finally {
    loading.value = false;
  }
};
</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.login-card {
  width: 400px;
}

.card-header {
  text-align: center;
}

.card-header h1 {
  margin: 0 0 10px 0;
  color: var(--siembox-text-color);
  font-size: 28px;
}

.card-header p {
  margin: 0;
  color: var(--siembox-text-tertiary);
  font-size: 14px;
}

.login-notice {
  margin-bottom: 18px;
}

.mfa-hint {
  width: 100%;
  margin-top: 6px;
  color: var(--siembox-text-tertiary);
  font-size: 12px;
  display: flex;
  justify-content: space-between;
  gap: 8px;
}
</style>
