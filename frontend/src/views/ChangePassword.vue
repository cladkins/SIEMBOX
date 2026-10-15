<template>
  <div class="change-password-container">
    <el-card class="change-password-card">
      <template #header>
        <div class="card-header">
          <h1>SIEMBox</h1>
          <p>Choose a new password</p>
        </div>
      </template>

      <el-alert type="warning" :closable="false" show-icon class="reason-notice">
        <template #title>
          <span class="reason-text">
            <template v-if="reason === 'initial'">
              This is the first sign-in to <strong>{{ username }}</strong>, with the password the account was
              created with. Choose your own password to continue.
            </template>
            <template v-else-if="reason === 'default'">
              <strong>{{ username }}</strong> still uses SIEMBox's default password, which anyone can look up.
              Choose a new password to continue.
            </template>
            <template v-else-if="reason === 'admin'">
              An administrator set a temporary password for <strong>{{ username }}</strong>. Choose your own
              password to continue.
            </template>
            <template v-else-if="reason === 'cli'">
              The password of <strong>{{ username }}</strong> was reset from the server's command line. Choose
              your own password to continue.
            </template>
            <template v-else>
              <strong>{{ username }}</strong> must choose a new password to continue.
            </template>
          </span>
        </template>
      </el-alert>
      <p class="afterwards">
        Nothing else works until you do. Afterwards you're signed out everywhere: sign in again with the new
        password, then turn on two-factor authentication under Settings → Account.
      </p>

      <el-alert
        v-if="error"
        :type="secondsLeft > 0 ? 'warning' : 'error'"
        :title="error"
        :closable="false"
        show-icon
        role="alert"
        class="inline-error"
      />

      <el-form label-position="top" @submit.prevent="changePassword">
        <!-- For password managers: the account the new password belongs to. -->
        <input class="username-for-managers" type="text" name="username" autocomplete="username" :value="username" readonly tabindex="-1" aria-hidden="true" />

        <el-form-item label="Current password">
          <el-input
            v-model="form.current"
            type="password"
            show-password
            autocomplete="current-password"
            size="large"
            autofocus
          />
          <div class="field-hint">The one you just signed in with</div>
        </el-form-item>
        <el-form-item label="New password">
          <el-input
            v-model="form.next"
            type="password"
            show-password
            autocomplete="new-password"
            size="large"
            placeholder="At least 8 characters"
          />
        </el-form-item>
        <el-form-item label="Confirm new password">
          <el-input
            v-model="form.confirm"
            type="password"
            show-password
            autocomplete="new-password"
            size="large"
          />
          <el-text v-if="form.confirm && form.confirm !== form.next" type="danger" size="small" class="mismatch">
            The new passwords don't match.
          </el-text>
        </el-form-item>
        <el-form-item>
          <el-button
            type="primary"
            size="large"
            native-type="submit"
            :loading="saving"
            :disabled="!ready || secondsLeft > 0"
            style="width: 100%"
          >
            {{ secondsLeft > 0 ? `Try again in ${formatCountdown(secondsLeft)}` : 'Change password' }}
          </el-button>
        </el-form-item>
      </el-form>

      <div class="footer">
        <el-link type="primary" underline="never" :disabled="signingOut" @click="signOut">Sign out</el-link>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue';
import { ElMessage } from 'element-plus';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import { errorBody, errorStatus, formatCountdown, isUnavailable, retryAfterSeconds } from '@/utils/signIn';

/**
 * Where an account that must change its password lands (router guard, and the
 * API client on a 403 PASSWORD_CHANGE_REQUIRED). It changes the password
 * through PUT /api/auth/me/password, which still asks for the current one and
 * signs the account out everywhere; then the user signs in again.
 */
const authStore = useAuthStore();

const username = computed(() => authStore.user?.username ?? '');
const reason = computed(() => authStore.passwordChangeReason);

const form = reactive({ current: '', next: '', confirm: '' });
const saving = ref(false);
const signingOut = ref(false);
const error = ref('');
const ready = computed(() => !!form.current && form.next.length >= 8 && form.next === form.confirm);

// A pause of wrong current passwords (429): the button counts down.
const pausedUntil = ref<number | null>(null);
const now = ref(Date.now());
let ticker: ReturnType<typeof setInterval> | null = null;
const secondsLeft = computed(() =>
  pausedUntil.value === null ? 0 : Math.max(0, Math.ceil((pausedUntil.value - now.value) / 1000))
);

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
      error.value = '';
    }
  }, 1000);
}

onBeforeUnmount(stopTicker);

// The reason may have changed since this browser signed in (or the tab was
// opened from an old copy of the profile): read it again. A 401 here means
// the session ended, and the API client already went back to /login.
onMounted(async () => {
  try {
    const { data } = await api.getProfile();
    authStore.setProfile(data);
  } catch {
    // Keep what the store has.
  }
});

async function changePassword() {
  if (!ready.value || saving.value || secondsLeft.value > 0) return;
  saving.value = true;
  error.value = '';
  try {
    await api.changeOwnPassword(form.current, form.next);
    form.current = '';
    form.next = '';
    form.confirm = '';
    // The server has signed this session out already, with every other one.
    ElMessage.success('Password changed. Sign in with your new password.');
    authStore.logout();
  } catch (failure) {
    if (errorStatus(failure) === 429) {
      error.value = errorBody(failure).message || 'Too many wrong current passwords. Please wait before trying again.';
      startPause(retryAfterSeconds(failure));
    } else if (isUnavailable(failure)) {
      error.value = 'Could not change the password right now. Please try again shortly.';
    } else {
      // 400: the current password is wrong, or the new one is too short,
      // unchanged or the default. The server's own words.
      error.value = errorBody(failure).message || 'Could not change the password.';
    }
  } finally {
    saving.value = false;
  }
}

async function signOut() {
  signingOut.value = true;
  try {
    await authStore.signOut();
  } finally {
    signingOut.value = false;
  }
}
</script>

<style scoped>
.change-password-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  padding: 16px;
  box-sizing: border-box;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.change-password-card {
  width: 440px;
  max-width: 100%;
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
  color: var(--siembox-text-color);
  font-size: 16px;
  font-weight: 600;
}

.reason-notice {
  margin-bottom: 12px;
}

.reason-text {
  font-weight: normal;
  line-height: 1.5;
}

.afterwards {
  margin: 0 0 16px 0;
  color: var(--siembox-text-tertiary);
  font-size: 13px;
  line-height: 1.5;
}

.inline-error {
  margin-bottom: 16px;
}

.username-for-managers {
  position: absolute;
  width: 1px;
  height: 1px;
  opacity: 0;
  pointer-events: none;
}

.field-hint {
  width: 100%;
  margin-top: 4px;
  color: var(--siembox-text-tertiary);
  font-size: 12px;
  line-height: 1.4;
}

.mismatch {
  margin-top: 4px;
}

.footer {
  text-align: center;
}
</style>
