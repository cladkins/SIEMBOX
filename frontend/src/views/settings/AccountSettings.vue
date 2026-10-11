<template>
  <div class="account-settings">
    <el-card>
      <template #header>
        <span>Security — Two-Factor Authentication (MFA) <HelpTip text="Adds a time-based one-time code (TOTP) from an authenticator app to your login. Applies to your own account; each user enables MFA for themselves." /></span>
      </template>

      <div v-loading="mfaLoading">
        <template v-if="mfaEnabled">
          <el-alert
            type="success"
            :closable="false"
            show-icon
            title="MFA is enabled on your account"
            style="margin-bottom: 12px"
          />
          <p class="mfa-note">
            You'll be asked for a 6-digit code from your authenticator app (or a recovery code) at login.
          </p>
          <el-button type="danger" plain @click="openMfaDisable">Disable MFA</el-button>
        </template>

        <template v-else>
          <p class="mfa-note">
            Protect your account with a time-based one-time code (TOTP) from an app like Google
            Authenticator, Authy, or 1Password. Optional, per-account, and recommended for admins.
          </p>
          <el-button type="primary" @click="startMfaSetup" :loading="mfaSetupLoading">
            <el-icon><Key /></el-icon> Enable MFA
          </el-button>
        </template>
      </div>
    </el-card>

    <!-- MFA enrollment dialog -->
    <el-dialog v-model="mfaSetupVisible" title="Enable two-factor authentication" width="520px">
      <ol class="mfa-steps">
        <li>
          Scan this in your authenticator app, or enter the key manually:
          <div class="mfa-qr">
            <qrcode-vue v-if="mfaOtpauthUrl" :value="mfaOtpauthUrl" :size="180" level="M" render-as="svg" />
          </div>
          <div class="mfa-secret-box">
            <div class="mfa-secret">{{ mfaSecret }}</div>
            <el-button size="small" @click="copySecret">Copy key</el-button>
          </div>
          <div class="mfa-uri">{{ mfaOtpauthUrl }}</div>
        </li>
        <li>
          Enter the 6-digit code it shows:
          <el-input
            v-model="mfaCode"
            placeholder="123456"
            style="max-width: 200px; margin-top: 6px"
            @keyup.enter="confirmMfaEnable"
          />
        </li>
      </ol>
      <template #footer>
        <el-button @click="mfaSetupVisible = false">Cancel</el-button>
        <el-button type="primary" :loading="mfaEnabling" :disabled="!mfaCode.trim()" @click="confirmMfaEnable">
          Verify &amp; enable
        </el-button>
      </template>
    </el-dialog>

    <!-- Recovery codes (shown once) -->
    <el-dialog v-model="mfaRecoveryVisible" title="Save your recovery codes" width="520px" :close-on-click-modal="false">
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        title="These are shown only once"
        description="Store them somewhere safe. Each code works once if you lose your authenticator."
        style="margin-bottom: 12px"
      />
      <div class="recovery-grid">
        <code v-for="(c, i) in mfaRecoveryCodes" :key="i">{{ c }}</code>
      </div>
      <template #footer>
        <el-button @click="copyRecovery">Copy all</el-button>
        <el-button type="primary" @click="mfaRecoveryVisible = false">I've saved them</el-button>
      </template>
    </el-dialog>

    <!-- Disable MFA dialog -->
    <el-dialog v-model="mfaDisableVisible" title="Disable MFA" width="460px">
      <p class="mfa-note">Enter a current code (or a recovery code) to turn MFA off.</p>
      <el-input v-model="mfaDisableCode" placeholder="6-digit or recovery code" @keyup.enter="confirmMfaDisable" />
      <template #footer>
        <el-button @click="mfaDisableVisible = false">Cancel</el-button>
        <el-button type="danger" :loading="mfaDisabling" :disabled="!mfaDisableCode.trim()" @click="confirmMfaDisable">
          Disable
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { api } from '@/services/api';
import { ElMessage } from 'element-plus';
import { Key } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import QrcodeVue from 'qrcode.vue';

// --- MFA (two-factor) ------------------------------------------------------
const mfaLoading = ref(false);
const mfaEnabled = ref(false);
const mfaSetupLoading = ref(false);
const mfaSetupVisible = ref(false);
const mfaSecret = ref('');
const mfaOtpauthUrl = ref('');
const mfaCode = ref('');
const mfaEnabling = ref(false);
const mfaRecoveryVisible = ref(false);
const mfaRecoveryCodes = ref<string[]>([]);
const mfaDisableVisible = ref(false);
const mfaDisableCode = ref('');
const mfaDisabling = ref(false);

async function loadMfaStatus() {
  mfaLoading.value = true;
  try {
    const { data } = await api.getProfile();
    mfaEnabled.value = !!data.mfa_enabled;
  } catch {
    /* non-fatal */
  } finally {
    mfaLoading.value = false;
  }
}

async function startMfaSetup() {
  mfaSetupLoading.value = true;
  try {
    const { data } = await api.mfaSetup();
    mfaSecret.value = data.secret;
    mfaOtpauthUrl.value = data.otpauthUrl;
    mfaCode.value = '';
    mfaSetupVisible.value = true;
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Could not start MFA setup');
  } finally {
    mfaSetupLoading.value = false;
  }
}

async function confirmMfaEnable() {
  if (!mfaCode.value.trim()) return;
  mfaEnabling.value = true;
  try {
    const { data } = await api.mfaEnable(mfaCode.value.trim());
    mfaRecoveryCodes.value = data.recoveryCodes || [];
    mfaSetupVisible.value = false;
    mfaRecoveryVisible.value = true;
    mfaEnabled.value = true;
    ElMessage.success('MFA enabled');
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Invalid code');
  } finally {
    mfaEnabling.value = false;
  }
}

function openMfaDisable() {
  mfaDisableCode.value = '';
  mfaDisableVisible.value = true;
}

async function confirmMfaDisable() {
  if (!mfaDisableCode.value.trim()) return;
  mfaDisabling.value = true;
  try {
    await api.mfaDisable(mfaDisableCode.value.trim());
    mfaEnabled.value = false;
    mfaDisableVisible.value = false;
    ElMessage.success('MFA disabled');
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Invalid code');
  } finally {
    mfaDisabling.value = false;
  }
}

async function copySecret() {
  try {
    await navigator.clipboard.writeText(mfaSecret.value);
    ElMessage.success('Key copied');
  } catch {
    ElMessage.warning('Copy failed');
  }
}

async function copyRecovery() {
  try {
    await navigator.clipboard.writeText(mfaRecoveryCodes.value.join('\n'));
    ElMessage.success('Recovery codes copied');
  } catch {
    ElMessage.warning('Copy failed');
  }
}

onMounted(() => {
  loadMfaStatus();
});
</script>

<style scoped>
.mfa-note {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin: 0 0 12px;
}
.mfa-steps {
  margin: 0;
  padding-left: 18px;
}
.mfa-steps li {
  margin-bottom: 14px;
}
.mfa-qr {
  display: flex;
  justify-content: center;
  margin: 12px 0;
}
/* White quiet-zone so the code scans even in dark mode. */
.mfa-qr :deep(svg) {
  background: #fff;
  padding: 10px;
  border-radius: 6px;
}
.mfa-secret-box {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 6px 0;
}
.mfa-secret {
  font-family: var(--el-font-family-mono, monospace);
  font-size: 16px;
  letter-spacing: 2px;
  background: var(--el-fill-color-light);
  padding: 6px 10px;
  border-radius: 4px;
  word-break: break-all;
}
.mfa-uri {
  font-size: 11px;
  color: var(--el-text-color-secondary);
  word-break: break-all;
}
.recovery-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
}
.recovery-grid code {
  font-family: var(--el-font-family-mono, monospace);
  font-size: 14px;
  background: var(--el-fill-color-light);
  padding: 6px 10px;
  border-radius: 4px;
  text-align: center;
}
</style>
