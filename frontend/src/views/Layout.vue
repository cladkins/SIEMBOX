<template>
  <el-container class="layout-container">
    <el-aside :width="isCollapsed ? '64px' : '220px'" class="sidebar" :class="{ 'mobile-open': mobileMenuOpen }">
      <div class="logo">
        <h2 v-if="!isCollapsed">SIEMBox</h2>
        <el-icon v-else :size="24"><Monitor /></el-icon>
      </div>
      <el-menu
        :default-active="activeMenu"
        :router="true"
        :collapse="isCollapsed"
        :background-color="themeStore.isDark ? '#1d1d1d' : '#304156'"
        text-color="#bfcbd9"
        active-text-color="#409EFF"
        :default-openeds="['siem']"
        class="sidebar-menu"
      >
        <el-menu-item index="/">
          <el-icon><Monitor /></el-icon>
          <span>Dashboard</span>
        </el-menu-item>

        <el-menu-item index="/threat-intel">
          <el-icon><Aim /></el-icon>
          <span>Threat Intel</span>
        </el-menu-item>

        <el-menu-item index="/ai-analyst" v-if="canAnalyst">
          <el-icon><ChatDotRound /></el-icon>
          <span>AI Analyst</span>
        </el-menu-item>

        <el-sub-menu index="siem">
          <template #title>
            <el-icon><Grid /></el-icon>
            <span>SIEM</span>
          </template>
          <el-menu-item index="/alerts">
            <el-icon><Bell /></el-icon>
            <span>Alerts</span>
          </el-menu-item>
          <el-menu-item index="/logs">
            <el-icon><Document /></el-icon>
            <span>Logs</span>
          </el-menu-item>
          <el-menu-item index="/parsers">
            <el-icon><Setting /></el-icon>
            <span>Parsers</span>
          </el-menu-item>
          <el-menu-item index="/rules">
            <el-icon><Files /></el-icon>
            <span>Detection Rules</span>
          </el-menu-item>
          <el-menu-item index="/shippers">
            <el-icon><Upload /></el-icon>
            <span>Log Shippers</span>
          </el-menu-item>
        </el-sub-menu>

        <el-sub-menu index="assets" v-if="authStore.user?.role === 'admin' || authStore.user?.role === 'analyst' || authStore.user?.role === 'operator'">
          <template #title>
            <el-icon><Monitor /></el-icon>
            <span>Assets & Vulnerabilities</span>
          </template>
          <el-menu-item index="/asset-inventory">
            <el-icon><Box /></el-icon>
            <span>Assets</span>
          </el-menu-item>
          <el-menu-item index="/vulnerability-scanning" v-if="authStore.user?.role === 'admin' || authStore.user?.role === 'operator'">
            <el-icon><Search /></el-icon>
            <span>Vulnerability Scanning</span>
          </el-menu-item>
          <el-menu-item index="/vulnerability-management" v-if="authStore.user?.role === 'admin' || authStore.user?.role === 'operator'">
            <el-icon><Warning /></el-icon>
            <span>Vulnerability Management</span>
          </el-menu-item>
          <el-menu-item index="/container-scanning" v-if="authStore.user?.role === 'admin' || authStore.user?.role === 'operator'">
            <el-icon><Ship /></el-icon>
            <span>Container Scanning</span>
          </el-menu-item>
          <el-menu-item index="/scheduled-scans" v-if="authStore.user?.role === 'admin' || authStore.user?.role === 'operator'">
            <el-icon><Timer /></el-icon>
            <span>Scheduled Scans</span>
          </el-menu-item>
          <el-menu-item index="/endpoints" v-if="authStore.user?.role === 'admin'">
            <el-icon><Cpu /></el-icon>
            <span>Endpoints</span>
          </el-menu-item>
          <el-menu-item index="/templates">
            <el-icon><Collection /></el-icon>
            <span>Templates</span>
          </el-menu-item>
        </el-sub-menu>

        <el-menu-item index="/users" v-if="authStore.user?.role === 'admin'">
          <el-icon><User /></el-icon>
          <span>Users</span>
        </el-menu-item>
        <el-menu-item index="/admin" v-if="authStore.user?.role === 'admin'">
          <el-icon><DataAnalysis /></el-icon>
          <span>Admin Dashboard</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Tools /></el-icon>
          <span>Settings</span>
        </el-menu-item>
      </el-menu>
      <div class="collapse-btn" @click="toggleCollapse">
        <el-icon :size="20">
          <Fold v-if="!isCollapsed" />
          <Expand v-else />
        </el-icon>
      </div>
    </el-aside>

    <div
      v-if="isMobile && mobileMenuOpen"
      class="sidebar-backdrop"
      @click="mobileMenuOpen = false"
    />

    <el-container>
      <el-header>
        <div class="header-content">
          <div class="header-left">
            <el-button
              v-if="isMobile"
              class="mobile-menu-btn"
              text
              @click="mobileMenuOpen = !mobileMenuOpen"
            >
              <el-icon :size="22"><Fold /></el-icon>
            </el-button>
            <span class="page-title">{{ pageTitle }}</span>
          </div>
          <div class="user-actions">
            <el-button
              v-if="canAnalyst"
              class="ask-ai-btn"
              size="small"
              @click="openAnalyst"
            >
              <el-icon><ChatDotRound /></el-icon>
              <span class="ask-ai-label">Ask AI</span>
            </el-button>
            <el-switch
              v-model="themeStore.isDark"
              :active-action-icon="Moon"
              :inactive-action-icon="Sunny"
              class="theme-switch"
            />
            <span class="username">{{ authStore.user?.username || 'User' }}</span>
            <el-button @click="handleLogout" type="danger" size="small">Logout</el-button>
          </div>
        </div>
      </el-header>

      <el-main>
        <router-view />
      </el-main>

      <el-footer height="28px" class="app-footer">
        <a href="https://db-ip.com" target="_blank" rel="noopener">IP Geolocation by DB-IP</a>
      </el-footer>
    </el-container>

    <!-- Global AI Analyst drawer — shares the conversation with the dedicated page. -->
    <el-drawer
      v-model="chatStore.drawerOpen"
      class="analyst-drawer"
      title="AI Security Analyst"
      :size="drawerSize"
      @closed="chatStore.clearContext()"
    >
      <div class="analyst-drawer-body" style="height: calc(100vh - 110px)">
        <AnalystChat />
      </div>
    </el-drawer>
  </el-container>
</template>

<script setup lang="ts">
import { computed, ref, watch, onMounted, onUnmounted } from 'vue';
import { useRoute } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { useThemeStore } from '@/stores/theme';
import { useChatStore } from '@/stores/chat';
import AnalystChat from '@/components/AnalystChat.vue';
import { Monitor, Bell, Document, Setting, Files, Tools, Upload, User, Grid, Box, Search, Warning, Collection, DataAnalysis, Fold, Expand, Moon, Sunny, Ship, Timer, Aim, Cpu, ChatDotRound } from '@element-plus/icons-vue';

const route = useRoute();
const authStore = useAuthStore();
const themeStore = useThemeStore();
const chatStore = useChatStore();

const isCollapsed = ref(false);

const toggleCollapse = () => {
  isCollapsed.value = !isCollapsed.value;
};

// Mobile responsive sidebar (slide-in overlay below 768px)
const isMobile = ref(false);
const mobileMenuOpen = ref(false);

const updateIsMobile = () => {
  isMobile.value = window.innerWidth <= 768;
  if (!isMobile.value) {
    mobileMenuOpen.value = false;
  }
};

onMounted(() => {
  updateIsMobile();
  window.addEventListener('resize', updateIsMobile);
});

onUnmounted(() => {
  window.removeEventListener('resize', updateIsMobile);
});

// Close the mobile menu after navigating.
watch(() => route.path, () => {
  mobileMenuOpen.value = false;
});

const activeMenu = computed(() => route.path);

const pageTitle = computed(() => {
  const titles: Record<string, string> = {
    '/': 'Dashboard',
    '/ai-analyst': 'AI Analyst',
    '/alerts': 'Alerts',
    '/logs': 'Logs',
    '/parsers': 'Parsers',
    '/rules': 'Detection Rules',
    '/shippers': 'Log Shippers',
    '/asset-inventory': 'Asset Inventory',
    '/vulnerability-scanning': 'Vulnerability Scanning',
    '/vulnerability-management': 'Vulnerability Management',
    '/templates': 'Nuclei Templates',
    '/users': 'User Management',
    '/admin': 'Admin Dashboard',
    '/settings': 'Settings',
  };
  return titles[route.path] || 'SIEMBox';
});

const canAnalyst = computed(() =>
  ['admin', 'analyst', 'operator'].includes(authStore.user?.role || '')
);
const drawerSize = computed(() => (isMobile.value ? '100%' : '460px'));
function openAnalyst() {
  chatStore.clearContext();
  chatStore.drawerOpen = true;
}

const handleLogout = () => {
  authStore.logout();
};
</script>

<style scoped>
.layout-container {
  height: 100vh;
}

.sidebar {
  background-color: var(--siembox-sidebar-bg);
  color: #fff;
  display: flex;
  flex-direction: column;
  transition: width 0.3s ease, background-color 0.3s;
  overflow: hidden;
}

.sidebar-menu {
  flex: 1;
  border-right: none;
}

.sidebar-menu:not(.el-menu--collapse) {
  width: 220px;
}

.logo {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 60px;
  background-color: var(--siembox-sidebar-header);
  flex-shrink: 0;
  transition: background-color 0.3s;
}

.logo h2 {
  color: #fff;
  font-size: 20px;
  margin: 0;
  white-space: nowrap;
}

.logo .el-icon {
  color: #fff;
}

.collapse-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 48px;
  cursor: pointer;
  background-color: var(--siembox-sidebar-header);
  color: #bfcbd9;
  transition: background-color 0.2s;
  flex-shrink: 0;
}

.collapse-btn:hover {
  background-color: #1f2d3d;
  color: #409EFF;
}

.el-header {
  background-color: var(--siembox-header-bg);
  display: flex;
  align-items: center;
  box-shadow: var(--siembox-shadow);
  padding: 0 20px;
  transition: background-color 0.3s;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

.page-title {
  font-size: 18px;
  font-weight: 500;
  color: var(--siembox-text-color);
}

.user-actions {
  display: flex;
  align-items: center;
  gap: 15px;
}

.theme-switch {
  --el-switch-on-color: #409EFF;
  --el-switch-off-color: #dcdfe6;
}

.username {
  color: var(--siembox-text-secondary);
}

.el-main {
  background-color: var(--siembox-bg-color);
  padding: 20px;
  transition: background-color 0.3s;
}

/* DB-IP GeoIP attribution (CC BY 4.0 requires a link on pages using the data). */
.app-footer {
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: var(--siembox-bg-color);
  padding: 0 20px;
  font-size: 11px;
  color: var(--siembox-text-secondary);
  border-top: 1px solid var(--el-border-color-lighter);
}

.app-footer a {
  color: var(--siembox-text-secondary);
  text-decoration: none;
}

.app-footer a:hover {
  color: #409eff;
  text-decoration: underline;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.mobile-menu-btn {
  color: var(--siembox-text-color);
  padding: 4px;
}

.sidebar-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  z-index: 2000;
}

/* Mobile: the sidebar becomes a slide-in overlay toggled from the header. */
@media (max-width: 768px) {
  .sidebar {
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    width: 220px !important;
    z-index: 2001;
    transform: translateX(-100%);
    transition: transform 0.3s ease;
    box-shadow: 2px 0 8px rgba(0, 0, 0, 0.3);
  }

  .sidebar.mobile-open {
    transform: translateX(0);
  }

  .sidebar-menu:not(.el-menu--collapse) {
    width: 220px;
  }

  .collapse-btn {
    display: none;
  }

  .el-header {
    padding: 0 12px;
  }

  .el-main {
    padding: 12px;
  }

  .page-title {
    font-size: 16px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .username {
    display: none;
  }

  .user-actions {
    gap: 10px;
  }
}
</style>
