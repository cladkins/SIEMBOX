<template>
  <el-container class="layout-container">
    <el-aside width="200px">
      <div class="logo">
        <h2>SIEMBox</h2>
      </div>
      <el-menu
        :default-active="activeMenu"
        :router="true"
        background-color="#304156"
        text-color="#bfcbd9"
        active-text-color="#409EFF"
        :default-openeds="['siem']"
      >
        <el-menu-item index="/">
          <el-icon><Monitor /></el-icon>
          <span>Dashboard</span>
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
    </el-aside>

    <el-container>
      <el-header>
        <div class="header-content">
          <span class="page-title">{{ pageTitle }}</span>
          <div class="user-actions">
            <span class="username">{{ authStore.user?.username || 'User' }}</span>
            <el-button @click="handleLogout" type="danger" size="small">Logout</el-button>
          </div>
        </div>
      </el-header>

      <el-main>
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useRoute } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { Monitor, Bell, Document, Setting, Files, Tools, Upload, User, Grid, Box, Search, Warning, Collection, DataAnalysis } from '@element-plus/icons-vue';

const route = useRoute();
const authStore = useAuthStore();

const activeMenu = computed(() => route.path);

const pageTitle = computed(() => {
  const titles: Record<string, string> = {
    '/': 'Dashboard',
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

const handleLogout = () => {
  authStore.logout();
};
</script>

<style scoped>
.layout-container {
  height: 100vh;
}

.el-aside {
  background-color: #304156;
  color: #fff;
}

.logo {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 60px;
  background-color: #263445;
}

.logo h2 {
  color: #fff;
  font-size: 20px;
  margin: 0;
}

.el-header {
  background-color: #fff;
  display: flex;
  align-items: center;
  box-shadow: 0 1px 4px rgba(0, 21, 41, 0.08);
  padding: 0 20px;
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
}

.user-actions {
  display: flex;
  align-items: center;
  gap: 15px;
}

.username {
  color: #606266;
}

.el-main {
  background-color: #f5f7fa;
  padding: 20px;
}
</style>
