<template>
  <el-tag :type="badgeType" :effect="effect" :size="size" class="severity-badge">
    <el-icon v-if="showIcon" class="badge-icon">
      <component :is="iconComponent" />
    </el-icon>
    <span>{{ formattedSeverity }}</span>
  </el-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { WarningFilled, Warning, InfoFilled, CircleCheck } from '@element-plus/icons-vue';

interface Props {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  showIcon?: boolean;
  effect?: 'dark' | 'light' | 'plain';
  size?: 'large' | 'default' | 'small';
}

const props = withDefaults(defineProps<Props>(), {
  showIcon: true,
  effect: 'dark',
  size: 'default'
});

const badgeType = computed(() => {
  const types: Record<string, any> = {
    critical: 'danger',
    high: 'warning',
    medium: '',
    low: 'success',
    info: 'info'
  };
  return types[props.severity] || 'info';
});

const iconComponent = computed(() => {
  const icons: Record<string, any> = {
    critical: WarningFilled,
    high: Warning,
    medium: InfoFilled,
    low: CircleCheck,
    info: InfoFilled
  };
  return icons[props.severity] || InfoFilled;
});

const formattedSeverity = computed(() => {
  return props.severity.toUpperCase();
});
</script>

<style scoped>
.severity-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-weight: 600;
}

.badge-icon {
  font-size: 14px;
}
</style>
