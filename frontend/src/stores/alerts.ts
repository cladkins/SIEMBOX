import { defineStore } from 'pinia';
import { ref } from 'vue';
import { api } from '@/services/api';

export interface Alert {
  id: number;
  rule_id: number;
  parsed_log_id: number | null;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string | null;
  matched_data: Record<string, any>;
  status: 'new' | 'investigating' | 'closed' | 'false_positive';
  assigned_to: number | null;
  created_at: string;
  updated_at: string;
}

export interface AlertStatistics {
  total: number;
  new_count: number;
  investigating_count: number;
  closed_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export const useAlertsStore = defineStore('alerts', () => {
  const alerts = ref<Alert[]>([]);
  const statistics = ref<AlertStatistics | null>(null);
  const loading = ref(false);
  const total = ref(0);

  const fetchAlerts = async (params?: any) => {
    loading.value = true;
    try {
      const response = await api.getAlerts(params);
      alerts.value = response.data.alerts;
      total.value = response.data.total;
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
      throw error;
    } finally {
      loading.value = false;
    }
  };

  const fetchStatistics = async () => {
    try {
      const response = await api.getAlertStatistics();
      statistics.value = response.data;
    } catch (error) {
      console.error('Failed to fetch alert statistics:', error);
      throw error;
    }
  };

  const updateAlert = async (id: number, data: any) => {
    try {
      const response = await api.updateAlert(id, data);
      // Update alert in local state
      const index = alerts.value.findIndex((a) => a.id === id);
      if (index !== -1) {
        alerts.value[index] = response.data;
      }
      return response.data;
    } catch (error) {
      console.error('Failed to update alert:', error);
      throw error;
    }
  };

  const deleteAlert = async (id: number) => {
    try {
      await api.deleteAlert(id);
      // Remove from local state
      alerts.value = alerts.value.filter((a) => a.id !== id);
      total.value--;
    } catch (error) {
      console.error('Failed to delete alert:', error);
      throw error;
    }
  };

  return {
    alerts,
    statistics,
    loading,
    total,
    fetchAlerts,
    fetchStatistics,
    updateAlert,
    deleteAlert,
  };
});
