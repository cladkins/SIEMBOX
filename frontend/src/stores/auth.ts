import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { api } from '@/services/api';
import router from '@/router';

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string | null>(localStorage.getItem('token'));
  const userJson = localStorage.getItem('user');
  const user = ref<any>(userJson ? JSON.parse(userJson) : null);

  const isAuthenticated = computed(() => !!token.value);

  const login = async (username: string, password: string) => {
    try {
      const response = await api.login(username, password);
      token.value = response.data.token;
      user.value = response.data.user;
      localStorage.setItem('token', token.value!);
      localStorage.setItem('user', JSON.stringify(user.value));
      router.push('/');
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    token.value = null;
    user.value = null;
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    router.push('/login');
  };

  return {
    token,
    user,
    isAuthenticated,
    login,
    logout,
  };
});
