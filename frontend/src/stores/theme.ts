import { defineStore } from 'pinia';
import { ref, watch } from 'vue';

export const useThemeStore = defineStore('theme', () => {
  // Check localStorage or system preference for initial value
  const getInitialTheme = (): boolean => {
    const stored = localStorage.getItem('siembox-dark-mode');
    if (stored !== null) {
      return stored === 'true';
    }
    // Fall back to system preference
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  };

  const isDark = ref(getInitialTheme());

  // Apply theme to document
  const applyTheme = (dark: boolean) => {
    if (dark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  };

  // Initialize theme on store creation
  applyTheme(isDark.value);

  // Watch for changes and persist
  watch(isDark, (newValue) => {
    localStorage.setItem('siembox-dark-mode', String(newValue));
    applyTheme(newValue);
  });

  const toggleTheme = () => {
    isDark.value = !isDark.value;
  };

  const setTheme = (dark: boolean) => {
    isDark.value = dark;
  };

  return {
    isDark,
    toggleTheme,
    setTheme,
  };
});
