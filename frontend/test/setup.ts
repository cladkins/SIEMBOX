/**
 * Global Test Setup for Frontend Tests
 */

import { expect, afterEach, beforeAll, afterAll } from 'vitest';
import { config } from '@vue/test-utils';
import ElementPlus from 'element-plus';
import { server } from './mocks/server';

// Register Element Plus globally for all tests
config.global.plugins = [ElementPlus];

// Stub Element Plus components to avoid rendering issues in tests
config.global.stubs = {
  // Stub complex components that cause issues in happy-dom
  'el-date-picker': true,
  'el-time-picker': true,
  'el-upload': true,
};

// Extend expect with custom matchers if needed
// import * as matchers from '@testing-library/jest-dom/matchers';
// expect.extend(matchers);

// Setup MSW server
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' });
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});

// Mock window.matchMedia for Element Plus responsive components
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

// Mock localStorage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};
global.localStorage = localStorageMock as any;

// Mock sessionStorage
const sessionStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};
global.sessionStorage = sessionStorageMock as any;
