# Testing Recommendations for SIEMBox Frontend

## Executive Summary

Based on current best practices for Vue 3 + TypeScript testing in 2025-2026, this document provides actionable recommendations for implementing a comprehensive test suite in the SIEMBox frontend.

## Recommended Technology Stack

### Core Testing Framework

**Vitest** (instead of Jest)

**Why Vitest:**
- Native Vite integration (same config, faster startup)
- 5-10x faster than Jest for Vue 3 applications
- Native ESM and TypeScript support
- Jest-compatible API (minimal migration effort)
- Better watch mode with HMR

**Installation:**

```bash
cd frontend
npm install -D vitest @vue/test-utils @vitest/ui
npm install -D happy-dom  # Faster than jsdom for most cases
```

### Testing Libraries

| Library | Purpose | Version |
|---------|---------|---------|
| `vitest` | Test runner | Latest (v4.x) |
| `@vue/test-utils` | Component testing | Latest (for Vue 3) |
| `@pinia/testing` | Store testing | Latest |
| `happy-dom` | DOM environment | Latest |
| `msw` | API mocking | Latest (v2.x) |
| `@vitest/ui` | Test UI dashboard | Latest |

## Configuration

### Minimal `vitest.config.ts`

```typescript
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import path from 'path'

export default defineConfig({
  plugins: [vue()],
  test: {
    globals: true,
    environment: 'happy-dom',
    setupFiles: ['./test/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.{js,ts,vue}'],
      exclude: [
        '**/*.test.{js,ts}',
        '**/*.spec.{js,ts}',
        '**/node_modules/**'
      ]
    }
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  }
})
```

### Test Setup File (`test/setup.ts`)

```typescript
import { expect, afterEach, vi } from 'vitest'
import { cleanup } from '@vue/test-utils'
import * as matchers from '@testing-library/jest-dom/matchers'

expect.extend(matchers)

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

// Mock window.matchMedia for Element Plus responsive components
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})
```

## Testing Patterns for SIEMBox

### 1. API Service Testing (Recommended Approach)

Use **Mock Service Worker (MSW)** for API mocking instead of manual mocks.

**Setup MSW:**

```typescript
// src/mocks/handlers.ts
import { http, HttpResponse } from 'msw'

export const handlers = [
  // Logs API
  http.get('/api/logs', ({ request }) => {
    const url = new URL(request.url)
    const page = url.searchParams.get('page') || '1'

    return HttpResponse.json({
      logs: [
        { id: 1, message: 'Test log', timestamp: '2025-01-09T10:00:00Z' }
      ],
      total: 1,
      page: parseInt(page)
    })
  }),

  // Authentication
  http.post('/api/login', async ({ request }) => {
    const body = await request.json()

    if (body.username === 'admin' && body.password === 'changeme') {
      return HttpResponse.json({
        token: 'mock-jwt-token',
        user: { id: 1, username: 'admin', role: 'Admin' }
      })
    }

    return HttpResponse.json(
      { error: 'Invalid credentials' },
      { status: 401 }
    )
  }),

  // Parsers
  http.get('/api/parsers', () => {
    return HttpResponse.json([
      { id: 1, name: 'NGINX', pattern: '.*', enabled: true }
    ])
  })
]
```

```typescript
// src/mocks/server.ts
import { setupServer } from 'msw/node'
import { handlers } from './handlers'

export const server = setupServer(...handlers)
```

```typescript
// test/setup.ts (add to existing file)
import { beforeAll, afterEach, afterAll } from 'vitest'
import { server } from '../src/mocks/server'

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => server.resetHandlers())
afterAll(() => server.close())
```

### 2. Component Testing with Element Plus

**Example: Testing Log Viewer Component**

```typescript
// components/LogViewer.spec.ts
import { mount, flushPromises } from '@vue/test-utils'
import { describe, it, expect } from 'vitest'
import LogViewer from '@/components/LogViewer.vue'
import { ElTable, ElPagination } from 'element-plus'

describe('LogViewer.vue', () => {
  it('renders log table', () => {
    const wrapper = mount(LogViewer, {
      global: {
        components: { ElTable, ElPagination }
      }
    })

    expect(wrapper.find('[data-test="log-table"]').exists()).toBe(true)
  })

  it('fetches and displays logs', async () => {
    const wrapper = mount(LogViewer)

    // Wait for API call to complete
    await flushPromises()

    expect(wrapper.text()).toContain('Test log')
  })

  it('handles pagination', async () => {
    const wrapper = mount(LogViewer)
    await flushPromises()

    const pagination = wrapper.findComponent(ElPagination)
    await pagination.vm.$emit('current-change', 2)

    // Verify API was called with page=2
    // (MSW will log the request)
  })
})
```

### 3. Store Testing

**Example: Testing Auth Store**

```typescript
// stores/auth.spec.ts
import { setActivePinia, createPinia } from 'pinia'
import { describe, it, expect, beforeEach } from 'vitest'
import { useAuthStore } from '@/stores/auth'

describe('Auth Store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('initializes with no user', () => {
    const store = useAuthStore()
    expect(store.user).toBeNull()
    expect(store.isAuthenticated).toBe(false)
  })

  it('logs in successfully', async () => {
    const store = useAuthStore()

    await store.login('admin', 'changeme')

    expect(store.isAuthenticated).toBe(true)
    expect(store.user?.username).toBe('admin')
    expect(store.token).toBe('mock-jwt-token')
  })

  it('handles login failure', async () => {
    const store = useAuthStore()

    await expect(
      store.login('admin', 'wrong')
    ).rejects.toThrow('Invalid credentials')

    expect(store.isAuthenticated).toBe(false)
  })

  it('logs out user', () => {
    const store = useAuthStore()
    store.user = { id: 1, username: 'admin', role: 'Admin' }
    store.token = 'token'

    store.logout()

    expect(store.user).toBeNull()
    expect(store.token).toBeNull()
    expect(store.isAuthenticated).toBe(false)
  })
})
```

### 4. Composable Testing

**Example: Testing usePagination Composable**

```typescript
// composables/usePagination.spec.ts
import { describe, it, expect } from 'vitest'
import { usePagination } from '@/composables/usePagination'

describe('usePagination', () => {
  it('initializes with default values', () => {
    const { currentPage, pageSize, total } = usePagination()

    expect(currentPage.value).toBe(1)
    expect(pageSize.value).toBe(20)
    expect(total.value).toBe(0)
  })

  it('calculates total pages', () => {
    const { pageSize, total, totalPages } = usePagination()

    total.value = 100
    pageSize.value = 20

    expect(totalPages.value).toBe(5)
  })

  it('changes page', () => {
    const { currentPage, changePage } = usePagination()

    changePage(3)

    expect(currentPage.value).toBe(3)
  })

  it('prevents invalid page numbers', () => {
    const { currentPage, changePage, totalPages, total } = usePagination()

    total.value = 100
    totalPages.value = 5

    changePage(-1)
    expect(currentPage.value).toBe(1)

    changePage(10)
    expect(currentPage.value).toBe(5)
  })
})
```

### 5. Router Testing

**Example: Testing Route Guards**

```typescript
// router/guards.spec.ts
import { describe, it, expect, vi } from 'vitest'
import { createRouter, createMemoryHistory } from 'vue-router'
import { setActivePinia, createPinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { authGuard } from '@/router/guards'

describe('Auth Guard', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('allows authenticated users to protected routes', async () => {
    const store = useAuthStore()
    store.isAuthenticated = true

    const next = vi.fn()
    const to = { meta: { requiresAuth: true } }

    authGuard(to, null, next)

    expect(next).toHaveBeenCalledWith()
  })

  it('redirects unauthenticated users to login', async () => {
    const store = useAuthStore()
    store.isAuthenticated = false

    const next = vi.fn()
    const to = { meta: { requiresAuth: true } }

    authGuard(to, null, next)

    expect(next).toHaveBeenCalledWith('/login')
  })
})
```

## What to Test (Priority Order)

### High Priority

1. **Critical User Flows:**
   - User authentication (login/logout)
   - Log viewing and filtering
   - Alert acknowledgment
   - Parser and rule creation

2. **API Integration:**
   - All API service methods
   - Error handling
   - Loading states

3. **Store Logic:**
   - Authentication store
   - Log store
   - Alert store

### Medium Priority

4. **Complex Components:**
   - LogViewer
   - ParserEditor
   - RuleBuilder
   - AlertDashboard

5. **Form Validation:**
   - Login form
   - Parser creation form
   - Rule creation form

### Lower Priority

6. **UI Components:**
   - Navigation
   - Sidebar
   - Modals
   - Tooltips

7. **Utility Functions:**
   - Date formatters
   - Data transformers

## What NOT to Test

- Element Plus component internals
- Vue Router navigation internals
- CSS and styling
- Third-party library behavior
- Trivial getters/setters with no logic

## Test File Organization

```
frontend/
├── src/
│   ├── components/
│   │   ├── LogViewer.vue
│   │   └── LogViewer.spec.ts      # Component tests
│   ├── stores/
│   │   ├── auth.ts
│   │   └── auth.spec.ts           # Store tests
│   ├── composables/
│   │   ├── usePagination.ts
│   │   └── usePagination.spec.ts  # Composable tests
│   └── mocks/
│       ├── handlers.ts            # MSW handlers
│       └── server.ts              # MSW server setup
├── test/
│   └── setup.ts                   # Global test setup
└── vitest.config.ts               # Vitest config
```

## Running Tests

```bash
# Run all tests
npm run test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Run tests with UI
npm run test:ui

# Run specific test file
npm run test LogViewer.spec.ts
```

**Add to `package.json`:**

```json
{
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest",
    "test:coverage": "vitest run --coverage",
    "test:ui": "vitest --ui"
  }
}
```

## Coverage Goals

| Area | Target Coverage |
|------|----------------|
| Stores | 90%+ |
| API Services | 85%+ |
| Critical Components | 80%+ |
| Composables | 85%+ |
| Utility Functions | 90%+ |
| Overall | 75%+ |

## Testing Best Practices

### DO:

1. **Test user behavior**, not implementation details
2. **Use data-test attributes** for element selection
3. **Mock API calls with MSW** for realistic tests
4. **Test async operations** with `flushPromises()`
5. **Keep tests focused** and independent
6. **Use descriptive test names** that explain intent
7. **Test error states** and edge cases

### DON'T:

1. Test internal component state directly
2. Rely on CSS classes for assertions
3. Mock everything (use real logic where possible)
4. Write brittle tests that break on refactors
5. Test third-party library internals
6. Ignore failing tests (fix or remove)

## Migration Path

### Phase 1: Setup (Week 1)

1. Install Vitest and dependencies
2. Create `vitest.config.ts`
3. Create `test/setup.ts`
4. Set up MSW with basic handlers
5. Add npm scripts

### Phase 2: Critical Tests (Week 2-3)

1. Test authentication store
2. Test API services (login, logs, alerts)
3. Test critical components (LogViewer, AlertDashboard)
4. Set up CI/CD integration

### Phase 3: Comprehensive Coverage (Week 4+)

1. Test remaining stores
2. Test complex components
3. Test composables
4. Test utility functions
5. Achieve 75% coverage

## CI/CD Integration

**GitHub Actions Example:**

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: cd frontend && npm ci

      - name: Run tests
        run: cd frontend && npm run test:coverage

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./frontend/coverage/lcov.info
```

## Resources

- **Full Testing Guide**: `docs/guides/VITEST_VUE_TESTING_GUIDE.md`
- Vitest Docs: https://vitest.dev
- Vue Test Utils: https://test-utils.vuejs.org
- MSW: https://mswjs.io
- Testing Library: https://testing-library.com/docs/vue-testing-library/intro

## Next Steps

1. Review and approve these recommendations
2. Set up basic Vitest configuration
3. Write first test (start with auth store)
4. Establish coverage baseline
5. Plan sprint for comprehensive test implementation

---

**Document Version**: 1.0
**Last Updated**: 2025-01-09
**Author**: Claude Code (Research Assistant)
