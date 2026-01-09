# Vitest and Vue.js Component Testing Guide (2025-2026)

## Table of Contents

1. [Vitest Configuration](#vitest-configuration)
2. [Vue Component Testing](#vue-component-testing)
3. [Testing Patterns](#testing-patterns)
4. [Best Practices](#best-practices)
5. [API Mocking with MSW](#api-mocking-with-msw)
6. [Example Test Suites](#example-test-suites)

---

## 1. Vitest Configuration

### 1.1 Basic Vitest Setup for Vue 3 + TypeScript

Vitest is a next-generation testing framework powered by Vite, offering blazing-fast performance, native ESM support, and Jest compatibility. It's the recommended testing solution for Vue 3 applications in 2025-2026.

**Install Dependencies:**

```bash
npm install -D vitest @vue/test-utils @vitest/ui
npm install -D happy-dom  # or jsdom
```

**Basic `vitest.config.ts`:**

```typescript
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  test: {
    // Test environment (happy-dom is faster, jsdom has better compatibility)
    environment: 'happy-dom',

    // Enable global test APIs (describe, it, expect, etc.)
    globals: true,

    // Test file patterns
    include: ['**/*.{test,spec}.{js,ts,jsx,tsx}'],
    exclude: ['**/node_modules/**', '**/dist/**'],

    // Setup files to run before each test file
    setupFiles: ['./test/setup.ts'],

    // Mock behavior
    clearMocks: true,      // Clear mock calls between tests
    restoreMocks: true,    // Restore original implementation after tests

    // Test execution
    testTimeout: 5000,
    hookTimeout: 10000,

    // Coverage configuration (see section 1.3)
    coverage: {
      provider: 'v8',
      enabled: false,
      reporter: ['text', 'json', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*.{js,ts,vue}'],
      exclude: [
        '**/*.test.{js,ts}',
        '**/*.spec.{js,ts}',
        '**/node_modules/**',
        '**/dist/**'
      ]
    }
  },
  resolve: {
    alias: {
      '@': '/src'
    }
  }
})
```

### 1.2 Vite Integration Advantages

Vitest leverages Vite's transformation pipeline, providing several advantages over Jest:

- **Instant Watch Mode**: Vite's HMR provides near-instantaneous test reruns
- **Native ESM**: No transpilation needed for modern JavaScript features
- **Shared Configuration**: Uses the same `vite.config.ts` for both dev and test
- **TypeScript Support**: Out-of-the-box TypeScript support without additional configuration
- **Component Transforms**: Automatically handles `.vue` file transformations

**Unified Configuration Example:**

```typescript
/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],

  // Vite dev/build config
  server: {
    port: 3000
  },

  // Vitest config
  test: {
    globals: true,
    environment: 'happy-dom',
    setupFiles: ['./test/setup.ts']
  }
})
```

### 1.3 Coverage Configuration: v8 vs Istanbul

**V8 Coverage (Recommended for 2025-2026):**

V8 is the default and recommended coverage provider. It uses native V8 coverage APIs for faster, more accurate results.

```typescript
export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',              // Default, uses native V8 coverage
      reporter: ['text', 'html', 'lcov', 'json'],
      reportsDirectory: './coverage',

      // Coverage thresholds
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80
      },

      // Files to include/exclude
      include: ['src/**/*.{js,ts,vue}'],
      exclude: [
        '**/*.test.{js,ts}',
        '**/*.spec.{js,ts}',
        '**/node_modules/**',
        '**/dist/**',
        '**/*.d.ts',
        '**/types/**'
      ]
    }
  }
})
```

**Istanbul Coverage:**

Istanbul provides instrumented coverage and may be more accurate for certain edge cases, but is slower.

```bash
npm install -D @vitest/coverage-istanbul
```

```typescript
export default defineConfig({
  test: {
    coverage: {
      provider: 'istanbul',
      reporter: ['text', 'html', 'lcov'],
      // Same configuration options as v8
    }
  }
})
```

**Key Differences:**

| Feature | V8 | Istanbul |
|---------|----|---------:|
| Speed | Faster | Slower |
| Accuracy | Very good | Excellent |
| Edge Cases | Misses some | More complete |
| Setup | Zero config | Requires plugin |

**Recommendation**: Use V8 for most projects. Only switch to Istanbul if you encounter specific coverage accuracy issues.

### 1.4 Test Setup File

Create `test/setup.ts` to configure global test behavior:

```typescript
import { expect, afterEach, vi } from 'vitest'
import { cleanup } from '@vue/test-utils'
import * as matchers from '@testing-library/jest-dom/matchers'

// Extend Vitest's expect with jest-dom matchers
expect.extend(matchers)

// Cleanup after each test
afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

// Mock window.matchMedia (for responsive components)
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

// Mock IntersectionObserver (for lazy loading components)
global.IntersectionObserver = class IntersectionObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  takeRecords() { return [] }
  unobserve() {}
}
```

---

## 2. Vue Component Testing

### 2.1 Vue Test Utils for Vue 3

Vue Test Utils is the official testing library for Vue.js 3. It provides utilities for mounting components and interacting with them.

**Core API:**

```typescript
import { mount, shallowMount, flushPromises } from '@vue/test-utils'

// mount() - Renders component with full child tree
const wrapper = mount(Component, options)

// shallowMount() - Renders component with stubbed children
const wrapper = shallowMount(Component, options)

// flushPromises() - Waits for all pending promises
await flushPromises()
```

**Mounting Options:**

```typescript
const wrapper = mount(Component, {
  // Component props
  props: {
    msg: 'Hello',
    count: 0
  },

  // Component slots
  slots: {
    default: 'Default slot content',
    header: '<h1>Header</h1>'
  },

  // Global configuration
  global: {
    // Plugins (Pinia, Router, etc.)
    plugins: [pinia, router],

    // Component stubs
    stubs: {
      'RouterLink': RouterLinkStub,
      'Teleport': true  // Stub Teleport
    },

    // Mock global properties
    mocks: {
      $t: (key) => key  // Mock i18n
    },

    // Provide/inject
    provide: {
      'my-key': 'some-data'
    },

    // Directives
    directives: {
      'focus': FocusDirective
    }
  },

  // Attach to DOM (for testing refs)
  attachTo: document.body
})
```

### 2.2 Testing Composition API Components

**Component Example:**

```vue
<script setup lang="ts">
import { ref, computed } from 'vue'

const count = ref(0)
const doubleCount = computed(() => count.value * 2)

const increment = () => {
  count.value++
}
</script>

<template>
  <div>
    <p>Count: {{ count }}</p>
    <p>Double: {{ doubleCount }}</p>
    <button @click="increment">Increment</button>
  </div>
</template>
```

**Test:**

```typescript
import { mount } from '@vue/test-utils'
import { describe, it, expect } from 'vitest'
import Counter from '@/components/Counter.vue'

describe('Counter.vue', () => {
  it('renders initial count', () => {
    const wrapper = mount(Counter)

    expect(wrapper.text()).toContain('Count: 0')
    expect(wrapper.text()).toContain('Double: 0')
  })

  it('increments count on button click', async () => {
    const wrapper = mount(Counter)
    const button = wrapper.find('button')

    await button.trigger('click')

    expect(wrapper.text()).toContain('Count: 1')
    expect(wrapper.text()).toContain('Double: 2')
  })

  it('increments multiple times', async () => {
    const wrapper = mount(Counter)
    const button = wrapper.find('button')

    await button.trigger('click')
    await button.trigger('click')
    await button.trigger('click')

    expect(wrapper.text()).toContain('Count: 3')
    expect(wrapper.text()).toContain('Double: 6')
  })
})
```

### 2.3 Testing Pinia Stores

**Install Testing Library:**

```bash
npm install -D @pinia/testing
```

**Store Example:**

```typescript
// stores/counter.ts
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

export const useCounterStore = defineStore('counter', () => {
  const count = ref(0)
  const doubleCount = computed(() => count.value * 2)

  function increment() {
    count.value++
  }

  async function fetchCount() {
    const response = await fetch('/api/count')
    const data = await response.json()
    count.value = data.count
  }

  return { count, doubleCount, increment, fetchCount }
})
```

**Testing Store Directly:**

```typescript
import { setActivePinia, createPinia } from 'pinia'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useCounterStore } from '@/stores/counter'

describe('Counter Store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('initializes with default state', () => {
    const store = useCounterStore()

    expect(store.count).toBe(0)
    expect(store.doubleCount).toBe(0)
  })

  it('increments count', () => {
    const store = useCounterStore()

    store.increment()

    expect(store.count).toBe(1)
    expect(store.doubleCount).toBe(2)
  })

  it('fetches count from API', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      json: async () => ({ count: 42 })
    })

    const store = useCounterStore()
    await store.fetchCount()

    expect(store.count).toBe(42)
    expect(global.fetch).toHaveBeenCalledWith('/api/count')
  })
})
```

**Testing Component with Pinia Store:**

```typescript
import { mount } from '@vue/test-utils'
import { createTestingPinia } from '@pinia/testing'
import { describe, it, expect, vi } from 'vitest'
import MyComponent from '@/components/MyComponent.vue'
import { useCounterStore } from '@/stores/counter'

describe('MyComponent with Store', () => {
  it('uses store state', () => {
    const wrapper = mount(MyComponent, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,  // Use Vitest spies
            initialState: {
              counter: {
                count: 10,
                name: 'Test Counter'
              }
            }
          })
        ]
      }
    })

    const store = useCounterStore()
    expect(store.count).toBe(10)
    expect(wrapper.text()).toContain('10')
  })

  it('calls store actions', async () => {
    const wrapper = mount(MyComponent, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            stubActions: true  // Actions are stubbed
          })
        ]
      }
    })

    const store = useCounterStore()
    const button = wrapper.find('[data-test="increment-btn"]')

    await button.trigger('click')

    expect(store.increment).toHaveBeenCalledTimes(1)
  })

  it('executes real store actions', async () => {
    const wrapper = mount(MyComponent, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            stubActions: false  // Actions execute real code
          })
        ]
      }
    })

    const store = useCounterStore()
    store.count = 5

    const button = wrapper.find('[data-test="increment-btn"]')
    await button.trigger('click')

    expect(store.count).toBe(6)
  })
})
```

### 2.4 Snapshot Testing

Snapshot testing captures the rendered output of a component and compares it to a saved snapshot file.

**File Snapshots:**

```typescript
import { mount } from '@vue/test-utils'
import { describe, it, expect } from 'vitest'
import Button from '@/components/Button.vue'

describe('Button.vue', () => {
  it('matches snapshot', () => {
    const wrapper = mount(Button, {
      props: { type: 'primary' },
      slots: { default: 'Click me' }
    })

    expect(wrapper.html()).toMatchSnapshot()
  })
})
```

This creates a snapshot file: `__snapshots__/Button.spec.ts.snap`

**Inline Snapshots:**

```typescript
describe('Button.vue', () => {
  it('matches inline snapshot', () => {
    const wrapper = mount(Button, {
      props: { type: 'primary' },
      slots: { default: 'Click me' }
    })

    expect(wrapper.html()).toMatchInlineSnapshot(`
      "<button class=\\"btn btn-primary\\">Click me</button>"
    `)
  })
})
```

**Update Snapshots:**

```bash
# Update all snapshots
npm run test -- -u

# Update specific test file
npm run test Button.spec.ts -- -u
```

**Best Practices for Snapshots:**

- Use snapshots for **stable UI components** (buttons, cards, badges)
- **Avoid** snapshots for dynamic content (timestamps, IDs)
- Review snapshot diffs carefully during PR reviews
- Keep snapshots small and focused
- Prefer inline snapshots for small components

---

## 3. Testing Patterns

### 3.1 Unit Testing Composables

Composables are reusable Composition API logic. They should be tested independently.

**Simple Composable:**

```typescript
// composables/useCounter.ts
import { ref } from 'vue'

export function useCounter(initialValue = 0) {
  const count = ref(initialValue)

  function increment() {
    count.value++
  }

  function decrement() {
    count.value--
  }

  function reset() {
    count.value = initialValue
  }

  return { count, increment, decrement, reset }
}
```

**Test:**

```typescript
import { describe, it, expect } from 'vitest'
import { useCounter } from '@/composables/useCounter'

describe('useCounter', () => {
  it('initializes with default value', () => {
    const { count } = useCounter()
    expect(count.value).toBe(0)
  })

  it('initializes with custom value', () => {
    const { count } = useCounter(10)
    expect(count.value).toBe(10)
  })

  it('increments count', () => {
    const { count, increment } = useCounter()
    increment()
    expect(count.value).toBe(1)
  })

  it('resets to initial value', () => {
    const { count, increment, reset } = useCounter(5)
    increment()
    increment()
    expect(count.value).toBe(7)
    reset()
    expect(count.value).toBe(5)
  })
})
```

**Composable with Lifecycle Hooks:**

When testing composables with lifecycle hooks, you need to mount a test component.

```typescript
// composables/useUser.ts
import { ref, onMounted } from 'vue'
import axios from 'axios'

export function useUser(userId: number) {
  const user = ref(null)
  const loading = ref(false)
  const error = ref(null)

  async function fetchUser(id: number) {
    loading.value = true
    try {
      const response = await axios.get(`/api/users/${id}`)
      user.value = response.data
    } catch (e) {
      error.value = e
    } finally {
      loading.value = false
    }
  }

  onMounted(() => fetchUser(userId))

  return { user, loading, error, fetchUser }
}
```

**Test with Helper Component:**

```typescript
import { defineComponent } from 'vue'
import { mount, flushPromises } from '@vue/test-utils'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import axios from 'axios'
import { useUser } from '@/composables/useUser'

vi.mock('axios')

describe('useUser', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('fetches user on mount', async () => {
    const mockUser = { id: 1, name: 'John Doe' }
    vi.mocked(axios.get).mockResolvedValue({ data: mockUser })

    const TestComponent = defineComponent({
      props: {
        userId: {
          type: Number,
          required: true
        }
      },
      setup(props) {
        return useUser(props.userId)
      },
      template: '<div>{{ user?.name }}</div>'
    })

    const wrapper = mount(TestComponent, {
      props: { userId: 1 }
    })

    expect(wrapper.vm.loading).toBe(true)
    expect(wrapper.vm.user).toBeNull()

    await flushPromises()

    expect(wrapper.vm.loading).toBe(false)
    expect(wrapper.vm.user).toEqual(mockUser)
    expect(wrapper.text()).toContain('John Doe')
  })

  it('handles fetch errors', async () => {
    const mockError = new Error('Network error')
    vi.mocked(axios.get).mockRejectedValue(mockError)

    const TestComponent = defineComponent({
      props: { userId: Number },
      setup(props) {
        return useUser(props.userId!)
      },
      template: '<div v-if="error">Error: {{ error.message }}</div>'
    })

    const wrapper = mount(TestComponent, {
      props: { userId: 1 }
    })

    await flushPromises()

    expect(wrapper.vm.error).toEqual(mockError)
    expect(wrapper.text()).toContain('Network error')
  })
})
```

### 3.2 Component Integration Tests

Integration tests verify that multiple components work together correctly.

**Parent-Child Component Test:**

```typescript
import { mount } from '@vue/test-utils'
import { describe, it, expect } from 'vitest'
import TodoList from '@/components/TodoList.vue'
import TodoItem from '@/components/TodoItem.vue'

describe('TodoList Integration', () => {
  it('renders todo items', () => {
    const todos = [
      { id: 1, text: 'Buy milk', done: false },
      { id: 2, text: 'Walk dog', done: true }
    ]

    const wrapper = mount(TodoList, {
      props: { todos }
    })

    const items = wrapper.findAllComponents(TodoItem)
    expect(items).toHaveLength(2)
    expect(items[0].props('todo')).toEqual(todos[0])
  })

  it('emits delete event when child emits', async () => {
    const todos = [
      { id: 1, text: 'Buy milk', done: false }
    ]

    const wrapper = mount(TodoList, {
      props: { todos }
    })

    const item = wrapper.findComponent(TodoItem)
    await item.vm.$emit('delete', 1)

    expect(wrapper.emitted('delete')).toBeTruthy()
    expect(wrapper.emitted('delete')?.[0]).toEqual([1])
  })
})
```

### 3.3 Testing Element Plus UI Components

Element Plus components can be tested like any Vue component, but you need to handle their internal state and events.

**Testing Element Plus Button:**

```typescript
import { mount } from '@vue/test-utils'
import { describe, it, expect } from 'vitest'
import { ElButton } from 'element-plus'
import MyComponent from '@/components/MyComponent.vue'

describe('MyComponent with Element Plus', () => {
  it('renders ElButton', () => {
    const wrapper = mount(MyComponent, {
      global: {
        components: { ElButton }
      }
    })

    const button = wrapper.findComponent(ElButton)
    expect(button.exists()).toBe(true)
    expect(button.text()).toBe('Submit')
  })

  it('emits event on button click', async () => {
    const wrapper = mount(MyComponent)
    const button = wrapper.findComponent(ElButton)

    await button.trigger('click')

    expect(wrapper.emitted('submit')).toBeTruthy()
  })
})
```

**Testing Element Plus Form:**

```typescript
import { mount, flushPromises } from '@vue/test-utils'
import { describe, it, expect, beforeEach } from 'vitest'
import { ElForm, ElFormItem, ElInput } from 'element-plus'
import LoginForm from '@/components/LoginForm.vue'

describe('LoginForm', () => {
  let wrapper

  beforeEach(() => {
    wrapper = mount(LoginForm, {
      global: {
        components: { ElForm, ElFormItem, ElInput }
      }
    })
  })

  it('validates required fields', async () => {
    const form = wrapper.findComponent(ElForm)
    const submitButton = wrapper.find('[data-test="submit-btn"]')

    await submitButton.trigger('click')
    await flushPromises()

    // Element Plus adds error classes
    expect(wrapper.html()).toContain('is-error')
  })

  it('submits valid form', async () => {
    const usernameInput = wrapper.find('input[name="username"]')
    const passwordInput = wrapper.find('input[name="password"]')

    await usernameInput.setValue('testuser')
    await passwordInput.setValue('password123')

    const submitButton = wrapper.find('[data-test="submit-btn"]')
    await submitButton.trigger('click')
    await flushPromises()

    expect(wrapper.emitted('submit')).toBeTruthy()
    expect(wrapper.emitted('submit')?.[0]).toEqual([{
      username: 'testuser',
      password: 'password123'
    }])
  })
})
```

**Stubbing Element Plus Components:**

For unit tests, you may want to stub Element Plus components to reduce complexity.

```typescript
const wrapper = mount(MyComponent, {
  global: {
    stubs: {
      ElButton: true,  // Render as <el-button-stub>
      ElDialog: {
        template: '<div><slot /></div>'  // Custom stub
      }
    }
  }
})
```

### 3.4 Testing Vue Router Navigation

**Mocking Vue Router (Options API):**

```typescript
import { mount } from '@vue/test-utils'
import { describe, it, expect, vi } from 'vitest'
import MyComponent from '@/components/MyComponent.vue'

describe('MyComponent with Router', () => {
  it('navigates on button click', async () => {
    const push = vi.fn()
    const mockRouter = {
      push
    }
    const mockRoute = {
      params: { id: '1' }
    }

    const wrapper = mount(MyComponent, {
      global: {
        mocks: {
          $router: mockRouter,
          $route: mockRoute
        }
      }
    })

    await wrapper.find('[data-test="edit-btn"]').trigger('click')

    expect(push).toHaveBeenCalledWith('/posts/1/edit')
  })
})
```

**Mocking Vue Router (Composition API):**

```typescript
import { useRouter, useRoute } from 'vue-router'
import { vi } from 'vitest'

vi.mock('vue-router', () => ({
  useRoute: vi.fn(),
  useRouter: vi.fn(() => ({
    push: () => {}
  }))
}))

describe('MyComponent with Composition API Router', () => {
  it('navigates on button click', async () => {
    const push = vi.fn()

    vi.mocked(useRoute).mockReturnValue({
      params: { id: '1' }
    } as any)

    vi.mocked(useRouter).mockReturnValue({
      push
    } as any)

    const wrapper = mount(MyComponent)
    await wrapper.find('[data-test="edit-btn"]').trigger('click')

    expect(push).toHaveBeenCalledWith('/posts/1/edit')
  })
})
```

**Using RouterLinkStub:**

```typescript
import { mount, RouterLinkStub } from '@vue/test-utils'

const wrapper = mount(Navigation, {
  global: {
    stubs: {
      RouterLink: RouterLinkStub
    }
  }
})

const links = wrapper.findAllComponents(RouterLinkStub)
expect(links[0].props('to')).toBe('/home')
```

---

## 4. Best Practices

### 4.1 What to Test vs What Not to Test

**✅ DO TEST:**

1. **User Interactions:**
   - Button clicks
   - Form inputs
   - Keyboard events
   - Mouse events

2. **Component Props:**
   - Required props
   - Optional props with defaults
   - Prop validation

3. **Component Events:**
   - Emitted events
   - Event payloads
   - Event handlers

4. **Computed Properties:**
   - Correct calculations
   - Reactivity to state changes

5. **Conditional Rendering:**
   - v-if/v-show logic
   - Dynamic classes/styles

6. **API Integration:**
   - Successful responses
   - Error handling
   - Loading states

7. **Store Integration:**
   - Store state updates
   - Action calls
   - Getter values

**❌ DON'T TEST:**

1. **Implementation Details:**
   - Internal component state (use public API instead)
   - Private methods
   - Exact class names (unless critical to functionality)

2. **Third-Party Library Internals:**
   - Vue.js reactivity system
   - Element Plus component internals
   - Router navigation internals

3. **Framework Behavior:**
   - Vue lifecycle hooks (test the outcome, not the hook itself)
   - Reactivity system

4. **Styles:**
   - CSS specifics (unless using visual regression testing)
   - Exact pixel values

### 4.2 Testing User Interactions

**Good Practice - Test User Behavior:**

```typescript
import { mount } from '@vue/test-utils'
import { describe, it, expect } from 'vitest'
import Counter from '@/components/Counter.vue'

describe('Counter', () => {
  it('increments counter when button is clicked', async () => {
    const wrapper = mount(Counter)

    // Find button by user-visible text
    const button = wrapper.find('button')

    // Simulate user interaction
    await button.trigger('click')
    await button.trigger('click')

    // Assert on visible output
    expect(wrapper.text()).toContain('Count: 2')
  })
})
```

**Bad Practice - Test Implementation:**

```typescript
// ❌ DON'T DO THIS
it('increments counter', async () => {
  const wrapper = mount(Counter)

  // Accessing internal state directly
  await wrapper.setData({ count: 2 })

  // Testing internal class names
  const paragraph = wrapper.find('.counter-text')
  expect(paragraph.text()).toBe('Count: 2')
})
```

**Testing Form Inputs:**

```typescript
describe('LoginForm', () => {
  it('updates username on input', async () => {
    const wrapper = mount(LoginForm)
    const input = wrapper.find('input[name="username"]')

    await input.setValue('john@example.com')

    expect(input.element.value).toBe('john@example.com')
  })

  it('submits form with entered data', async () => {
    const wrapper = mount(LoginForm)

    await wrapper.find('input[name="username"]').setValue('john@example.com')
    await wrapper.find('input[name="password"]').setValue('secret123')
    await wrapper.find('form').trigger('submit')

    expect(wrapper.emitted('submit')?.[0]).toEqual([{
      username: 'john@example.com',
      password: 'secret123'
    }])
  })
})
```

**Testing Keyboard Events:**

```typescript
describe('SearchInput', () => {
  it('searches on Enter key', async () => {
    const wrapper = mount(SearchInput)
    const input = wrapper.find('input')

    await input.setValue('test query')
    await input.trigger('keydown.enter')

    expect(wrapper.emitted('search')?.[0]).toEqual(['test query'])
  })

  it('clears on Escape key', async () => {
    const wrapper = mount(SearchInput)
    const input = wrapper.find('input')

    await input.setValue('test query')
    await input.trigger('keydown.escape')

    expect(input.element.value).toBe('')
  })
})
```

### 4.3 Async Component Testing

**Testing Async Components:**

```typescript
import { defineAsyncComponent, Suspense } from 'vue'
import { mount, flushPromises } from '@vue/test-utils'

const AsyncComponent = defineAsyncComponent(() =>
  Promise.resolve({
    template: '<div>Async Content</div>'
  })
)

const Parent = {
  components: { AsyncComponent },
  template: `
    <Suspense>
      <template #default>
        <AsyncComponent />
      </template>
      <template #fallback>
        <div>Loading...</div>
      </template>
    </Suspense>
  `
}

it('renders async component', async () => {
  const wrapper = mount(Parent)

  expect(wrapper.text()).toContain('Loading...')

  await flushPromises()

  expect(wrapper.text()).toContain('Async Content')
})
```

**Testing Async Data Fetching:**

```typescript
import { mount, flushPromises } from '@vue/test-utils'
import { describe, it, expect, vi } from 'vitest'
import UserProfile from '@/components/UserProfile.vue'

describe('UserProfile', () => {
  it('shows loading state', () => {
    const wrapper = mount(UserProfile, {
      props: { userId: 1 }
    })

    expect(wrapper.find('[data-test="loading"]').exists()).toBe(true)
  })

  it('displays user data after fetch', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      json: async () => ({ name: 'John Doe', email: 'john@example.com' })
    })

    const wrapper = mount(UserProfile, {
      props: { userId: 1 }
    })

    await flushPromises()

    expect(wrapper.find('[data-test="loading"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('John Doe')
    expect(wrapper.text()).toContain('john@example.com')
  })

  it('shows error message on fetch failure', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))

    const wrapper = mount(UserProfile, {
      props: { userId: 1 }
    })

    await flushPromises()

    expect(wrapper.find('[data-test="error"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('Failed to load user')
  })
})
```

### 4.4 Using Data Test Attributes

Use `data-test` attributes for reliable element selection:

```vue
<template>
  <div>
    <button data-test="submit-btn" @click="submit">Submit</button>
    <div data-test="error-message" v-if="error">{{ error }}</div>
  </div>
</template>
```

```typescript
// Test
const wrapper = mount(MyComponent)
const button = wrapper.find('[data-test="submit-btn"]')
const error = wrapper.find('[data-test="error-message"]')
```

**Benefits:**
- Resilient to CSS changes
- Clear intent in tests
- Easy to identify testable elements
- No impact on production (can be removed in build)

---

## 5. API Mocking with MSW

### 5.1 Mock Service Worker Setup

Mock Service Worker (MSW) is the industry standard for API mocking in 2025-2026. It intercepts requests at the network level.

**Install MSW:**

```bash
npm install -D msw@latest
```

**Create Request Handlers:**

```typescript
// src/mocks/handlers.ts
import { http, HttpResponse } from 'msw'

export const handlers = [
  // GET request
  http.get('https://api.example.com/user', () => {
    return HttpResponse.json({
      id: 'abc-123',
      firstName: 'John',
      lastName: 'Doe',
      email: 'john@example.com'
    })
  }),

  // POST request
  http.post('https://api.example.com/login', async ({ request }) => {
    const body = await request.json()

    if (body.username === 'admin' && body.password === 'password') {
      return HttpResponse.json({
        token: 'mock-jwt-token',
        user: { id: 1, username: 'admin' }
      })
    }

    return HttpResponse.json(
      { error: 'Invalid credentials' },
      { status: 401 }
    )
  }),

  // Error response
  http.get('https://api.example.com/error', () => {
    return HttpResponse.json(
      { message: 'Internal server error' },
      { status: 500 }
    )
  }),

  // Network error
  http.get('https://api.example.com/network-error', () => {
    return HttpResponse.error()
  })
]
```

**Setup MSW Server:**

```typescript
// src/mocks/server.ts
import { setupServer } from 'msw/node'
import { handlers } from './handlers'

export const server = setupServer(...handlers)
```

**Integrate with Vitest:**

```typescript
// test/setup.ts
import { beforeAll, afterEach, afterAll } from 'vitest'
import { server } from '../src/mocks/server'

// Start MSW server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))

// Reset handlers after each test
afterEach(() => server.resetHandlers())

// Close server after all tests
afterAll(() => server.close())
```

### 5.2 Using MSW in Tests

**Basic Test with MSW:**

```typescript
import { mount, flushPromises } from '@vue/test-utils'
import { describe, it, expect } from 'vitest'
import UserProfile from '@/components/UserProfile.vue'

describe('UserProfile with MSW', () => {
  it('fetches and displays user data', async () => {
    const wrapper = mount(UserProfile, {
      props: { userId: 'abc-123' }
    })

    await flushPromises()

    expect(wrapper.text()).toContain('John Doe')
    expect(wrapper.text()).toContain('john@example.com')
  })
})
```

**Override Handlers in Tests:**

```typescript
import { http, HttpResponse } from 'msw'
import { server } from '@/mocks/server'

describe('UserProfile error handling', () => {
  it('displays error message on fetch failure', async () => {
    // Override handler for this test only
    server.use(
      http.get('https://api.example.com/user', () => {
        return HttpResponse.json(
          { message: 'User not found' },
          { status: 404 }
        )
      })
    )

    const wrapper = mount(UserProfile, {
      props: { userId: 'abc-123' }
    })

    await flushPromises()

    expect(wrapper.find('[data-test="error"]').text()).toContain('User not found')
  })

  it('handles network errors', async () => {
    server.use(
      http.get('https://api.example.com/user', () => {
        return HttpResponse.error()
      })
    )

    const wrapper = mount(UserProfile, {
      props: { userId: 'abc-123' }
    })

    await flushPromises()

    expect(wrapper.find('[data-test="error"]').exists()).toBe(true)
  })
})
```

**Testing with Dynamic Responses:**

```typescript
import { http, HttpResponse, delay } from 'msw'
import { server } from '@/mocks/server'

describe('UserList with pagination', () => {
  it('loads more users on scroll', async () => {
    let page = 1

    server.use(
      http.get('https://api.example.com/users', ({ request }) => {
        const url = new URL(request.url)
        const pageParam = url.searchParams.get('page')
        page = parseInt(pageParam || '1')

        return HttpResponse.json({
          users: [
            { id: page * 10 + 1, name: `User ${page * 10 + 1}` },
            { id: page * 10 + 2, name: `User ${page * 10 + 2}` }
          ],
          hasMore: page < 3
        })
      })
    )

    const wrapper = mount(UserList)
    await flushPromises()

    expect(wrapper.text()).toContain('User 11')

    // Simulate scroll to load more
    await wrapper.find('[data-test="load-more"]').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('User 21')
  })

  it('shows loading indicator during fetch', async () => {
    server.use(
      http.get('https://api.example.com/users', async () => {
        await delay(100)  // Simulate slow network
        return HttpResponse.json({ users: [] })
      })
    )

    const wrapper = mount(UserList)

    expect(wrapper.find('[data-test="loading"]').exists()).toBe(true)

    await flushPromises()

    expect(wrapper.find('[data-test="loading"]').exists()).toBe(false)
  })
})
```

---

## 6. Example Test Suites

### 6.1 Complete Component Test Suite

```typescript
// components/TodoList.spec.ts
import { mount } from '@vue/test-utils'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createTestingPinia } from '@pinia/testing'
import TodoList from '@/components/TodoList.vue'
import { useTodoStore } from '@/stores/todo'

describe('TodoList.vue', () => {
  let wrapper
  let store

  beforeEach(() => {
    wrapper = mount(TodoList, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              todo: {
                todos: [
                  { id: 1, text: 'Buy milk', completed: false },
                  { id: 2, text: 'Walk dog', completed: true }
                ]
              }
            }
          })
        ]
      }
    })

    store = useTodoStore()
  })

  describe('rendering', () => {
    it('renders all todos', () => {
      const items = wrapper.findAll('[data-test="todo-item"]')
      expect(items).toHaveLength(2)
    })

    it('displays todo text', () => {
      expect(wrapper.text()).toContain('Buy milk')
      expect(wrapper.text()).toContain('Walk dog')
    })

    it('shows completed state', () => {
      const items = wrapper.findAll('[data-test="todo-item"]')
      expect(items[0].classes()).not.toContain('completed')
      expect(items[1].classes()).toContain('completed')
    })
  })

  describe('interactions', () => {
    it('toggles todo on checkbox click', async () => {
      const checkbox = wrapper.find('[data-test="todo-checkbox-1"]')
      await checkbox.trigger('click')

      expect(store.toggleTodo).toHaveBeenCalledWith(1)
    })

    it('deletes todo on delete button click', async () => {
      const deleteBtn = wrapper.find('[data-test="delete-btn-1"]')
      await deleteBtn.trigger('click')

      expect(store.deleteTodo).toHaveBeenCalledWith(1)
    })

    it('adds new todo on form submit', async () => {
      const input = wrapper.find('[data-test="new-todo-input"]')
      await input.setValue('New task')

      const form = wrapper.find('[data-test="todo-form"]')
      await form.trigger('submit')

      expect(store.addTodo).toHaveBeenCalledWith('New task')
    })
  })

  describe('filtering', () => {
    it('shows all todos by default', () => {
      const items = wrapper.findAll('[data-test="todo-item"]')
      expect(items).toHaveLength(2)
    })

    it('filters active todos', async () => {
      store.filter = 'active'
      await wrapper.vm.$nextTick()

      const items = wrapper.findAll('[data-test="todo-item"]')
      expect(items).toHaveLength(1)
      expect(items[0].text()).toContain('Buy milk')
    })

    it('filters completed todos', async () => {
      store.filter = 'completed'
      await wrapper.vm.$nextTick()

      const items = wrapper.findAll('[data-test="todo-item"]')
      expect(items).toHaveLength(1)
      expect(items[0].text()).toContain('Walk dog')
    })
  })

  describe('edge cases', () => {
    it('shows empty state when no todos', async () => {
      store.todos = []
      await wrapper.vm.$nextTick()

      expect(wrapper.find('[data-test="empty-state"]').exists()).toBe(true)
      expect(wrapper.text()).toContain('No todos yet')
    })

    it('disables submit when input is empty', async () => {
      const input = wrapper.find('[data-test="new-todo-input"]')
      await input.setValue('')

      const submitBtn = wrapper.find('[data-test="submit-btn"]')
      expect(submitBtn.attributes('disabled')).toBeDefined()
    })
  })

  describe('snapshots', () => {
    it('matches snapshot with todos', () => {
      expect(wrapper.html()).toMatchSnapshot()
    })

    it('matches snapshot when empty', async () => {
      store.todos = []
      await wrapper.vm.$nextTick()

      expect(wrapper.html()).toMatchSnapshot()
    })
  })
})
```

### 6.2 Store Test Suite

```typescript
// stores/todo.spec.ts
import { setActivePinia, createPinia } from 'pinia'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useTodoStore } from '@/stores/todo'

describe('Todo Store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  describe('state', () => {
    it('initializes with empty todos', () => {
      const store = useTodoStore()
      expect(store.todos).toEqual([])
    })
  })

  describe('getters', () => {
    it('returns active todos', () => {
      const store = useTodoStore()
      store.todos = [
        { id: 1, text: 'Task 1', completed: false },
        { id: 2, text: 'Task 2', completed: true },
        { id: 3, text: 'Task 3', completed: false }
      ]

      expect(store.activeTodos).toHaveLength(2)
      expect(store.activeTodos[0].text).toBe('Task 1')
    })

    it('returns completed todos', () => {
      const store = useTodoStore()
      store.todos = [
        { id: 1, text: 'Task 1', completed: false },
        { id: 2, text: 'Task 2', completed: true }
      ]

      expect(store.completedTodos).toHaveLength(1)
      expect(store.completedTodos[0].text).toBe('Task 2')
    })
  })

  describe('actions', () => {
    it('adds new todo', () => {
      const store = useTodoStore()
      store.addTodo('New task')

      expect(store.todos).toHaveLength(1)
      expect(store.todos[0].text).toBe('New task')
      expect(store.todos[0].completed).toBe(false)
    })

    it('toggles todo completion', () => {
      const store = useTodoStore()
      store.todos = [{ id: 1, text: 'Task', completed: false }]

      store.toggleTodo(1)

      expect(store.todos[0].completed).toBe(true)

      store.toggleTodo(1)

      expect(store.todos[0].completed).toBe(false)
    })

    it('deletes todo', () => {
      const store = useTodoStore()
      store.todos = [
        { id: 1, text: 'Task 1', completed: false },
        { id: 2, text: 'Task 2', completed: false }
      ]

      store.deleteTodo(1)

      expect(store.todos).toHaveLength(1)
      expect(store.todos[0].id).toBe(2)
    })

    it('clears completed todos', () => {
      const store = useTodoStore()
      store.todos = [
        { id: 1, text: 'Task 1', completed: false },
        { id: 2, text: 'Task 2', completed: true },
        { id: 3, text: 'Task 3', completed: true }
      ]

      store.clearCompleted()

      expect(store.todos).toHaveLength(1)
      expect(store.todos[0].text).toBe('Task 1')
    })
  })

  describe('persistence', () => {
    it('loads todos from API', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        json: async () => [
          { id: 1, text: 'Task from API', completed: false }
        ]
      })

      const store = useTodoStore()
      await store.loadTodos()

      expect(store.todos).toHaveLength(1)
      expect(store.todos[0].text).toBe('Task from API')
    })

    it('handles API errors gracefully', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))

      const store = useTodoStore()
      await expect(store.loadTodos()).rejects.toThrow('Network error')
    })
  })
})
```

### 6.3 Composable Test Suite

```typescript
// composables/useLocalStorage.spec.ts
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useLocalStorage } from '@/composables/useLocalStorage'

describe('useLocalStorage', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  it('initializes with default value when key does not exist', () => {
    const { value } = useLocalStorage('test-key', 'default')
    expect(value.value).toBe('default')
  })

  it('initializes with stored value when key exists', () => {
    localStorage.setItem('test-key', JSON.stringify('stored'))

    const { value } = useLocalStorage('test-key', 'default')
    expect(value.value).toBe('stored')
  })

  it('updates localStorage when value changes', () => {
    const { value } = useLocalStorage('test-key', 'initial')

    value.value = 'updated'

    expect(localStorage.getItem('test-key')).toBe(JSON.stringify('updated'))
  })

  it('works with objects', () => {
    const { value } = useLocalStorage('test-key', { count: 0 })

    value.value = { count: 5 }

    expect(JSON.parse(localStorage.getItem('test-key')!)).toEqual({ count: 5 })
  })

  it('handles localStorage errors gracefully', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError')
    })

    const { value } = useLocalStorage('test-key', 'default')

    expect(() => {
      value.value = 'new value'
    }).not.toThrow()
  })
})
```

---

## Summary

This guide covers the essential aspects of testing Vue 3 applications with Vitest in 2025-2026:

1. **Vitest Configuration**: Fast, Vite-native testing with TypeScript support and flexible coverage options
2. **Vue Test Utils**: Comprehensive component testing with mounting, querying, and interaction utilities
3. **Testing Patterns**: Unit tests for composables, integration tests for components, and store testing with Pinia
4. **Best Practices**: Focus on user behavior, avoid implementation details, and use data-test attributes
5. **MSW Integration**: Network-level API mocking for realistic and maintainable tests

**Key Takeaways:**

- Use **V8 coverage** for speed, switch to Istanbul only if needed
- Test **user behavior** (clicks, inputs, visible output), not internal state
- Use **MSW** for API mocking instead of manual fetch mocks
- Use **createTestingPinia** for isolated store testing
- Use **data-test** attributes for reliable element selection
- Keep tests **focused** and **maintainable** by avoiding implementation details

**Resources:**

- Vitest Docs: https://vitest.dev
- Vue Test Utils: https://test-utils.vuejs.org
- MSW: https://mswjs.io
- Pinia Testing: https://pinia.vuejs.org/cookbook/testing.html
