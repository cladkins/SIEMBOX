# SIEMBox Frontend

The SIEMBox frontend is a modern Vue.js 3 single-page application (SPA) that provides a comprehensive web interface for security event management.

> 📚 **Related Documentation:**
> - [Getting Started (Development)](../docs/guides/GETTING_STARTED_DEVELOPMENT.md) - Complete development setup
> - [Backend Development](../backend/README.md) - API development guide
> - [API Documentation](../API.md) - REST API reference for integration
> - [Testing Guide](../docs/guides/TESTING_GUIDE.md) - Frontend testing practices

## Tech Stack

- **Vue.js 3.4.5** - Progressive JavaScript framework
- **TypeScript 5.3.3** - Type-safe JavaScript
- **Vite 5.0.11** - Next-generation build tool
- **Element Plus 2.5.1** - Vue 3 UI component library
- **Pinia 2.1.7** - State management
- **Vue Router 4.2.5** - Routing
- **Chart.js 4.4.1** - Data visualization
- **Axios 1.6.4** - HTTP client

## Project Structure

```
frontend/
├── src/
│   ├── main.ts              # Application entry point
│   ├── App.vue              # Root component
│   ├── router/
│   │   └── index.ts         # Route definitions & guards
│   ├── stores/              # Pinia state management
│   │   ├── auth.ts          # Authentication state
│   │   └── alerts.ts        # Alert state
│   ├── views/               # Page-level components
│   │   ├── Layout.vue       # App shell (sidebar, header)
│   │   ├── Login.vue        # Login page
│   │   ├── Dashboard.vue    # Main dashboard
│   │   ├── Logs.vue         # Log viewer
│   │   ├── Parsers.vue      # Parser management
│   │   ├── Rules.vue        # Detection rules
│   │   ├── Alerts.vue       # Alert management
│   │   ├── Shippers.vue     # Log shipper management
│   │   ├── Settings.vue     # System settings
│   │   ├── Users.vue        # User management
│   │   ├── Assets.vue       # Asset inventory
│   │   └── ...
│   ├── services/
│   │   ├── api.ts           # Axios HTTP client
│   │   └── assetService.ts  # Asset-specific APIs
│   ├── components/          # Reusable components
│   └── assets/              # Static assets
├── public/                  # Static files
├── package.json
├── vite.config.ts
├── tsconfig.json
└── Dockerfile
```

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn
- Backend API running (see `/backend/README.md`)

### Installation

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install
```

### Development

```bash
# Start development server with hot reload
npm run dev

# Access at http://localhost:5173
```

The dev server will proxy API requests to `http://localhost:3001` (configurable via `VITE_API_URL`).

### Building for Production

```bash
# Build optimized production bundle
npm run build

# Output: ./dist directory
```

### Preview Production Build

```bash
# Preview the production build locally
npm run preview
```

## Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server with hot reload |
| `npm run build` | Build production-optimized bundle |
| `npm run preview` | Preview production build locally |
| `npm run type-check` | Run TypeScript type checking |
| `npm run lint` | Run ESLint to check code quality |

## Development Workflow

### 1. Creating New Views

Views are page-level components in `/src/views/`:

```vue
<template>
  <div>
    <!-- Your UI here -->
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { ElMessage } from 'element-plus';
import { api } from '@/services/api';

// Component logic here
</script>

<style scoped>
/* Component-specific styles */
</style>
```

**Register routes in `/src/router/index.ts`:**

```typescript
{
  path: '/your-path',
  name: 'YourView',
  component: () => import('@/views/YourView.vue'),
  meta: { requiresAuth: true }
}
```

### 2. Using Element Plus Components

Element Plus provides pre-built UI components:

```vue
<template>
  <el-button type="primary" @click="handleClick">
    Click Me
  </el-button>

  <el-table :data="tableData">
    <el-table-column prop="name" label="Name" />
    <el-table-column prop="value" label="Value" />
  </el-table>
</template>
```

**Documentation**: https://element-plus.org/

### 3. State Management with Pinia

Create stores in `/src/stores/`:

```typescript
// stores/example.ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import { api } from '@/services/api';

export const useExampleStore = defineStore('example', () => {
  // State
  const items = ref<any[]>([]);
  const loading = ref(false);

  // Actions
  const fetchItems = async () => {
    loading.value = true;
    try {
      const response = await api.getItems();
      items.value = response.data;
    } catch (error) {
      console.error('Failed to fetch items:', error);
      throw error;
    } finally {
      loading.value = false;
    }
  };

  return {
    items,
    loading,
    fetchItems
  };
});
```

**Use in components:**

```typescript
import { useExampleStore } from '@/stores/example';

const exampleStore = useExampleStore();
await exampleStore.fetchItems();
```

### 4. Making API Calls

Use the centralized API service:

```typescript
import { api } from '@/services/api';

// GET request
const response = await api.getLogs({ limit: 100 });

// POST request
await api.createParser(parserData);

// PUT request
await api.updateRule(ruleId, ruleData);

// DELETE request
await api.deleteAlert(alertId);
```

The API service automatically:
- Adds JWT bearer token from auth store
- Handles common error responses (401, 403, 404, 500)
- Shows error messages via ElMessage

### 5. Routing & Navigation

**Navigation guards** (in `/src/router/index.ts`):
- Automatically redirect to login if not authenticated
- Check `requiresAuth` meta field on routes

**Programmatic navigation:**

```typescript
import { useRouter } from 'vue-router';

const router = useRouter();

// Navigate to route
router.push('/dashboard');

// Navigate with parameters
router.push({ name: 'LogDetails', params: { id: 123 } });

// Go back
router.back();
```

## Component Guidelines

### Composition API Pattern

Use Vue 3 Composition API with `<script setup>`:

```vue
<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';

// Props
const props = defineProps<{
  title: string;
  count?: number;
}>();

// Emits
const emit = defineEmits<{
  update: [value: string];
  delete: [id: number];
}>();

// Reactive state
const isLoading = ref(false);
const items = ref<any[]>([]);

// Computed properties
const itemCount = computed(() => items.value.length);

// Methods
const handleUpdate = (value: string) => {
  emit('update', value);
};

// Lifecycle
onMounted(() => {
  // Initialization logic
});
</script>
```

### Styling Guidelines

- Use `<style scoped>` to prevent style leakage
- Follow Element Plus design system
- Keep styles co-located with components
- Use CSS variables for theming

### Error Handling

Always handle errors gracefully:

```typescript
try {
  await someAsyncOperation();
  ElMessage.success('Operation successful');
} catch (error: any) {
  ElMessage.error(
    error.response?.data?.message || 'Operation failed'
  );
}
```

## TypeScript Usage

### Type Definitions

Define interfaces for data structures:

```typescript
interface Alert {
  id: number;
  rule_id: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  created_at: string;
  acknowledged: boolean;
}
```

### Typing Component Props

```typescript
interface Props {
  id: number;
  name: string;
  optional?: boolean;
}

const props = defineProps<Props>();
```

### API Response Types

```typescript
import type { AxiosResponse } from 'axios';

interface ApiResponse<T> {
  data: T;
  total?: number;
  limit?: number;
  offset?: number;
}

const response: AxiosResponse<ApiResponse<Alert[]>> =
  await api.getAlerts();
```

## Testing

### Running Tests

```bash
# Run all tests
npm run test

# Run tests in watch mode
npm run test:watch

# Run tests with UI
npm run test:ui
```

### Writing Tests

Create test files in `__tests__` directories:

```typescript
// views/__tests__/Login.spec.ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import Login from '@/views/Login.vue';

describe('Login.vue', () => {
  it('renders login form', () => {
    const wrapper = mount(Login);
    expect(wrapper.find('form').exists()).toBe(true);
  });

  it('calls login on form submit', async () => {
    const wrapper = mount(Login);
    const loginSpy = vi.spyOn(wrapper.vm, 'handleLogin');

    await wrapper.find('form').trigger('submit');

    expect(loginSpy).toHaveBeenCalled();
  });
});
```

## Docker Development

### Development with Docker Compose

```bash
# From project root
docker compose up -d

# Frontend available at http://localhost:3000
```

### Building Docker Image

```bash
# From frontend directory
docker build -t siembox-frontend .
```

## Environment Variables

Create `.env.local` for local overrides:

```bash
# API endpoint (default: /api)
VITE_API_URL=http://localhost:3001/api
```

**Note**: Variables must be prefixed with `VITE_` to be exposed to the app.

## Code Style

### ESLint Configuration

The project uses ESLint for code quality:

```bash
# Check for issues
npm run lint

# Auto-fix issues
npm run lint -- --fix
```

### Prettier (Future)

Consider adding Prettier for consistent formatting.

## Common Issues

### Port Already in Use

If port 5173 is already in use:

```bash
# Change port in vite.config.ts
export default defineConfig({
  server: {
    port: 3000
  }
})
```

### API Connection Issues

1. Verify backend is running on port 3001
2. Check `VITE_API_URL` environment variable
3. Check browser console for CORS errors
4. Verify network tab in dev tools

### Hot Reload Not Working

1. Restart dev server
2. Clear browser cache
3. Check file watching limits: `ulimit -n 4096`

### Build Errors

```bash
# Clear node_modules and reinstall
rm -rf node_modules
npm install

# Clear Vite cache
rm -rf node_modules/.vite
```

## Performance Optimization

### Code Splitting

Vite automatically splits code. For manual chunks:

```typescript
// vite.config.ts
export default defineConfig({
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'element-plus': ['element-plus'],
          'chart': ['chart.js', 'vue-chartjs']
        }
      }
    }
  }
})
```

### Lazy Loading Components

```typescript
// Lazy load heavy components
const HeavyComponent = defineAsyncComponent(
  () => import('@/components/HeavyComponent.vue')
);
```

## Resources

- **Vue 3 Documentation**: https://vuejs.org/
- **Element Plus**: https://element-plus.org/
- **Pinia**: https://pinia.vuejs.org/
- **Vite**: https://vitejs.dev/
- **Vue Router**: https://router.vuejs.org/
- **Chart.js**: https://www.chartjs.org/

## Contributing

See `/CONTRIBUTING.md` for contribution guidelines.

## Related Documentation

- **Backend Development**: `/backend/README.md`
- **API Documentation**: `/docs/reference/API.md`
- **Deployment Guide**: `/DEPLOYMENT.md`
- **Getting Started (Development)**: `/docs/guides/GETTING_STARTED_DEVELOPMENT.md`

## Support

- **Issues**: https://github.com/cladkins/SIEMBOX/issues
- **Discussions**: https://github.com/cladkins/SIEMBOX/discussions
