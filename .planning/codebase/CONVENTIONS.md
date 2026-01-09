# Code Conventions

## Language Standards

### TypeScript Configuration

**Backend** (`/backend/tsconfig.json`):
- **Target**: ES2022
- **Module**: CommonJS
- **Strict mode**: Enabled
- **Key options**: noUnusedLocals, noUnusedParameters, noImplicitReturns
- **Output**: `./dist` directory with source maps

**Frontend** (`/frontend/tsconfig.json`):
- **Target**: ES2020
- **Module**: ESNext (for Vite)
- **Module resolution**: bundler
- **Strict mode**: Enabled
- **No emit**: true (Vite handles compilation)
- **Path mapping**: `@/*` → `./src/*`

## Code Style

### Prettier Configuration
```json
{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "useTabs": false
}
```

**Standards:**
- Semicolons required
- Single quotes for strings
- 100 character line width
- 2-space indentation (no tabs)
- ES5 trailing commas

### ESLint Rules
- **Parser**: @typescript-eslint/parser
- **Key rules**:
  - `@typescript-eslint/no-explicit-any`: "warn" (not error)
  - `@typescript-eslint/explicit-function-return-type`: "off"
  - `@typescript-eslint/no-unused-vars`: error (except `_` prefix)
- **ECMAVersion**: 2022

## Naming Conventions

### Files
- **Backend models**: PascalCase.ts (e.g., `DetectionRule.ts`, `ParsedLog.ts`)
- **Backend routes**: lowercase.ts (e.g., `auth.ts`, `logs.ts`)
- **Backend services**: camelCase directories (e.g., `parser/parserEngine.ts`)
- **Frontend components**: PascalCase.vue (e.g., `Login.vue`, `Dashboard.vue`)
- **Frontend stores**: camelCase.ts (e.g., `alerts.ts`, `auth.ts`)
- **Test files**: `[name].test.ts` or `[name].spec.ts`

### Variables & Functions
- **Variables**: camelCase (`const loginForm`, `let sourceIp`)
- **Constants**: camelCase (most), UPPER_SNAKE_CASE (config constants)
- **Functions**: camelCase (`handleLogin`, `fetchAlerts`, `updateAlert`)
- **Async functions**: Always use `async/await`, not callbacks
- **Boolean variables**: Prefix with `is`, `has`, `should` when appropriate

### Classes & Interfaces
- **Classes**: PascalCase (`ApiError`, `DetectionRuleModel`)
- **Interfaces**: PascalCase (e.g., `Alert`, `DetectionRule`, `CreateParams`)
- **Type definitions**: PascalCase
- **Model classes**: Suffix with `Model` (e.g., `UserModel`, `AlertModel`)

### Database & API
- **Database columns**: snake_case (e.g., `created_at`, `source_ip`, `rule_logic`)
- **API endpoints**: kebab-case paths (e.g., `/shippers/unknown-sources`)
- **Query parameters**: snake_case (e.g., `source_ip`, `start_date`)

## Code Organization

### Backend Structure
```
Routes (HTTP layer)
  ↓ calls
Services (Business logic)
  ↓ calls
Models (Data access)
  ↓ queries
Database
```

### Frontend Structure
```
Views (UI components)
  ↓ uses
Services (API calls)
  ↓ updates
Stores (State management)
```

## Import Patterns

### Backend
```typescript
// External packages first
import { Router, Request, Response } from 'express';

// Internal modules (blank line separator)
import { UserModel } from '../models/User';
import { ApiError } from '../middleware/errorHandler';
import { logger } from '../utils/logger';
```

### Frontend
```typescript
// Vue imports
import { ref, reactive } from 'vue';

// UI library
import { ElMessage, FormInstance } from 'element-plus';

// Internal (using @ alias)
import { useAuthStore } from '@/stores/auth';
import { api } from '@/services/api';
```

## Error Handling

### Backend Pattern
```typescript
router.get('/endpoint', async (req: Request, res: Response) => {
  try {
    // Logic here
    if (!valid) {
      throw new ApiError(400, 'Validation error message');
    }
    res.json({ data: result });
  } catch (error) {
    // Re-throw ApiError, wrap others
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Generic error message');
  }
});
```

**Key points:**
- Always use try-catch in route handlers
- Custom `ApiError` class with status code
- Re-throw `ApiError`, wrap other errors
- Centralized error handler middleware

### Frontend Pattern
```typescript
const handleLogin = async () => {
  loading.value = true;
  try {
    await authStore.login(username, password);
    ElMessage.success('Login successful');
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Login failed');
  } finally {
    loading.value = false;
  }
};
```

**Key points:**
- Axios interceptors handle 401/403/404/500 globally
- ElMessage for user-friendly errors
- Check `error.response?.data?.message` for API errors
- Use `finally` for cleanup (loading states)

## Async/Await Patterns

**Consistent usage:**
- Always use `async/await`, not callbacks or raw promises
- Always handle errors with try-catch
- Use `finally` for cleanup

**Example:**
```typescript
const fetchData = async () => {
  try {
    const result = await someAsyncOperation();
    return result;
  } catch (error) {
    logger.error('Failed to fetch data', error);
    throw error;
  } finally {
    // Cleanup if needed
  }
};
```

## Vue.js Conventions

### Composition API
- **Preferred**: `<script setup lang="ts">` syntax
- **Refs**: Use `ref()` for reactive primitives
- **Reactive objects**: Use `reactive()` for objects
- **Stores**: Pinia with composition API
- **Computed**: Use `computed()` from Vue

### Component Structure
```vue
<template>
  <!-- Template first -->
</template>

<script setup lang="ts">
// Imports
// Store usage
// Refs/reactive state
// Computed properties
// Methods
// Lifecycle hooks
</script>

<style scoped>
/* Component-specific styles */
</style>
```

### Props and Emits
- Use TypeScript interfaces for prop types
- Define emits explicitly
- Use `defineProps` and `defineEmits` macros

## Database Query Patterns

### Parameterized Queries
```typescript
// ALWAYS use parameterized queries
const result = await query(
  'SELECT * FROM users WHERE username = $1',
  [username]
);

// NEVER use string concatenation
// BAD: `SELECT * FROM users WHERE username = '${username}'`
```

### Model Pattern
```typescript
class UserModel {
  static async create(data: UserData): Promise<User> {
    const result = await query(
      'INSERT INTO users (...) VALUES ($1, $2) RETURNING *',
      [data.field1, data.field2]
    );
    return result.rows[0];
  }

  static async findById(id: number): Promise<User | null> {
    const result = await query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );
    return result.rows[0] || null;
  }
}
```

**Key points:**
- Static methods on Model classes
- Common methods: create, findById, findAll, update, delete
- Return typed results
- Handle null cases explicitly

## Logging Patterns

### Winston Usage
```typescript
import { logger } from '../utils/logger';

// Info logging
logger.info('User logged in', { userId, username });

// Error logging
logger.error('Failed to process request', { error, context });

// Warning
logger.warn('Rate limit approaching', { ip, requestCount });

// Debug (only in development)
logger.debug('Debug details', { data });
```

**Standards:**
- JSON format in production
- Colorized console in development
- Structured logging with metadata objects
- Service name: `siembox-backend`

## API Response Patterns

### Success Response
```typescript
res.json({
  data: result,
  total: count,     // For paginated results
  limit: 100,
  offset: 0
});
```

### Error Response
```typescript
// Handled by errorHandler middleware
{
  status: 'error',
  statusCode: 400,
  message: 'Error description'
}
```

## State Management (Pinia)

### Store Structure
```typescript
export const useAlertsStore = defineStore('alerts', () => {
  // State
  const alerts = ref<Alert[]>([]);
  const loading = ref(false);

  // Actions
  const fetchAlerts = async (params?: any) => {
    loading.value = true;
    try {
      const response = await api.getAlerts(params);
      alerts.value = response.data.alerts;
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
      throw error;
    } finally {
      loading.value = false;
    }
  };

  // Return public API
  return {
    alerts,
    loading,
    fetchAlerts
  };
});
```

**Key points:**
- Composition API pattern with `defineStore`
- Refs for reactive state
- Async actions with try-catch-finally
- Return only public API

## Documentation Practices

### Inline Comments
- **JSDoc-style**: Used for functions and complex logic
- **Purpose comments**: Explain "why", not "what"
- **TODOs**: Marked with `// TODO:` prefix
- **Critical sections**: Marked with `/** CRITICAL: ... */`

### File Headers
```typescript
/**
 * Unit tests for NGINX parser patterns
 * Tests NGINX access and error log parsing with various formats
 * NOTE: Regex patterns should be provided by backend-architect
 */
```

## Environment Configuration

### Backend
```typescript
// Load with dotenv
import 'dotenv/config';

// Access with process.env
const port = process.env.PORT || 3001;
const jwtSecret = process.env.JWT_SECRET;

// Validate required variables
if (!jwtSecret) {
  throw new Error('JWT_SECRET is required');
}
```

### Frontend
```typescript
// Vite environment variables (prefixed with VITE_)
const apiUrl = import.meta.env.VITE_API_URL || '/api';
```

## Testing Conventions

### Test Structure
```typescript
describe('Feature Name', () => {
  beforeEach(() => {
    // Setup before each test
  });

  it('should perform expected behavior', async () => {
    // Arrange
    const input = setupTestData();

    // Act
    const result = await functionUnderTest(input);

    // Assert
    expect(result).toBe(expected);
  });
});
```

### Naming
- Use `describe` for grouping
- Use `it('should ...')` format
- Be specific and descriptive

### Assertions
```typescript
expect(value).toBe(expected)
expect(array).toHaveLength(3)
expect(object).toHaveProperty('key', 'value')
expect(fn).toHaveBeenCalledWith(arg)
expect(value).toMatch(/regex/)
```

## Security Best Practices

1. **Always use parameterized queries** (SQL injection prevention)
2. **Never log sensitive data** (passwords, tokens, API keys)
3. **Validate all user input** (express-validator)
4. **Use bcrypt for passwords** (10+ salt rounds)
5. **Set secure headers** (CORS, X-Frame-Options, etc.)
6. **Implement rate limiting** (express-rate-limit)
7. **Use HTTPS in production**
8. **Validate JWT tokens** (authenticate middleware)

## Git Commit Conventions

### Commit Message Format
```
<type>: <short description>

<optional longer description>

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

### Types
- **feat**: New feature
- **fix**: Bug fix
- **refactor**: Code restructuring
- **docs**: Documentation changes
- **test**: Test additions/changes
- **chore**: Maintenance tasks

### Examples
```
fix: add scan timeout and better event logging

fix: ignore non-fatal nmap warnings and prevent false scan failures

feat: add ghost shipper detection capability
```

## Additional Standards

### Pre-v1.0 Development
- Database schema changes in `001_initial_schema.sql`
- No incremental migrations yet (post-v1.0)

### Docker
- Alpine-based images for minimal size
- Multi-stage builds for frontend and backend
- Health checks in docker-compose.yml

### Type Safety
- Avoid `any` type (warn instead of error)
- Use interfaces for complex types
- Type all function parameters and return values
- Use type guards for runtime type checking

### Performance
- Use connection pooling for database
- Implement rate limiting on expensive operations
- Add indexes on frequently queried columns
- Use JSONB for flexible schema

### Maintainability
- Keep functions small and focused
- Extract complex logic to services
- Use meaningful variable names
- Comment complex algorithms
- Write tests for critical paths
