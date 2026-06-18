# SIEMBox Backend

The SIEMBox backend is a Node.js/TypeScript application that provides the core SIEM functionality including log ingestion, parsing, detection rules, alerting, and a REST API.

> 📚 **Related Documentation:**
> - [Getting Started (Development)](../docs/guides/GETTING_STARTED_DEVELOPMENT.md) - Complete development setup
> - [API Documentation](../API.md) - Full REST API reference
> - [API Quick Reference](../docs/reference/API_QUICK_REFERENCE.md) - Common API operations
> - [Frontend Development](../frontend/README.md) - Frontend component guide

## Tech Stack

- **Node.js 20** - Runtime environment
- **TypeScript 5.3.3** - Type-safe JavaScript
- **Express 4.18.2** - Web framework
- **PostgreSQL 15** - Database
- **node-postgres (pg) 8.11.3** - Database client
- **Winston 3.11.0** - Logging
- **Jest 29.7.0** - Testing framework
- **bcrypt 5.1.1** - Password hashing
- **jsonwebtoken 9.0.2** - JWT authentication

## Architecture

The backend follows a **layered architecture** pattern:

```
HTTP Request
  ↓
Route Handler (routes/*.ts)
  ↓
Service Layer (services/*/*.ts)    [Business Logic]
  ↓
Model Layer (models/*.ts)           [Data Access]
  ↓
Database (PostgreSQL)
```

**Key Components:**
- **Express REST API** - HTTP endpoints for frontend
- **Syslog Server** - UDP/TCP port 514 for log ingestion
- **Parser Engine** - Transforms raw logs to structured data
- **Rules Engine** - Evaluates logs against detection rules
- **Cleanup Service** - Enforces retention policies
- **Auto-Discovery Job** - Periodic network scanning
- **NMAP Scanner** - Asset discovery and vulnerability scanning

## Project Structure

```
backend/
├── src/
│   ├── server.ts              # Entry point (starts all services)
│   ├── app.ts                 # Express app configuration
│   ├── config/
│   │   └── database.ts        # PostgreSQL connection pool
│   ├── middleware/            # Express middleware
│   │   ├── auth.ts            # Authentication & authorization
│   │   ├── errorHandler.ts    # Global error handling
│   │   ├── rateLimiter.ts     # Rate limiting configs
│   │   ├── scanPermissions.ts # Asset scan authorization
│   │   └── scanValidation.ts  # Input validation
│   ├── routes/                # API endpoint controllers
│   │   ├── auth.ts            # Authentication endpoints
│   │   ├── users.ts           # User management
│   │   ├── logs.ts            # Log retrieval
│   │   ├── parsers.ts         # Parser CRUD
│   │   ├── rules.ts           # Detection rules CRUD
│   │   ├── alerts.ts          # Alert management
│   │   ├── settings.ts        # System settings
│   │   ├── shippers.ts        # Log shipper management
│   │   └── assets.ts          # Asset inventory & scanning
│   ├── services/              # Business logic
│   │   ├── syslog/
│   │   │   ├── syslogServer.ts   # UDP/TCP listener
│   │   │   └── syslogParser.ts   # RFC 3164 parsing
│   │   ├── parser/
│   │   │   └── parserEngine.ts   # Log parsing engine
│   │   ├── rules/
│   │   │   └── rulesEngine.ts    # Detection rule evaluation
│   │   ├── cleanup/
│   │   │   └── cleanupService.ts # Data retention
│   │   ├── assets/
│   │   │   ├── assetRepository.ts
│   │   │   ├── scanRepository.ts
│   │   │   └── autoDiscoveryService.ts
│   │   ├── scanner/
│   │   │   └── nmapScanner.ts    # Network scanning
│   │   ├── credentials/
│   │   │   └── credentialEncryption.ts
│   │   └── audit/
│   │       └── auditService.ts
│   ├── models/                # Database models (repository pattern)
│   │   ├── User.ts
│   │   ├── Session.ts
│   │   ├── RawLog.ts
│   │   ├── ParsedLog.ts
│   │   ├── Parser.ts
│   │   ├── DetectionRule.ts
│   │   ├── Alert.ts
│   │   ├── LogShipper.ts
│   │   ├── Asset.ts
│   │   └── Scan.ts
│   ├── types/                 # TypeScript type definitions
│   │   ├── index.ts
│   │   ├── apiTypes.ts
│   │   ├── serviceTypes.ts
│   │   └── nmapTypes.ts
│   ├── utils/
│   │   ├── logger.ts          # Winston logger config
│   │   └── typeGuards.ts      # Type guards
│   ├── jobs/
│   │   └── autoDiscovery.ts   # Scheduled asset scanning
│   └── scripts/
│       ├── migrate.ts         # Database migration runner
│       └── import-rules.ts    # Auto-import detection rules
├── migrations/
│   └── 001_initial_schema.sql # Database schema (459 lines)
├── tests/                     # Unit and integration tests
├── package.json
├── tsconfig.json              # TypeScript configuration
├── jest.config.js             # Jest test configuration
├── Dockerfile                 # Multi-stage Docker build
└── README.md                  # This file
```

## Getting Started

### Prerequisites

- Node.js 18+
- PostgreSQL 15+
- npm or yarn
- Docker (optional, for containerized development)

### Installation

```bash
# Navigate to backend directory
cd backend

# Install dependencies
npm install
```

### Database Setup

**Option 1: Docker Compose (Recommended)**

```bash
# From project root
docker compose up -d postgres

# Database will be available at localhost:5432
```

**Option 2: Local PostgreSQL**

```bash
# Create database
createdb siembox

# Run migrations
npm run migrate
```

### Environment Variables

Create `.env` file in backend directory:

```bash
# Server
NODE_ENV=development
PORT=8421
HOST=0.0.0.0

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=siembox
DB_USER=siembox
DB_PASSWORD=changeme

# Security (CHANGE THESE!)
JWT_SECRET=change-this-to-a-random-secret-key
DEFAULT_ADMIN_PASSWORD=changeme
CREDENTIAL_ENCRYPTION_KEY=32-character-hex-key-here

# Logging
LOG_LEVEL=debug

# CORS
CORS_ORIGIN=*

# Syslog
SYSLOG_PORT=514

# Cleanup
CLEANUP_INTERVAL_HOURS=24
```

**⚠️ Security Warning**: Always change default secrets in production!

### Development

```bash
# Start development server with hot reload
npm run dev

# Server will start on http://localhost:8421
```

The dev server uses `tsx` to run TypeScript directly with watch mode.

### Building for Production

```bash
# Compile TypeScript to JavaScript
npm run build

# Output: ./dist directory
```

### Running Production Build

```bash
# Start production server
npm start

# Or with PM2
pm2 start dist/server.js --name siembox-backend
```

## Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server with hot reload |
| `npm run build` | Compile TypeScript to JavaScript |
| `npm start` | Run production build |
| `npm run migrate` | Run database migrations |
| `npm run import-rules` | Import detection rules from /rules |
| `npm test` | Run all tests |
| `npm run test:watch` | Run tests in watch mode |
| `npm run test:coverage` | Generate coverage report |
| `npm run lint` | Run ESLint |
| `npm run format` | Format code with Prettier |

## Development Workflow

### 1. Creating New API Endpoints

**Define route in appropriate router** (`/src/routes/`):

```typescript
// routes/example.ts
import { Router, Request, Response } from 'express';
import { authenticate, authorize } from '../middleware/auth';
import { ExampleModel } from '../models/Example';
import { ApiError } from '../middleware/errorHandler';

const router = Router();

router.get(
  '/example',
  authenticate,
  authorize('admin', 'analyst'),
  async (req: Request, res: Response) => {
    try {
      const items = await ExampleModel.findAll();
      res.json({ data: items });
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(500, 'Failed to fetch items');
    }
  }
);

export default router;
```

**Register router in `app.ts`:**

```typescript
import exampleRouter from './routes/example';
app.use('/api/example', exampleRouter);
```

### 2. Creating Database Models

Models use the **repository pattern** with static methods:

```typescript
// models/Example.ts
import { query } from '../config/database';

export interface Example {
  id: number;
  name: string;
  value: string;
  created_at: Date;
}

export class ExampleModel {
  static async create(data: Omit<Example, 'id' | 'created_at'>): Promise<Example> {
    const result = await query(
      'INSERT INTO examples (name, value) VALUES ($1, $2) RETURNING *',
      [data.name, data.value]
    );
    return result.rows[0];
  }

  static async findById(id: number): Promise<Example | null> {
    const result = await query(
      'SELECT * FROM examples WHERE id = $1',
      [id]
    );
    return result.rows[0] || null;
  }

  static async findAll(): Promise<Example[]> {
    const result = await query('SELECT * FROM examples ORDER BY created_at DESC');
    return result.rows;
  }

  static async update(id: number, data: Partial<Example>): Promise<Example> {
    const result = await query(
      'UPDATE examples SET name = $1, value = $2 WHERE id = $3 RETURNING *',
      [data.name, data.value, id]
    );
    return result.rows[0];
  }

  static async delete(id: number): Promise<void> {
    await query('DELETE FROM examples WHERE id = $1', [id]);
  }
}
```

**Key principles:**
- Always use parameterized queries (`$1`, `$2`, etc.)
- Return typed results
- Handle null cases explicitly
- Keep database logic in models

### 3. Creating Services

Services contain business logic and coordinate between models:

```typescript
// services/example/exampleService.ts
import { ExampleModel } from '../../models/Example';
import { logger } from '../../utils/logger';

export class ExampleService {
  async processExample(data: any): Promise<void> {
    try {
      // Business logic here
      const example = await ExampleModel.create(data);

      // Additional processing
      logger.info('Example processed', { id: example.id });
    } catch (error) {
      logger.error('Failed to process example', { error });
      throw error;
    }
  }
}
```

### 4. Error Handling

Use the custom `ApiError` class:

```typescript
import { ApiError } from '../middleware/errorHandler';

// Throw API errors with status codes
throw new ApiError(400, 'Invalid input');
throw new ApiError(404, 'Resource not found');
throw new ApiError(403, 'Insufficient permissions');

// In route handlers, wrap logic in try-catch
try {
  // Logic here
} catch (error) {
  if (error instanceof ApiError) throw error;
  throw new ApiError(500, 'Internal server error');
}
```

The `errorHandler` middleware automatically formats error responses.

### 5. Logging

Use Winston logger throughout:

```typescript
import { logger } from '../utils/logger';

// Info logging
logger.info('User logged in', { userId, username });

// Error logging
logger.error('Failed to process request', { error, context });

// Debug logging (only in development)
logger.debug('Processing data', { data });

// Warning
logger.warn('Rate limit approaching', { ip, count });
```

**Log levels:** error, warn, info, debug

### 6. Authentication & Authorization

**Protect routes with middleware:**

```typescript
import { authenticate, authorize, requireAdmin } from '../middleware/auth';

// Require authentication
router.get('/protected', authenticate, handler);

// Require specific roles
router.post('/admin-only', requireAdmin, handler);
router.get('/multi-role', authorize('admin', 'analyst'), handler);
```

**Roles:**
- `admin` - Full system access
- `analyst` - View and manage logs, alerts, rules
- `viewer` - Read-only access
- `operator` - Manage assets and scans

### 7. Database Migrations

**Pre-v1.0 approach:**
Edit `migrations/001_initial_schema.sql` directly.

**Post-v1.0 approach:**
Create sequential migration files (002, 003, etc.).

```bash
# Run migrations
npm run migrate
```

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Watch mode
npm run test:watch

# With coverage
npm run test:coverage

# Specific test file
npm test -- shippers.test.ts
```

### Writing Tests

Create test files alongside source or in `/tests` directory:

```typescript
// tests/routes/example.test.ts
import { describe, it, expect, jest } from '@jest/globals';
import { ExampleModel } from '../../src/models/Example';

// Mock dependencies
jest.mock('../../src/config/database');

describe('ExampleModel', () => {
  it('should create example', async () => {
    const data = { name: 'Test', value: 'Value' };
    const result = await ExampleModel.create(data);

    expect(result).toHaveProperty('id');
    expect(result.name).toBe('Test');
  });
});
```

**Testing patterns:**
- Unit tests for individual functions
- Integration tests for API endpoints
- Regression tests to prevent bug reintroduction

## Database Operations

### Querying the Database

```typescript
import { query } from '../config/database';

// Simple query
const result = await query('SELECT * FROM users');
const users = result.rows;

// Parameterized query
const result = await query(
  'SELECT * FROM users WHERE id = $1',
  [userId]
);

// JSONB queries
const result = await query(
  'SELECT * FROM parsed_logs WHERE parsed_data->>'status_code' = $1',
  ['200']
);
```

### Connection Pooling

The database uses connection pooling (max 20 connections):

```typescript
// Connection pool is automatically managed
// No manual connection handling needed
```

## Syslog Server

The backend listens for syslog messages on UDP/TCP port 514:

**Architecture:**
1. Raw syslog message received
2. SyslogParser extracts metadata (RFC 3164)
3. Stored in `raw_logs` table
4. ParserEngine applies user-defined parsers
5. Structured data stored in `parsed_logs` table
6. RulesEngine evaluates against detection rules
7. Alerts created if rules match

**Key files:**
- `/src/services/syslog/syslogServer.ts` - UDP/TCP listener
- `/src/services/syslog/syslogParser.ts` - RFC 3164 parsing
- `/src/services/parser/parserEngine.ts` - Application parsing
- `/src/services/rules/rulesEngine.ts` - Detection logic

## Parser Development

See `/docs/reference/PARSERS.md` for detailed parser creation guide.

**Quick example:**

```sql
INSERT INTO parsers (name, description, pattern, pattern_type, priority)
VALUES (
  'nginx-access',
  'NGINX access log parser',
  '^\[(?<timestamp>[^\]]+)\].*(?<status_code>\d{3})',
  'regex',
  30
);
```

**Test parsers:**

```bash
# Use test endpoint
curl -X POST http://localhost:8421/api/parsers/test \
  -H "Content-Type: application/json" \
  -d '{
    "pattern": "your-regex-pattern",
    "pattern_type": "regex",
    "test_message": "your-test-log-message"
  }'
```

## Detection Rules

See `/docs/reference/RULES.md` for detailed rule creation guide.

**Quick example:**

```yaml
# /rules/authentication/ssh-bruteforce.yml
name: SSH Brute Force Detection
description: Detects multiple failed SSH login attempts
severity: high
enabled: true
conditions:
  - field: app_name
    operator: equals
    value: sshd
  - field: message
    operator: contains
    value: "Failed password"
aggregation:
  type: threshold
  field: source_ip
  threshold: 5
  timeframe: 300
```

## Code Style

### TypeScript Conventions

- Use **strict mode** (enabled in `tsconfig.json`)
- Prefer **interfaces** over type aliases for objects
- Use **explicit return types** for public functions
- Avoid `any` type (use `unknown` if necessary)

### Naming Conventions

- **Variables**: camelCase (`userId`, `parsedData`)
- **Functions**: camelCase (`handleRequest`, `processLog`)
- **Classes**: PascalCase (`UserModel`, `ApiError`)
- **Interfaces**: PascalCase (`User`, `DetectionRule`)
- **Files**: Match class/export name

### Import Order

```typescript
// 1. External packages
import { Router } from 'express';
import bcrypt from 'bcrypt';

// 2. Internal modules (blank line separator)
import { UserModel } from '../models/User';
import { logger } from '../utils/logger';
```

## Common Issues

### Port 514 Permission Denied

Ports below 1024 require root privileges:

```bash
# Option 1: Run with sudo (not recommended)
sudo npm run dev

# Option 2: Use authbind (Linux)
authbind --deep npm run dev

# Option 3: Change to higher port
SYSLOG_PORT=5514 npm run dev
```

### Database Connection Failed

1. Verify PostgreSQL is running
2. Check connection string in `.env`
3. Test connection: `psql -U siembox -d siembox`
4. Check firewall rules

### TypeScript Errors

```bash
# Clear build cache
rm -rf dist

# Reinstall dependencies
rm -rf node_modules
npm install

# Check TypeScript version
npx tsc --version
```

### Memory Issues

Node.js may need more memory for large log volumes:

```bash
# Increase heap size
NODE_OPTIONS=--max-old-space-size=4096 npm run dev
```

## Docker Development

### Development with Docker Compose

```bash
# From project root
docker compose up -d backend

# View logs
docker logs -f siembox-backend

# Exec into container
docker exec -it siembox-backend sh
```

### Building Docker Image

```bash
# From backend directory
docker build -t siembox-backend .
```

## Performance Tips

1. **Use connection pooling** (already configured)
2. **Add database indexes** on frequently queried fields
3. **Use pagination** for large result sets
4. **Cache frequently accessed data** (consider Redis)
5. **Profile slow queries** with `EXPLAIN ANALYZE`
6. **Monitor memory usage** during log ingestion

## Security Best Practices

1. ✅ **Always use parameterized queries** (SQL injection prevention)
2. ✅ **Never log sensitive data** (passwords, tokens, keys)
3. ✅ **Validate all user input** (express-validator)
4. ✅ **Use bcrypt for passwords** (10+ rounds)
5. ✅ **Implement rate limiting** (already configured)
6. ✅ **Set secure headers** (CORS, etc.)
7. ✅ **Use HTTPS in production**
8. ✅ **Rotate secrets regularly**

## Monitoring

### Health Checks

```bash
# Basic health check
curl http://localhost:8421/health

# Database status
curl http://localhost:8421/health/database-status
```

### Logging

Logs are written to:
- Console (all environments)
- `logs/error.log` (production)
- `logs/combined.log` (production)

### Metrics (Future)

Consider adding:
- Prometheus metrics endpoint
- Application performance monitoring (APM)
- Database query performance tracking

## Resources

- **Express Documentation**: https://expressjs.com/
- **TypeScript Documentation**: https://www.typescriptlang.org/
- **PostgreSQL Documentation**: https://www.postgresql.org/docs/
- **Node.js Best Practices**: https://github.com/goldbergyoni/nodebestpractices
- **Winston Logging**: https://github.com/winstonjs/winston

## Contributing

See `/CONTRIBUTING.md` for contribution guidelines.

## Related Documentation

- **Frontend Development**: `/frontend/README.md`
- **API Documentation**: `/docs/reference/API.md`
- **Parser Documentation**: `/docs/reference/PARSERS.md`
- **Detection Rules**: `/docs/reference/RULES.md`
- **Security Guide**: `/docs/reference/SECURITY.md`
- **Deployment Guide**: `/DEPLOYMENT.md`
- **Getting Started (Development)**: `/docs/guides/GETTING_STARTED_DEVELOPMENT.md`

## Support

- **Issues**: https://github.com/cladkins/SIEMBOX/issues
- **Discussions**: https://github.com/cladkins/SIEMBOX/discussions
