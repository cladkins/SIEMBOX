# Getting Started with SIEMBox Development

This guide will help you set up your development environment and start contributing to SIEMBox.

> 📚 **Component-Specific Guides:**
> - [Backend Development Guide](../../backend/README.md) - API development, services, models
> - [Frontend Development Guide](../../frontend/README.md) - Vue.js components, state management
> - [Testing Guide](./TESTING_GUIDE.md) - Running tests and writing test cases
> - [FAQ](../../FAQ.md) - Common development questions

## Prerequisites

Before you begin, ensure you have the following installed:

- **Git** - Version control
- **Node.js 18+** - JavaScript runtime
- **npm** or **yarn** - Package manager
- **Docker & Docker Compose** - Container platform (recommended)
- **PostgreSQL 15+** - Database (if not using Docker)
- **Code Editor** - VS Code recommended

### Optional Tools

- **Postman** or **curl** - API testing
- **pgAdmin** or **psql** - Database management
- **nmap** - Network scanning (for testing asset discovery)

## Quick Start (Docker Compose - Recommended)

The fastest way to get started is using Docker Compose:

```bash
# 1. Clone the repository
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX

# 2. Create environment file
cp .env.example .env

# 3. Start all services
docker compose up -d

# 4. Wait for services to start (30-60 seconds)
docker compose logs -f

# 5. Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:3001
# Default credentials: admin / changeme
```

That's it! The application is now running.

## Manual Development Setup

If you prefer to run services individually for development:

### Step 1: Clone and Setup

```bash
# Clone repository
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX

# Ensure you're on main branch
git checkout main
```

### Step 2: Database Setup

**Option A: PostgreSQL with Docker**

```bash
# Start only PostgreSQL
docker compose up -d postgres

# Database will be available at localhost:5432
```

**Option B: Local PostgreSQL Installation**

```bash
# Install PostgreSQL (varies by OS)
# macOS
brew install postgresql@15

# Ubuntu/Debian
sudo apt install postgresql-15

# Start PostgreSQL service
# macOS
brew services start postgresql@15

# Ubuntu/Debian
sudo systemctl start postgresql

# Create database and user
psql postgres
CREATE DATABASE siembox;
CREATE USER siembox WITH PASSWORD 'changeme';
GRANT ALL PRIVILEGES ON DATABASE siembox TO siembox;
\q
```

### Step 3: Backend Setup

```bash
# Navigate to backend
cd backend

# Install dependencies
npm install

# Create .env file
cat > .env << EOF
NODE_ENV=development
PORT=3001
HOST=0.0.0.0

DB_HOST=localhost
DB_PORT=5432
DB_NAME=siembox
DB_USER=siembox
DB_PASSWORD=changeme

JWT_SECRET=dev-secret-change-in-production
DEFAULT_ADMIN_PASSWORD=changeme
CREDENTIAL_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef

LOG_LEVEL=debug
CORS_ORIGIN=*
SYSLOG_PORT=5514
CLEANUP_INTERVAL_HOURS=24
EOF

# Run database migrations
npm run migrate

# Import detection rules (optional)
npm run import-rules

# Start development server
npm run dev

# Backend API will be available at http://localhost:3001
```

**Note**: Syslog port changed to 5514 to avoid requiring root privileges. Change back to 514 in production.

### Step 4: Frontend Setup

Open a new terminal:

```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Create .env.local file (optional)
cat > .env.local << EOF
VITE_API_URL=http://localhost:3001/api
EOF

# Start development server
npm run dev

# Frontend will be available at http://localhost:5173
```

### Step 5: Verify Installation

1. **Open browser**: Navigate to `http://localhost:5173`
2. **Login**: Username: `admin`, Password: `changeme`
3. **Check dashboard**: You should see the main dashboard

## Project Structure Overview

```
SIEMBox/
├── backend/             # Node.js/Express API server
│   ├── src/             # TypeScript source code
│   ├── migrations/      # Database schema
│   └── tests/           # Backend tests
├── frontend/            # Vue.js 3 web application
│   ├── src/             # TypeScript/Vue source code
│   └── public/          # Static assets
├── log-shipper/         # Log forwarding agent (Bash)
├── docs/                # Documentation
├── rules/               # Detection rule definitions
├── scripts/             # Utility scripts
└── docker-compose.yml   # Container orchestration
```

## Development Workflow

### 1. Choose a Task

Find something to work on:

- Browse [GitHub Issues](https://github.com/cladkins/SIEMBOX/issues)
- Check the [Project Board](https://github.com/cladkins/SIEMBOX/projects)
- Look for issues labeled `good first issue`
- Review `/docs/features/` for planned features

### 2. Create a Branch

```bash
# Create feature branch from main
git checkout main
git pull origin main
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/bug-description
```

**Branch naming conventions:**
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test additions/updates

### 3. Make Changes

Follow the coding conventions:

- **Backend**: See `/backend/README.md`
- **Frontend**: See `/frontend/README.md`
- **General**: See `/.claude/CLAUDE.md` for project conventions

### 4. Test Your Changes

**Backend:**
```bash
cd backend
npm test
npm run lint
```

**Frontend:**
```bash
cd frontend
npm test
npm run lint
```

**Manual testing:**
1. Test in browser
2. Check browser console for errors
3. Verify API responses in Network tab
4. Test with different user roles

### 5. Commit Changes

Follow commit message conventions:

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: add user profile page

- Created profile view component
- Added profile update API endpoint
- Implemented password change functionality

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

**Commit message format:**
```
<type>: <short description>

<optional longer description>

<optional co-author>
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation
- `refactor` - Code restructuring
- `test` - Tests
- `chore` - Maintenance

### 6. Push and Create Pull Request

```bash
# Push branch to remote
git push origin feature/your-feature-name

# Create pull request on GitHub
# Target branch: main
```

**Pull Request Template:**

```markdown
## Summary
Brief description of changes

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing
- [ ] Unit tests added/updated
- [ ] Manual testing completed
- [ ] Documentation updated

## Screenshots (if applicable)
[Add screenshots for UI changes]
```

## Common Development Tasks

### Adding a New API Endpoint

1. **Create route handler** in `/backend/src/routes/`
2. **Add model methods** in `/backend/src/models/`
3. **Add service logic** in `/backend/src/services/` (if needed)
4. **Write tests** in `/backend/tests/`
5. **Update API documentation** in `/docs/reference/API.md`

See `/backend/README.md` for detailed examples.

### Creating a New Vue Component

1. **Create component** in `/frontend/src/views/` or `/components/`
2. **Add route** in `/frontend/src/router/index.ts`
3. **Create service methods** in `/frontend/src/services/api.ts`
4. **Update navigation** in `/frontend/src/views/Layout.vue`
5. **Write tests** in `__tests__` directory

See `/frontend/README.md` for detailed examples.

### Adding a New Parser

1. **Create YAML file** in `/parsers/` directory
2. **Test pattern** using test endpoint or script
3. **Document** in `/docs/reference/PARSERS.md`
4. **Add to community parsers** if generally useful

See `/docs/reference/PARSERS.md` for detailed guide.

### Adding a Detection Rule

1. **Create YAML file** in `/rules/<category>/`
2. **Test rule** against sample logs
3. **Document** in `/docs/reference/RULES.md`
4. **Verify alert generation** works correctly

See `/docs/reference/RULES.md` for detailed guide.

### Database Schema Changes

**Pre-v1.0:**
- Edit `/backend/migrations/001_initial_schema.sql`
- Users will need to reset their database (documented in PRE-V1-DATABASE.md)

**Post-v1.0:**
- Create new migration file (002, 003, etc.)
- Follow migration best practices

See `/docs/guides/PRE-V1-DATABASE.md` for current approach.

## Debugging

### Backend Debugging

**VS Code Launch Configuration** (`.vscode/launch.json`):

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Debug Backend",
      "skipFiles": ["<node_internals>/**"],
      "program": "${workspaceFolder}/backend/src/server.ts",
      "preLaunchTask": "tsc: build - backend/tsconfig.json",
      "outFiles": ["${workspaceFolder}/backend/dist/**/*.js"],
      "env": {
        "NODE_ENV": "development"
      }
    }
  ]
}
```

**Console debugging:**

```typescript
// Use logger instead of console.log
import { logger } from '../utils/logger';

logger.debug('Debug info', { data });
logger.info('Info message', { context });
logger.error('Error occurred', { error });
```

### Frontend Debugging

**Browser DevTools:**
1. Open DevTools (F12 or Cmd+Option+I)
2. Use Console tab for logs
3. Use Network tab for API calls
4. Use Vue DevTools extension for component inspection

**Vue DevTools:**
- Install [Vue DevTools](https://devtools.vuejs.org/) extension
- Inspect component state and props
- Track Pinia store changes

### Database Debugging

```bash
# Connect to database
psql -U siembox -d siembox

# View tables
\dt

# Describe table structure
\d table_name

# View recent logs
SELECT * FROM raw_logs ORDER BY created_at DESC LIMIT 10;

# Check parser matches
SELECT COUNT(*), parser_id FROM parsed_logs GROUP BY parser_id;

# View active rules
SELECT * FROM detection_rules WHERE enabled = true;
```

## Testing

### Running Tests

```bash
# Backend tests
cd backend
npm test                    # All tests
npm run test:watch          # Watch mode
npm run test:coverage       # Coverage report

# Frontend tests
cd frontend
npm test                    # All tests
npm run test:watch          # Watch mode
npm run test:ui             # UI mode
```

### Writing Tests

Follow testing guidelines in:
- Backend: `/backend/README.md`
- Frontend: `/frontend/README.md`

**Key principles:**
- Write tests for new features
- Maintain/update existing tests
- Aim for 70%+ code coverage
- Test success and error paths

## Documentation

### Documentation Standards

When making changes, update relevant documentation:

- **API changes**: Update `/docs/reference/API.md`
- **New features**: Add to feature docs in `/docs/features/`
- **Parsers**: Update `/docs/reference/PARSERS.md`
- **Rules**: Update `/docs/reference/RULES.md`
- **Configuration**: Update `/DEPLOYMENT.md`
- **Troubleshooting**: Add to `/docs/operations/TROUBLESHOOTING.md`

### Writing Good Documentation

- Be clear and concise
- Include examples
- Use proper formatting (markdown)
- Add code blocks with syntax highlighting
- Include screenshots for UI changes
- Keep documentation up-to-date with code

## Environment Variables Reference

### Backend Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `NODE_ENV` | Environment | development | No |
| `PORT` | API server port | 3001 | No |
| `HOST` | Bind address | 0.0.0.0 | No |
| `DB_HOST` | PostgreSQL host | localhost | Yes |
| `DB_PORT` | PostgreSQL port | 5432 | Yes |
| `DB_NAME` | Database name | siembox | Yes |
| `DB_USER` | Database user | siembox | Yes |
| `DB_PASSWORD` | Database password | - | Yes |
| `JWT_SECRET` | JWT signing key | - | Yes |
| `DEFAULT_ADMIN_PASSWORD` | Initial admin password | changeme | No |
| `CREDENTIAL_ENCRYPTION_KEY` | Encryption key | - | Yes |
| `LOG_LEVEL` | Winston log level | info | No |
| `CORS_ORIGIN` | CORS allowed origins | * | No |
| `SYSLOG_PORT` | Syslog listener port | 514 | No |
| `CLEANUP_INTERVAL_HOURS` | Cleanup frequency | 24 | No |

### Frontend Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_URL` | Backend API URL | /api |

## Troubleshooting

### Common Issues

**Issue**: Port 514 requires root privileges

**Solution**: Use higher port for development:
```bash
SYSLOG_PORT=5514 npm run dev
```

---

**Issue**: Database connection failed

**Solution**:
1. Check PostgreSQL is running
2. Verify credentials in `.env`
3. Test connection: `psql -U siembox -d siembox`

---

**Issue**: Frontend can't connect to backend

**Solution**:
1. Verify backend is running on port 3001
2. Check `VITE_API_URL` in `.env.local`
3. Check browser console for CORS errors

---

**Issue**: Hot reload not working

**Solution**:
1. Restart dev servers
2. Clear browser cache
3. Check file watching limits: `ulimit -n 4096`

---

**Issue**: TypeScript errors

**Solution**:
```bash
# Clear and rebuild
rm -rf node_modules dist
npm install
npm run build
```

See `/docs/operations/TROUBLESHOOTING.md` for more issues.

## Getting Help

- **Documentation**: Check `/docs` directory
- **Issues**: [GitHub Issues](https://github.com/cladkins/SIEMBOX/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cladkins/SIEMBOX/discussions)
- **Component READMEs**:
  - Backend: `/backend/README.md`
  - Frontend: `/frontend/README.md`
  - Log Shipper: `/log-shipper/README.md`

## Next Steps

Now that you have your development environment set up:

1. **Explore the codebase**
   - Read through backend and frontend code
   - Understand the architecture
   - Review existing parsers and rules

2. **Try adding a feature**
   - Start with something small (new parser, UI improvement)
   - Follow the development workflow
   - Submit a pull request

3. **Contribute to documentation**
   - Improve existing docs
   - Add examples
   - Fix typos or unclear sections

4. **Join the community**
   - Star the repository on GitHub
   - Watch for updates
   - Participate in discussions

## Additional Resources

### Documentation

- **Main README**: `/README.md`
- **Deployment Guide**: `/DEPLOYMENT.md`
- **API Documentation**: `/docs/reference/API.md`
- **Parser Guide**: `/docs/reference/PARSERS.md`
- **Rules Guide**: `/docs/reference/RULES.md`
- **Security Guide**: `/docs/reference/SECURITY.md`
- **Contributing**: `/CONTRIBUTING.md`

### External Resources

- **Vue.js**: https://vuejs.org/
- **Express**: https://expressjs.com/
- **PostgreSQL**: https://www.postgresql.org/docs/
- **TypeScript**: https://www.typescriptlang.org/
- **Docker**: https://docs.docker.com/

### Community

- **GitHub**: https://github.com/cladkins/SIEMBOX
- **Issues**: https://github.com/cladkins/SIEMBOX/issues
- **Discussions**: https://github.com/cladkins/SIEMBOX/discussions

---

**Welcome to the SIEMBox community! We're excited to have you contribute.**
