# SIEMBox - Claude Code Project Context

## Project Overview

SIEMBox is a lightweight, self-hosted Security Information and Event Management (SIEM) system built with Node.js, TypeScript, and Vue.js. It provides log ingestion, parsing, detection rules, alerting, and a web-based management interface.

## Architecture

### Technology Stack
- **Frontend**: Vue.js 3 + Element Plus UI + Vite + TypeScript
- **Backend**: Node.js + Express + TypeScript
- **Database**: PostgreSQL with JSONB for flexible log storage
- **Log Shipper**: Alpine-based log forwarder (optional component)
- **Deployment**: Docker Compose

### Project Structure
```
/backend          - Express API server
/frontend         - Vue.js web interface
/log-shipper      - Universal log forwarder component
```

## Key Components

### Backend (`/backend`)
- Express REST API
- PostgreSQL database integration
- Syslog server (UDP/TCP port 514)
- Parser engine (regex, grok, JSON)
- Detection rule engine
- Alert management
- User authentication & authorization

### Frontend (`/frontend`)
- Vue 3 with Composition API
- Element Plus UI components
- Log viewer and search
- Parser configuration UI
- Detection rule builder
- Alert dashboard
- User management interface

### Log Shipper (`/log-shipper`)
- Universal log forwarder
- Configurable log sources (files, journald, etc.)
- Sends logs to SIEMBox API
- Alpine-based Docker container

## Important Files

### Configuration
- `.env.example` - Environment variable template
- `docker-compose.yml` - Container orchestration
- `backend/tsconfig.json` - Backend TypeScript config
- `frontend/tsconfig.json` - Frontend TypeScript config

### Documentation
- `README.md` - Main project readme
- `API.md` - Complete REST API documentation
- `DEPLOYMENT.md` - Installation and configuration guide
- `PARSERS.md` - Parser creation and community parsers
- `RULES.md` - Detection rule documentation
- `SECURITY.md` - Security hardening guide
- `TROUBLESHOOTING.md` - Common issues and solutions
- `CONTRIBUTING.md` - Contribution guidelines

## Development Workflow

### Branch Strategy
- **Main branch**: Not specified (typically `main` or `master`)
- **Current branch**: `develop` - active development branch
- Use `develop` branch for creating pull requests unless directed otherwise

### Recent Changes
The project recently added:
- Syslog server settings configuration
- Severity filtering for logs
- Improved documentation
- Log shipper configuration enhancements

### Running the Project
```bash
# Build and start all services
docker compose up -d

# Access points
# Frontend: http://localhost:3000
# Default credentials: admin / changeme
```

### Development Commands
```bash
# Backend
cd backend
npm install
npm run dev

# Frontend
cd frontend
npm install
npm run dev

# Log Shipper
cd log-shipper
docker build -t siembox-log-shipper .
```

## Code Style Guidelines

### Backend
- TypeScript strict mode enabled
- Express middleware patterns
- Async/await for database operations
- Error handling with try/catch blocks
- API routes follow REST conventions

### Frontend
- Vue 3 Composition API preferred
- TypeScript for type safety
- Element Plus components for UI
- Composables for shared logic
- Single File Components (.vue)

## Database Schema

PostgreSQL is used with JSONB columns for flexible log storage. Key tables include:
- Users and authentication
- Log entries with JSONB fields
- Parsers (regex, grok, JSON)
- Detection rules with conditions
- Alerts with severity levels
- Log retention policies

## Security Considerations

- Role-based access control (Admin, Analyst, Viewer)
- JWT-based authentication
- SQL injection prevention via parameterized queries
- Input validation on all endpoints
- See `SECURITY.md` for comprehensive security guidelines

## Common Tasks

### Adding a New API Endpoint
1. Define route in appropriate backend router
2. Create controller function with error handling
3. Add database queries if needed
4. Update `API.md` documentation
5. Add corresponding frontend service call

### Creating a New Parser
1. Define parser in parsers UI or via API
2. Test with sample log data
3. Consider contributing to `PARSERS.md`
4. Document field extraction logic

### Adding a Detection Rule
1. Create rule via UI or API
2. Define conditions and thresholds
3. Set severity level
4. Test against historical logs
5. Document in `RULES.md` if generally useful

## Testing

- Manual testing via Docker Compose environment
- Test with sample log data
- Verify parsers extract fields correctly
- Confirm detection rules trigger appropriately
- Check alert generation and acknowledgment

## Deployment Notes

- Uses Docker Compose for all components
- PostgreSQL data persisted in Docker volume
- Environment variables configured via `.env`
- Log shipper runs as separate container
- See `DEPLOYMENT.md` for production considerations

## Contributing

- Follow existing code patterns
- Update documentation for new features
- Consider contributing parsers and rules to community
- See `CONTRIBUTING.md` for full guidelines

## Resources

- **Issues**: https://github.com/cladkins/SIEMBOX/issues
- **Discussions**: https://github.com/cladkins/SIEMBOX/discussions
- **License**: MIT

## Notes for Claude Code

- This is an active security project - prioritize security best practices
- The project uses TypeScript throughout - maintain type safety
- Docker Compose is the primary deployment method
- The `develop` branch is the active development branch
- Parser and rule contributions are encouraged
- Documentation is comprehensive - reference existing docs when needed
- Avoid over-engineering - keep solutions focused and simple

### Important Development Constraints

**Docker Testing Environment:**
- This application is deployed and tested on a remote Docker server
- **DO NOT run any `docker compose` commands** - the application is running remotely
- Code changes are tested by deploying to the remote Docker environment
- Focus on code development and Git operations only

**Git Workflow:**
- All completed changes must be submitted to GitHub
- After completing a feature or fix, create a commit with an appropriate message
- Push changes to the appropriate branch (typically `develop`)
- Follow the Git Safety Protocol outlined in the bash tool instructions

**Documentation Requirements:**
- Good documentation is required after all changes and new features
- Update relevant documentation files when making changes:
  - `API.md` for new or modified API endpoints
  - `PARSERS.md` for new parsers or parser features
  - `RULES.md` for new detection rules
  - `DEPLOYMENT.md` for deployment or configuration changes
  - `TROUBLESHOOTING.md` for common issues and solutions
  - Backend/Frontend READMEs for component-specific changes
- Include inline code comments for complex logic
- Update code examples in documentation to reflect changes
- Documentation should be clear, concise, and accurate
