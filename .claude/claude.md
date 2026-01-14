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
/analysis         - Claude Code deep-dive analysis reports (git-ignored)
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
- `docs/reference/API.md` - Complete REST API documentation (symlinked at root)
- `DEPLOYMENT.md` - Installation and configuration guide
- `docs/reference/PARSERS.md` - Parser creation and community parsers (symlinked at root)
- `docs/reference/RULES.md` - Detection rule documentation (symlinked at root)
- `docs/reference/SECURITY.md` - Security hardening guide (symlinked at root)
- `docs/operations/TROUBLESHOOTING.md` - Common issues and solutions
- `CONTRIBUTING.md` - Contribution guidelines
- `docs/guides/PRE-V1-DATABASE.md` - Pre-v1.0 database schema management
- `docs/operations/SHIPPER-DIAGNOSTICS.md` - Log shipper diagnostics

## Development Workflow

### Branch Strategy
- **Main branch**: `main` - all development happens here
- Feature branches can be created from `main` for larger changes
- All pull requests target `main`

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

## Log Shipper Architecture

### Shipper Authentication and Configuration Management

SIEMBox uses a **managed log shipper** (`shipper-managed.sh`) that balances security with operational resilience through a configuration caching system.

**Key Design Principles:**

1. **Authentication-Required Configuration**: Shippers must register with a valid API key to fetch configuration
2. **Cached Configuration Fallback**: If API key validation fails (invalid, expired, or rotated), shipper continues using last-known-good cached configuration
3. **Ghost Shipper Detection**: Shippers operating with invalid API keys create "ghost shippers" - visible in the UI for administrators to identify and remediate

**Configuration Flow:**

```
Initial Startup:
1. Shipper generates 8-char ID from API key: SHA256(api_key)[0:8]
2. Attempts registration: POST /api/shippers/register
   ├─ Success: Receives config, caches it, starts log transmission
   └─ Failure: Loads cached config (if exists), continues as ghost shipper

Polling Loop (every 30s):
1. Attempts config fetch: GET /api/shippers/config/:api_key
   ├─ Success: Updates cache, applies new config if changed
   └─ Failure: Continues with existing config (cached or current)
```

**Ghost Shipper Behavior:**

When a shipper's API key becomes invalid (deleted, rotated, expired):
- ✅ **Logs continue flowing** via syslog (UDP/TCP port 514)
- ✅ **Shipper ID remains in logs** (`raw_logs.shipper_id` column)
- ✅ **Ghost shipper appears in UI** (detected via `/api/shippers/unknown-sources`)
- ⚠️ **Configuration updates blocked** (cannot fetch new config without valid API key)
- ⚠️ **Heartbeat fails** (shows as "last seen" timestamp not updating)

**Why This Design:**

- **Security**: Requires initial authentication to access configuration
- **Resilience**: Temporary API issues don't stop log collection
- **Visibility**: Administrators can identify unauthorized or misconfigured shippers
- **Operational Continuity**: API key rotation doesn't create log gaps

**Configuration Cache:**

- Location: `/tmp/siembox-cached-config.json` (or Docker volume mount)
- Saved: On every successful config fetch or registration
- Loaded: When config fetch fails (404/network error)
- Contains: Log sources, syslog server details, facility/tag mappings

**Testing Ghost Shipper Detection:**

```bash
# 1. Start shipper with valid API key
docker run -e SHIPPER_API_KEY=valid_key siembox-log-shipper

# 2. Delete/change API key in SIEMBox UI or database

# 3. Shipper continues sending logs (ghost shipper mode)

# 4. Check UI: Navigate to Shippers page → See "Unknown Sources" alert

# 5. Query database:
SELECT shipper_id, COUNT(*) FROM raw_logs
WHERE shipper_id NOT IN (
  SELECT SUBSTRING(ENCODE(SHA256(api_key::bytea), 'hex'), 1, 8)
  FROM log_shippers
) GROUP BY shipper_id;
```

### Historical Context

**Commit `2846356` (Dec 10, 2024)**: Removed unauthenticated `shipper.sh`, enforced API key requirement
- **Before**: Two shipper modes (managed/unmanaged), logs could flow without authentication
- **After**: Single managed shipper with mandatory API authentication

**Current Implementation** (as of Dec 2024): Cached configuration system
- **Purpose**: Restore ghost shipper detection capability while maintaining security
- **Benefit**: Administrators can identify misconfigured/unauthorized shippers instead of silently losing logs

## Syslog Parsing Architecture

### Two-Stage Parsing Pipeline

SIEMBox uses a two-stage parsing architecture for processing syslog messages:

**Stage 1: Syslog Protocol Parsing** (`backend/src/services/syslog/syslogParser.ts`)
- Receives raw syslog messages via UDP/TCP on port 514
- Parses RFC 3164 format: `<PRI>TIMESTAMP HOSTNAME TAG: MESSAGE`
- Extracts metadata: priority, timestamp, hostname, app name, process ID
- **Stores only the MESSAGE portion** in `raw_logs.raw_message`

**Stage 2: Application Log Parsing** (`backend/src/services/parser/parserEngine.ts`)
- Receives the extracted message from Stage 1
- Applies user-defined parsers (regex/grok/JSON) in priority order
- Extracts structured fields from application-specific log formats
- Stores parsed data in `parsed_logs` table with field mappings

### Critical Understanding for Parser Development

**What gets stored in `raw_message`:**

After commit `0f58032`, the system stores **only the extracted message portion**, not the full syslog line.

Example:
```
Syslog Server Receives:
<134>Dec 09 20:36:20 webserver NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET

Stage 1 Extracts:
raw_message = "[09/Dec/2025:20:35:53 +0000] - 200 200 - GET"

Stage 2 Matches Against:
Parser pattern: ^\[(?<timestamp>[^\]]+)\]...
```

### Common Pitfalls When Creating Parsers

1. **Writing patterns for full syslog messages**: Parsers receive only the message portion, not the syslog headers
   - ❌ Wrong: `^<\d+>\w+\s+\d+.*NGINX: \[(?<timestamp>...)`
   - ✓ Correct: `^\[(?<timestamp>[^\]]+)\]...`

2. **Assuming standard log format**: Custom applications may have non-standard formats after syslog extraction
   - Always test with actual `raw_message` content from the database
   - Use diagnostic queries to see what parsers will match against

3. **Ignoring parser priority**: Lower priority numbers match first
   - Custom parsers should have higher priority (lower numbers) than generic parsers
   - Example: `nginx-custom` (priority 30) before `standard-nginx` (priority 40)

4. **Not testing edge cases**: Logs may have optional fields or truncated content
   - Use optional regex groups: `(?<field>...)?`
   - Test with incomplete log samples

### Diagnostic Procedures

**Symptom: Logs appear in `raw_logs` but not `parsed_logs`**

Step 1: Check what's in `raw_message`
```sql
SELECT id, LEFT(raw_message, 80) as message_preview
FROM raw_logs
WHERE source_ip = 'x.x.x.x'
ORDER BY created_at DESC
LIMIT 5;
```

Step 2: Verify syslog extraction is working
```sql
SELECT
  raw_message,  -- Should NOT contain <PRI>TIMESTAMP HOSTNAME TAG:
  app_name,     -- Should contain the TAG (e.g., "NGINX")
  hostname      -- Should contain the hostname
FROM raw_logs
WHERE id = [log_id];
```

Step 3: Test parser patterns against actual `raw_message` content
- Use the test scripts in `backend/test-*-patterns.js`
- Create a sample with the exact `raw_message` format
- Verify the regex matches and extracts expected fields

Step 4: Check parser priority ordering
```sql
SELECT name, priority, enabled, pattern
FROM parsers
WHERE enabled = true
ORDER BY priority ASC;
```

Step 5: Review parser engine logs for matching failures
```bash
# Check application logs for parser errors
docker logs siembox-backend | grep -i "parser"
```

Step 6: Validate parser with test data
```javascript
// Create test script based on test-nginx-patterns.js
const testMessage = "[actual raw_message from database]";
const pattern = /your-parser-pattern/;
const match = testMessage.match(pattern);
console.log(match ? match.groups : "No match");
```

## Common Tasks

### Adding a New API Endpoint
1. Define route in appropriate backend router
2. Create controller function with error handling
3. Add database queries if needed
4. Update `API.md` documentation
5. Add corresponding frontend service call

### Creating a New Parser
1. **Analyze the log format**: Query `raw_message` from database to see actual content
   ```sql
   SELECT DISTINCT LEFT(raw_message, 100) FROM raw_logs WHERE app_name = 'YourApp' LIMIT 10;
   ```
2. **Design the parser pattern**: Match against the extracted message (NOT the syslog header)
3. **Create test script**: Use `backend/test-nginx-patterns.js` as template
4. **Validate pattern**: Run tests to confirm field extraction works
5. **Set appropriate priority**: Custom parsers should have priority 30-40 range (lower numbers match first)
6. **Add to database**: Use parsers UI/API, or add directly to `001_initial_schema.sql` if needed during pre-v1.0 development
7. **Test in production**: Monitor `parsed_logs` table for successful parsing
8. **Document**: Add to `PARSERS.md` with examples and field descriptions

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

## Analysis Documents

When Claude Code performs deep-dive investigations (like the agent-organizer), comprehensive analysis documents are generated and stored in the `/analysis` directory. These documents provide:

- Root cause analysis of complex issues
- Architectural deep-dives and recommendations
- Diagnostic flowcharts and data flow diagrams
- Implementation strategies with confidence metrics
- Technical context for major decisions

**Important Notes:**
- The `/analysis` directory is git-ignored (local-only reference material)
- Analysis docs are named descriptively (e.g., `PARSER_REGRESSION_ANALYSIS.md`)
- These documents complement code comments and serve as historical context
- Not all investigations generate analysis docs - only comprehensive deep-dives
- Summary documents (like `PARSER_FIX_SUMMARY.md`) may be committed to provide context

**When to Request Analysis:**
- Complex bugs affecting multiple systems
- Architectural decisions requiring trade-off analysis
- Performance issues needing root cause investigation
- Pre-implementation planning for major features

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
- All development happens on the `main` branch
- Parser and rule contributions are encouraged
- Documentation is comprehensive - reference existing docs when needed
- Avoid over-engineering - keep solutions focused and simple

### Important Development Constraints

**Docker Testing Environment:**
- This application is deployed and tested on a remote Docker server
- **DO NOT run any `docker compose` commands** - the application is running remotely
- Code changes are tested by deploying to the remote Docker environment
- Focus on code development and Git operations only

**Pre-v1.0 Database Schema Management:**
- SIEMBox is currently in pre-v1.0 development
- Database schema changes are made directly in `backend/migrations/001_initial_schema.sql`
- Users may need to reset their database when pulling schema changes (see docs/guides/PRE-V1-DATABASE.md)
- **DO NOT create new migration files (002, 003, etc.) for schema changes**
- Keep the schema simple - all tables/columns in the base file
- After v1.0 release, we'll implement proper migration tracking for production users

**Git Workflow:**
- All completed changes must be submitted to GitHub
- After completing a feature or fix, create a commit with an appropriate message
- Push changes to `main` branch (or a feature branch for larger changes)
- Follow the Git Safety Protocol outlined in the bash tool instructions

**Documentation Requirements:**
- Good documentation is required after all changes and new features
- Update relevant documentation files when making changes:
  - `API.md` for new or modified API endpoints
  - `PARSERS.md` for new parsers or parser features
  - `RULES.md` for new detection rules
  - `DEPLOYMENT.md` for deployment or configuration changes
  - `docs/operations/TROUBLESHOOTING.md` for common issues and solutions
  - Backend/Frontend READMEs for component-specific changes
- Include inline code comments for complex logic
- Update code examples in documentation to reflect changes
- Documentation should be clear, concise, and accurate
