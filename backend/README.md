# SIEMBox Backend

Backend API server for SIEMBox - handles syslog ingestion, log parsing, detection rules, and alerting.

## Features

- **Syslog Ingestion**: Receives syslog messages on port 514 (UDP/TCP)
- **Log Parsing**: Transforms raw logs using custom parsers (regex, grok, JSON)
- **Detection Rules**: YAML-based rules for security event detection
- **Alert Management**: Generated alerts with severity levels and status tracking
- **User Authentication**: Role-based access control (admin, analyst, viewer)
- **REST API**: Complete API for frontend and integrations

## Tech Stack

- **Runtime**: Node.js with TypeScript
- **Framework**: Express.js
- **Database**: PostgreSQL
- **Authentication**: bcrypt + JWT
- **Logging**: Winston

## Prerequisites

- Node.js 18+ and npm
- PostgreSQL 15+
- Or use Docker Compose (see root directory)

## Installation

```bash
# Install dependencies
npm install

# Copy environment file and configure
cp ../.env.example .env
# Edit .env with your database credentials

# Run database migrations
npm run migrate

# Start development server
npm run dev
```

## Environment Variables

See `.env.example` in the root directory for all required variables:

- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`
- `PORT`, `HOST`
- `JWT_SECRET`
- `DEFAULT_ADMIN_PASSWORD`
- `NODE_ENV`
- `LOG_LEVEL`

## Scripts

- `npm run dev` - Start development server with hot reload
- `npm run build` - Build TypeScript to JavaScript
- `npm start` - Start production server
- `npm run migrate` - Run database migrations
- `npm run lint` - Lint code
- `npm run format` - Format code with Prettier

## Project Structure

```
backend/
├── src/
│   ├── config/          # Configuration files (database, etc.)
│   ├── middleware/      # Express middleware (auth, error handling)
│   ├── models/          # Database models
│   ├── routes/          # API route handlers
│   ├── services/        # Business logic
│   │   ├── syslog/      # Syslog server and parser
│   │   ├── parser/      # Log parser engine
│   │   ├── rules/       # Detection rules engine
│   │   └── alerting/    # Alert management
│   ├── utils/           # Utility functions (logger, validation)
│   ├── scripts/         # Maintenance scripts (migrations)
│   ├── app.ts           # Express app setup
│   └── server.ts        # Server entry point
├── migrations/          # SQL migration files
└── package.json
```

## API Endpoints

**Complete API documentation:** See [../API.md](../API.md) for detailed request/response examples.

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user profile
- `PUT /api/auth/me/password` - Change password
- `POST /api/auth/cleanup` - Cleanup expired sessions (admin)

### Logs
- `GET /api/logs/raw` - List raw syslog messages
- `GET /api/logs/parsed` - List parsed logs
- `GET /api/logs/parsed/search` - Search logs by field

### Parsers
- `GET /api/parsers` - List all parsers
- `GET /api/parsers/:id` - Get single parser
- `POST /api/parsers` - Create parser
- `PUT /api/parsers/:id` - Update parser
- `DELETE /api/parsers/:id` - Delete parser
- `POST /api/parsers/:id/test` - Test saved parser
- `POST /api/parsers/test` - Test parser config (without saving)

### Detection Rules
- `GET /api/rules` - List all rules
- `GET /api/rules/:id` - Get single rule
- `POST /api/rules` - Create rule
- `PUT /api/rules/:id` - Update rule
- `DELETE /api/rules/:id` - Delete rule

### Alerts
- `GET /api/alerts` - List alerts (with filtering)
- `GET /api/alerts/statistics` - Get alert statistics
- `GET /api/alerts/:id` - Get alert details
- `PUT /api/alerts/:id` - Update alert status
- `DELETE /api/alerts/:id` - Delete alert

### Users
- `GET /api/users` - List users (admin only)
- `GET /api/users/:id` - Get single user (admin only)
- `POST /api/users` - Create user (admin only)
- `PUT /api/users/:id` - Update user (admin only)
- `DELETE /api/users/:id` - Delete user (admin only)

### Settings
- `GET /api/settings/retention` - Get retention settings (admin)
- `PUT /api/settings/retention` - Update retention (admin)
- `POST /api/settings/retention/cleanup` - Manual cleanup (admin)
- `GET /api/settings/retention/stats` - Get cleanup stats (admin)
- `GET /api/settings/syslog` - Get syslog server settings
- `PUT /api/settings/syslog` - Update syslog settings (admin)

### Log Shippers
- `GET /api/shippers` - List all shippers
- `GET /api/shippers/:id` - Get shipper with full config
- `POST /api/shippers` - Create shipper
- `PUT /api/shippers/:id` - Update shipper
- `DELETE /api/shippers/:id` - Delete shipper
- `GET /api/shippers/:id/sources` - Get shipper sources
- `POST /api/shippers/:id/sources` - Add source
- `PUT /api/shippers/sources/:sourceId` - Update source
- `DELETE /api/shippers/sources/:sourceId` - Delete source
- `GET /api/shippers/:id/volumes` - Get volume mounts
- `POST /api/shippers/:id/volumes` - Add volume
- `DELETE /api/shippers/volumes/:volumeId` - Delete volume
- `GET /api/shippers/:id/activity` - Get activity log
- `POST /api/shippers/:id/regenerate-key` - Regenerate API key
- `POST /api/shippers/register` - Shipper registration (public)
- `GET /api/shippers/config/:api_key` - Get config (public)

## Default Admin User

After running migrations, a default admin user is created:

- **Username**: `admin`
- **Password**: `changeme` (or value from `DEFAULT_ADMIN_PASSWORD` env var)

**IMPORTANT**: Change this password immediately after first login!

## Built-in Parsers

The system includes 5 built-in parsers:

1. **SSH Authentication** - Parse SSH login attempts
2. **Apache/Nginx Access Log** - Parse web server access logs
3. **Linux Sudo** - Parse sudo command execution
4. **Generic Syslog** - Fallback for standard syslog format
5. **JSON Parser** - Parse JSON-formatted logs

## Built-in Detection Rules

The system includes 6 built-in detection rules:

1. **SSH Brute Force Attempt** - Multiple failed SSH logins
2. **Direct Root SSH Login** - Root user SSH access
3. **Sudo Privilege Escalation** - Sudo to root commands
4. **Web Path Scanning** - Multiple 404 errors (directory scanning)
5. **Web Server Errors** - Multiple HTTP 5xx errors
6. **Multiple Failed Authentication** - Generic failed login detection

## Development

```bash
# Install dependencies
npm install

# Run in development mode (auto-reload)
npm run dev

# Lint code
npm run lint

# Format code
npm run format
```

## Production Deployment

```bash
# Build TypeScript
npm run build

# Set NODE_ENV=production in .env

# Run migrations
npm run migrate

# Start server
npm start
```

## License

MIT
