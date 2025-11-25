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

### Health Check
- `GET /health` - Server health status

### Authentication (Coming Soon)
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout

### Logs (Coming Soon)
- `GET /api/logs/raw` - List raw logs
- `GET /api/logs/parsed` - List parsed logs

### Parsers (Coming Soon)
- `GET /api/parsers` - List all parsers
- `POST /api/parsers` - Create parser
- `PUT /api/parsers/:id` - Update parser
- `DELETE /api/parsers/:id` - Delete parser
- `POST /api/parsers/:id/test` - Test parser

### Detection Rules (Coming Soon)
- `GET /api/rules` - List all rules
- `POST /api/rules` - Create rule
- `PUT /api/rules/:id` - Update rule
- `DELETE /api/rules/:id` - Delete rule
- `POST /api/rules/:id/test` - Test rule

### Alerts (Coming Soon)
- `GET /api/alerts` - List alerts
- `GET /api/alerts/:id` - Get alert details
- `PUT /api/alerts/:id` - Update alert
- `DELETE /api/alerts/:id` - Delete alert

### Users (Coming Soon)
- `GET /api/users` - List users (admin only)
- `POST /api/users` - Create user (admin only)
- `PUT /api/users/:id` - Update user (admin only)
- `DELETE /api/users/:id` - Delete user (admin only)

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
