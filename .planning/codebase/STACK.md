# Technology Stack

## Overview

SIEMBox is a full-stack TypeScript application using modern web technologies, containerized with Docker, and powered by PostgreSQL for data persistence.

## Core Languages

- **TypeScript 5.3.3** - Primary language for backend and frontend
  - Backend target: ES2022, CommonJS modules
  - Frontend target: ES2020, ESNext modules
  - Strict mode enabled across all projects
- **Bash** - Log shipper scripting
- **SQL** - PostgreSQL database schema and queries

## Runtime Environments

### Backend
- **Node.js 20** (Alpine-based)
  - Runtime: CommonJS modules
  - Dev tool: tsx 4.7.0 (TypeScript executor with watch mode)
  - Package manager: npm

### Frontend
- **Modern browser runtime** (ES2020+)
  - Built with Vite for optimized production bundles
  - Served via Nginx in production

## Frameworks

### Backend Framework
- **Express 4.18.2** - Web application framework
  - REST API architecture
  - Middleware-based request processing
  - ~10,353 lines of TypeScript code

### Frontend Framework
- **Vue.js 3.4.5** - Progressive JavaScript framework
  - Composition API pattern
  - Single File Components (.vue)
  - TypeScript integration
  - ~5,798 lines of TypeScript and Vue code

## Key Libraries & Tools

### Backend Dependencies
**Security & Authentication:**
- bcrypt 5.1.1 - Password hashing (10 salt rounds)
- jsonwebtoken 9.0.2 - JWT token generation/verification
- express-rate-limit 7.1.5 - Rate limiting middleware

**API & Middleware:**
- cors 2.8.5 - Cross-Origin Resource Sharing
- express-async-errors 3.1.1 - Async error handling
- express-validator 7.3.1 - Request validation

**Database:**
- pg 8.11.3 - PostgreSQL client (node-postgres)
- Connection pooling (max 20 connections)

**Logging:**
- winston 3.11.0 - Structured logging
  - JSON format in production
  - File transports: error.log, combined.log

**Network Scanning:**
- node-nmap 4.0.0 - Network discovery and port scanning
  - Requires nmap binary (installed in Docker image)

**Utilities:**
- dotenv 16.3.1 - Environment variable management
- js-yaml 4.1.0 - YAML parsing for rules

### Frontend Dependencies
**UI Framework:**
- Element Plus 2.5.1 - Vue 3 component library
  - @element-plus/icons-vue 2.3.1

**State Management:**
- Pinia 2.1.7 - Official Vue.js state store
- Vue Router 4.2.5 - Official routing library

**HTTP Client:**
- axios 1.6.4 - Promise-based HTTP client
  - Request/response interceptors
  - JWT token injection

**Charting:**
- Chart.js 4.4.1 - JavaScript charting
- vue-chartjs 5.3.0 - Vue wrapper for Chart.js

**Utilities:**
- date-fns 3.0.6 - Date manipulation
- js-yaml 4.1.0 - YAML parsing

## Build Tools

### Frontend Build
- **Vite 5.0.11** - Next-generation build tool
  - @vitejs/plugin-vue 5.0.2
  - Fast HMR (Hot Module Replacement)
  - Manual code-splitting optimization

### Backend Build
- **TypeScript Compiler (tsc)** - Compiles to JavaScript
  - Output: /backend/dist directory
  - Source maps enabled

### Code Quality
- **ESLint 8.56.0** - Linting
  - @typescript-eslint/eslint-plugin 6.15.0
  - eslint-plugin-vue 9.19.2
- **Prettier 3.1.1** - Code formatting
  - Single quotes, 2-space indent, 100 char width

## Testing

### Backend Testing
- **Jest 29.7.0** - Testing framework
- **ts-jest 29.1.1** - TypeScript preprocessor
- Test commands: test, test:watch, test:coverage

### Frontend Testing
- **Vitest** - Testing framework (Vite-native)
- **@vue/test-utils** - Vue component testing

## Database

**PostgreSQL 15 (Alpine-based)**
- pg driver with connection pooling
- JSONB columns for flexible log storage
- Extensions: pgcrypto (for hashing)
- Features used:
  - JSONB operators for log queries
  - Array types for tags
  - Foreign keys for referential integrity
  - Triggers for timestamp updates
  - Indexes for performance

## Web Server

**Nginx (Alpine-based)** - Production frontend server
- Serves Vue.js SPA
- Reverse proxy for /api requests
- Gzip compression
- Security headers (X-Frame-Options, etc.)
- Asset caching (1 year for static files)

## Container Technology

**Docker** - Application containerization
- Multi-stage builds for backend and frontend
- Alpine-based images for minimal size

**Docker Compose** - Multi-container orchestration
- Services: postgres, backend, frontend
- Network: siembox-network (bridge)
- Volume: postgres-data (persistent storage)

## Development Tools

- **Git** - Version control
- **VS Code** - Recommended IDE (TypeScript support)
- **tsx** - TypeScript execution for development
- **Nodemon** - Auto-restart on file changes

## Network Protocols

- **HTTP/HTTPS** - REST API communication
- **Syslog (RFC 3164/5424)** - Log ingestion
  - UDP port 514
  - TCP port 514
- **PostgreSQL Wire Protocol** - Database communication

## Package Sizes

- Frontend node_modules: 231MB
- Backend node_modules: 123MB
- Total TypeScript/Vue files: ~7,316 (including dependencies)

## Version Requirements

- Node.js: 20+ (Alpine-based)
- PostgreSQL: 15+
- Docker: 20+
- Docker Compose: 2+

## Notable Technology Choices

1. **TypeScript Everywhere** - Type safety across stack
2. **Alpine Linux** - Minimal container images
3. **JSONB Storage** - Flexible schema for diverse logs
4. **Composition API** - Modern Vue.js patterns
5. **Winston Logging** - Structured, production-ready logs
6. **Pinia State** - Official Vue state management
7. **Express Middleware** - Modular request processing
