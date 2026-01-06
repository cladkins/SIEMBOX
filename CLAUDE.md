# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

SIEM BOX is a production-ready, self-hosted Security Information and Event Management (SIEM) solution designed for homelab environments. It now uses a **lightweight ingestion architecture** where agents send structured JSON events directly to a FastAPI backend backed by PostgreSQL.

## Key Architecture Components

### Lightweight Architecture
- **Log Processing**: Agents (Fluent Bit, Vector, custom scripts, etc.) normalize events and call `/api/v1/logs/ingest`
- **Backend**: FastAPI application with async SQLAlchemy for ingestion, detection, alerting, and API/UI support
- **Database**: PostgreSQL stores processed logs, alerts, detection rules, and configuration
- **Frontend**: React 18 with TypeScript, Vite build system
- **Storage**: Processed logs live in PostgreSQL; no external pipeline required

### Service Structure
- **Frontend**: React app at `frontend/` with comprehensive UI for all operations
- **Backend**: FastAPI app at `backend/` with modular service architecture
- **Ingestion Agents**: Example configurations in `ingestion_agents/` for Fluent Bit/Vector/custom scripts
- **Database**: PostgreSQL with async SQLAlchemy ORM

## Development Commands

### Docker Deployment (Primary)
```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# View service logs
docker logs siembox-backend
docker logs siembox-frontend
docker logs siembox-postgres

# Service health checks
curl http://localhost:8000/api/v1/health/
```

### Backend Development
```bash
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Run backend in development mode
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Run tests
pytest tests/
pytest tests/ -v  # verbose output
pytest tests/ --cov=app --cov-report=html  # with coverage

# Database migrations (if needed)
alembic upgrade head
```

### Frontend Development
```bash
cd frontend
npm install

# Development server
npm run dev

# Build for production
npm run build

# Run tests
npm test
npm run test:watch
npm run test:coverage
npm run test:ci

# Linting
npm run lint
```

### Utility Scripts
```bash
# Setup script for first-time deployment
./setup.sh

# Deployment testing
./test_deployment.sh

# Reset Docker volumes (destroys all data)
./scripts/reset-volumes.sh
```

## Important Implementation Details

### Log Flow
1. Agents parse raw logs and POST structured events to `POST /api/v1/logs/ingest`
2. Backend stores each event in `processed_logs`, immediately runs detection, and creates alerts if needed
3. Frontend queries `/api/v1/logs`, `/api/v1/dashboard/*`, `/api/v1/alerts/*` for visualization and triage

### Deprecated Endpoints
- `/api/v1/parsing/*` – Returns HTTP 410 with guidance; parsing occurs upstream before ingestion.

### Service Ports
- **3000**: Frontend web interface
- **8000**: Backend API
- **5432**: PostgreSQL database

### Database Schema
- **alerts**: Security alerts and incidents
- **detection_rules**: Custom security rules
- **users**: Authentication and authorization
- **vulnerabilities**: Vulnerability scan results
- **notification_channels**: Alert notification configuration

### Key Services (backend/app/services/)
- **detection_service.py**: Real-time security rule evaluation
- **alert_service.py**: Alert lifecycle management
- **notification_service.py**: Multi-channel alerting
- **vulnerability_service.py**: Network and container scanning
- **auth_service.py**: User authentication

## Configuration Notes

### Environment Variables
- Check `backend/.env.example` for configuration options
- Database URL, secret keys, and debug settings

### Ingestion Agent Configuration
- Example Fluent Bit/Vector configurations live under `ingestion_agents/`
- Agents should output structured JSON (with `timestamp`, `hostname`, `source_ip`, etc.) to `/api/v1/logs/ingest`
- Include any parsed fields in the payload’s `fields` object so detection rules can act on them
- Tests: Use `curl` or custom scripts to post sample events to the ingestion endpoint during development

### Frontend Configuration
- Vite proxy setup for API calls in `vite.config.ts`
- WebSocket support for real-time updates

## Testing Guidelines

### Backend Testing
- Use `pytest` for all backend tests
- Tests located in `backend/tests/`
- Database tests use async SQLAlchemy patterns
- Mock external services (notification providers, vulnerability scanners) as needed

### Frontend Testing
- Jest for unit tests
- React Testing Library for component tests
- Playwright for E2E tests
- Coverage reports available

### Integration Testing
- Use `test_deployment.sh` for end-to-end validation
- Health checks for all services
- Log ingestion and retrieval testing

## Security Considerations

### Authentication
- JWT-based authentication system
- Default credentials: admin/admin123 (MUST change in production)
- Session management with refresh tokens

### Network Security
- Privileged container mode for network scanning
- Source authentication should be handled by the agent (e.g., API tokens, TLS); backend expects trusted traffic
- CORS configuration for frontend integration

### Data Protection
- Processed logs (with structured fields) are stored directly in PostgreSQL
- Sensitive data handling in notification services
- Secure communication between services

## Common Development Patterns

### Service Layer Pattern
All business logic is in service classes with async methods:
```python
# Example service usage
from app.services.detection_service import DetectionService

async def process_log(log_data: dict):
    detection_service = DetectionService()
    await detection_service.run_detection(log_data)
```

### API Response Patterns
- Use Pydantic models for request/response validation
- Consistent error handling with HTTP status codes
- Async route handlers throughout

### Frontend State Management
- Zustand for global state management
- React Query for server state and caching
- WebSocket integration for real-time updates

## Troubleshooting

### Common Issues
1. **PostgreSQL version compatibility**: Run `./scripts/reset-volumes.sh` if needed
2. **Ingestion connectivity**: Verify your agent can reach `/api/v1/logs/ingest` and that the backend logs show received events
3. **Frontend build issues**: Ensure Node.js version compatibility
4. **Permission errors**: Check Docker volume permissions

### Health Checks
- Backend: `GET /api/v1/health/`
- Database: `GET /api/v1/health/database`
- Backend: `http://localhost:8000/api/v1/health`

### Log Analysis
- Backend logs: `docker logs siembox-backend`
- Database queries: Enable SQLAlchemy logging in development
- Backlog processing: Inspect backend logs and the `processed_logs` table

This is a production-ready SIEM solution with comprehensive documentation. Focus on the Pattern B architecture when making changes and ensure all modifications maintain the dual-destination log processing flow.
