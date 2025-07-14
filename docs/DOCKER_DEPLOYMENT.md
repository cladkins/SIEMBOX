# SIEM Box - Docker Deployment Guide

This guide covers the complete containerized deployment of SIEM Box using Docker Compose.

## Overview

SIEM Box uses **Pattern B** architecture with the following containerized services:
- **Frontend**: React application served by Nginx (Port 3000)
- **Backend**: FastAPI application with direct Cribl integration (Port 8000)
- **Database**: PostgreSQL 15 for metadata, alerts, and configuration (Port 5432)
- **Log Processing**: Cribl Stream with dual-destination architecture (Ports 9000, 10514, 8088)
- **Vulnerability Scanning**: Integrated Nmap and Trivy scanning capabilities
- **Notification Service**: Multi-channel alerting (Email, Discord, Webhooks)

### Pattern B Architecture Benefits
- **Real-time Processing**: Direct backend-to-Cribl integration via HTTP destination
- **Dual Storage**: HTTP for real-time + filesystem for long-term storage
- **Scalability**: Cribl handles high-throughput log processing independently
- **Flexibility**: Easy addition of new log sources without backend changes

## Quick Start

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+

### Deployment

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd SIEMBox
   ```

2. **Start all services**:
   ```bash
   docker-compose up -d
   ```

3. **Access the application**:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Cribl Stream UI: http://localhost:9000

### Default Credentials
- Username: `admin`
- Password: `admin123`

## Service Details

### Frontend Service
- **Image**: Custom React build with Nginx
- **Port**: 3000 → 80 (container)
- **Features**:
  - Production-optimized React build
  - Nginx reverse proxy for API calls
  - WebSocket support for real-time features
  - Security headers and gzip compression
  - Health check endpoint: `/health`

### Backend Service
- **Image**: Custom FastAPI application
- **Port**: 8000 → 8000 (container)
- **Features**:
  - FastAPI with comprehensive API documentation
  - **Pattern B Integration**: Direct Cribl Stream API communication with JWT authentication
  - Sophisticated detection engine with 20+ security rules
  - Multi-channel notification system (Email, Discord, Webhooks)
  - Real-time alert processing and management
  - Vulnerability scanning integration (Nmap, Trivy)
  - PostgreSQL database for metadata and alerts (no raw logs)
  - JWT-based authentication system
  - WebSocket support for real-time updates
  - CORS enabled for frontend communication
  - Comprehensive health check endpoints

### Database Service
- **Image**: postgres:14-alpine
- **Port**: 5432 → 5432 (container)
- **Features**:
  - **Pattern B Optimized**: Stores metadata, alerts, and configuration (no raw logs)
  - Automatic database initialization with migration support
  - Health checks for service dependencies
  - Reduced storage requirements due to Pattern B architecture

### Log Processing Service (Cribl Stream)
- **Image**: cribl/cribl:4.2.1
- **Ports**:
  - 9000 → 9000 (Web UI)
  - 10514 UDP/TCP → 10514 UDP/TCP (Syslog input)
  - 8088 → 8088 (HTTP input)
- **Features**:
  - **Dual Destination Architecture**:
    - HTTP destination: Real-time processing via `/api/v1/logs/cribl`
    - Filesystem destination: Long-term storage to `/opt/cribl/data/SIEMBOX`
  - Advanced, pipeline-based log processing and enrichment
  - Support for multiple data sources (Syslog, HTTP, Docker logs)
  - JWT API authentication for backend integration
  - Persistent configuration and data via volume mounts (`cribl_data`)
  - Web-based configuration UI for pipeline management
  - Health monitoring and comprehensive metrics

## 🎯 Complete Feature Matrix

### Core SIEM Capabilities
| Feature | Status | Description |
|---------|--------|-------------|
| **Log Ingestion** | ✅ Complete | Multi-source log collection via Cribl Stream (syslog, HTTP, Docker) |
| **Log Processing** | ✅ Complete | Cribl Stream pipeline-based processing and enrichment |
| **Real-time Processing** | ✅ Complete | Dual-destination architecture for immediate analysis |
| **Detection Engine** | ✅ Complete | 20+ security rules covering major threat vectors |
| **Alert Management** | ✅ Complete | Full alert lifecycle with status tracking |
| **Notification System** | ✅ Complete | Multi-channel alerts (Email, Discord, Webhooks) |
| **Web Interface** | ✅ Complete | Modern React frontend with real-time updates |
| **API Access** | ✅ Complete | Comprehensive REST API with documentation |
| **Authentication** | ✅ Complete | JWT-based user authentication |
| **Vulnerability Scanning** | ✅ Complete | Network (Nmap) and container (Trivy) scanning |

### Security Coverage
| Attack Vector | Detection Rules | Status |
|---------------|----------------|---------|
| **Authentication Attacks** | SSH brute force, credential stuffing | ✅ Active |
| **Network Security** | Port scanning, firewall evasion | ✅ Active |
| **Web Application Security** | SQL injection, XSS, path traversal | ✅ Active |
| **System Security** | File access monitoring, privilege escalation | ✅ Active |
| **Behavioral Analysis** | Anomaly detection, baseline deviation | ✅ Active |
| **Malware Detection** | Cryptocurrency mining, suspicious processes | ✅ Active |

### Deployment Features
| Component | Status | Description |
|-----------|--------|-------------|
| **Docker Compose** | ✅ Ready | Single-command deployment |
| **Health Checks** | ✅ Active | All services monitored |
| **Data Persistence** | ✅ Active | PostgreSQL with volume persistence |
| **Service Discovery** | ✅ Active | Internal DNS resolution |
| **Load Balancing** | ✅ Ready | Nginx reverse proxy |
| **SSL/TLS Support** | 🔧 Configurable | Ready for certificate deployment |

## Configuration

### Environment Variables

The following environment variables can be configured in `docker-compose.yml`:

#### Backend
- `DATABASE_URL`: PostgreSQL connection string
- `DEBUG`: Enable/disable debug mode
- `LOG_LEVEL`: Logging level (INFO, DEBUG, WARNING, ERROR)
- `SECRET_KEY`: JWT secret key (change in production)
- `CRIBL_API_URL`: Cribl Stream API endpoint (default: http://cribl:9000)
- `CRIBL_API_TOKEN`: JWT token for Cribl API authentication
- `CRIBL_SEARCH_TIMEOUT`: Timeout for Cribl API requests (default: 30)

#### Database
- `POSTGRES_DB`: Database name
- `POSTGRES_USER`: Database user
- `POSTGRES_PASSWORD`: Database password

### Networking

All services communicate through the `siembox-network` bridge network:
- Subnet: 172.20.0.0/16
- Internal DNS resolution between services
- Frontend proxies API calls to backend service

## Management Commands

### View logs
```bash
docker-compose logs -f
```

### Stop services
```bash
docker-compose down
```

### Restart services
```bash
docker-compose restart
```

### Rebuild and restart
```bash
docker-compose up --build -d
```

### Check service status
```bash
docker-compose ps
```

## Health Checks

All services include health checks:
- **Frontend**: HTTP GET to `/health`
- **Backend**: HTTP GET to `/api/v1/health/`
- **Database**: PostgreSQL connection test
- **Cribl**: Process health check

## Data Persistence

The following volumes are created for data persistence:
- `postgres_data`: Database files (metadata, alerts, configuration only)
- `cribl_data`: Cribl Stream data and configuration files
- **Pattern B Storage**: Long-term logs stored in Cribl filesystem destination at `/opt/cribl/data/SIEMBOX`

## Security Considerations

### Production Deployment
1. **Change default credentials** immediately
2. **Update SECRET_KEY** in backend environment
3. **Configure CORS origins** specifically for your domain
4. **Use HTTPS** with proper SSL certificates
5. **Restrict database access** to internal network only
6. **Update default passwords** for all services

### Network Security
- Services communicate only through internal Docker network
- Only necessary ports are exposed to host
- Frontend serves as reverse proxy for API access

## Troubleshooting

### Common Issues

1. **PostgreSQL Version Compatibility**:
   ```bash
   # Error: "FATAL: database files are incompatible with server"
   # This occurs when existing data was created with a different PostgreSQL version
   
   # Solution 1: Reset volumes (DESTROYS ALL DATA)
   docker-compose down
   docker volume rm siembox_postgres_data
   docker-compose up -d
   
   # Solution 2: Use reset script
   ./scripts/reset-volumes.sh
   ```

2. **Port conflicts**:
   ```bash
   # Check if ports are in use
   netstat -tulpn | grep -E ':(3000|8000|5432|5140)'
   ```

3. **Service startup order**:
   - Database must be healthy before backend starts
   - Backend must be healthy before frontend starts
   - Dependencies are configured in docker-compose.yml

4. **Log analysis**:
   ```bash
   # View specific service logs
   docker-compose logs frontend
   docker-compose logs backend
   docker-compose logs postgres
   ```

5. **Database connection issues**:
   ```bash
   # Test database connectivity
   docker-compose exec postgres psql -U siembox -d siembox -c "SELECT 1;"
   ```

### Performance Tuning

1. **Frontend optimization**:
   - Static assets are cached for 1 year
   - Gzip compression enabled
   - Chunked JavaScript bundles

2. **Backend optimization**:
   - Connection pooling for database
   - Async request handling
   - Configurable worker processes

3. **Database optimization**:
   - Proper indexing on log tables
   - Regular VACUUM and ANALYZE
   - Connection pooling

## Development vs Production

### Development
- Use `docker-compose.override.yml` for development-specific settings
- Enable debug mode and verbose logging
- Mount source code volumes for live reloading

### Production
- Disable debug mode
- Use production-grade secrets management
- Implement proper backup strategies
- Configure monitoring and alerting

## Backup and Recovery

### Database Backup
```bash
docker-compose exec postgres pg_dump -U siembox siembox > backup.sql
```

### Database Restore
```bash
docker-compose exec -T postgres psql -U siembox siembox < backup.sql
```

### Volume Backup
```bash
docker run --rm -v siembox_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_backup.tar.gz -C /data .
```

## Monitoring

### Service Health
- All services expose health check endpoints
- Docker Compose monitors service health automatically
- Failed services are automatically restarted

### Log Monitoring
- Centralized logging through Cribl
- Structured JSON logs from backend
- Nginx access and error logs from frontend

## Updates and Maintenance

### Updating Services
1. Pull latest changes from repository
2. Rebuild containers: `docker-compose up --build -d`
3. Verify all services are healthy
4. Test functionality through frontend

### Database Migrations
- Backend automatically handles database schema updates
- Always backup database before major updates
- Test migrations in development environment first

## Support

For issues and questions:
1. Check service logs for error messages
2. Verify all services are healthy
3. Test individual service endpoints
4. Review configuration files for syntax errors

---

**Note**: This deployment is designed for homelab and development environments. For production use, additional security hardening and monitoring should be implemented.