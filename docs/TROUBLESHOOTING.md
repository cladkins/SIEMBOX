# SIEM BOX - Troubleshooting Guide

## PostgreSQL Version Compatibility Issues

### Problem
When upgrading or changing PostgreSQL versions, you may encounter the following error:
```
FATAL: database files are incompatible with server
```

This occurs when:
- Existing PostgreSQL data was initialized with version 14
- Docker Compose tries to use PostgreSQL 15 (or different version)
- PostgreSQL cannot read data files from a different major version

### Solution

#### Option 1: Reset Volumes (Recommended for Development)
```bash
# Stop all services
docker-compose down

# Remove the PostgreSQL data volume (DESTROYS ALL DATA)
docker volume rm siembox_postgres_data

# Start services with clean database
docker-compose up -d
```

#### Option 2: Use Reset Script
```bash
# Use the provided reset script
./scripts/reset-volumes.sh
```

#### Option 3: Manual Volume Cleanup
```bash
# Stop services
docker-compose down

# List and remove SIEM BOX volumes
docker volume ls | grep siembox
docker volume rm siembox_postgres_data siembox_fluent_bit_data

# Restart services
docker-compose up -d
```

### Prevention
- Always use the same PostgreSQL major version in production
- Backup data before version changes
- Test version upgrades in development first

## Database Migration Issues

### Problem
Migration scripts failing with "relation does not exist" errors during container startup.

### Root Cause
Migration files were being executed during PostgreSQL initialization, before SQLAlchemy created the base tables.

### Solution
The system now properly handles migrations:
1. PostgreSQL initializes with basic setup
2. Backend application creates base tables via SQLAlchemy
3. Migration scripts run after base tables exist

## Common Service Issues

### Backend Service Fails to Start
**Symptoms:**
- Backend container shows as unhealthy
- Database connection errors in logs

**Solutions:**
1. Check PostgreSQL is healthy: `docker logs siembox-postgres`
2. Verify database credentials match in docker-compose.yml
3. Reset volumes if version compatibility issues exist

### Frontend Not Accessible
**Symptoms:**
- Cannot access http://localhost:3000
- Frontend container not starting

**Solutions:**
1. Check if port 3000 is available: `netstat -tulpn | grep 3000`
2. Verify backend is healthy (frontend depends on backend)
3. Check frontend logs: `docker logs siembox-frontend`

### Fluent Bit Not Collecting Logs
**Symptoms:**
- No logs appearing in the system
- Syslog sources not working

**Solutions:**
1. Check Fluent Bit configuration: `docker logs siembox-fluent-bit`
2. Verify syslog sources are configured to send to port 5140
3. Check network connectivity between sources and SIEM BOX

## Health Check Commands

### Service Status
```bash
# Check all services
docker-compose ps

# Check specific service health
docker logs siembox-backend
docker logs siembox-postgres
docker logs siembox-frontend
docker logs siembox-fluent-bit
```

### API Health
```bash
# Backend API health
curl http://localhost:8000/api/v1/health/

# Frontend accessibility
curl http://localhost:3000/health
```

### Database Connectivity
```bash
# Test database connection
docker-compose exec postgres psql -U siembox -d siembox -c "SELECT 1;"
```

## Recovery Procedures

### Complete System Reset
```bash
# Stop all services
docker-compose down

# Remove all volumes (DESTROYS ALL DATA)
docker volume rm siembox_postgres_data siembox_fluent_bit_data siembox_vulnerability_data siembox_trivy_cache

# Remove any orphaned containers
docker container prune

# Start fresh
docker-compose up -d
```

### Backup and Restore
```bash
# Backup database
docker-compose exec postgres pg_dump -U siembox siembox > backup.sql

# Restore database
docker-compose exec -T postgres psql -U siembox siembox < backup.sql
```

## Performance Issues

### High Resource Usage
1. Check log retention settings
2. Adjust Fluent Bit buffer settings
3. Monitor PostgreSQL performance
4. Consider log rotation policies

### Slow Response Times
1. Check database indexes
2. Monitor container resource limits
3. Verify network connectivity
4. Review log volume and processing load

## Getting Help

### Log Collection
When reporting issues, include:
```bash
# Service status
docker-compose ps

# Service logs
docker-compose logs --tail=100

# System resources
docker stats --no-stream
```

### Configuration Verification
```bash
# Verify configuration files
docker-compose config

# Check environment variables
docker-compose exec backend env | grep -E "(DATABASE|DEBUG|LOG_LEVEL)"
```

---

**Note:** Always backup your data before performing troubleshooting steps that involve volume removal or service resets.