# SIEMBox

Realtime security monitoring and threat detection for your infrastructure. Built with Docker.

## Overview

SIEMBox is a Security Information and Event Management (SIEM) system designed to provide real-time monitoring, threat detection, and security analytics for infrastructure. It's containerized with Docker for easy deployment and management.

## Features

- Syslog collection (TCP/UDP port 5514)
- Sigma-based threat detection
- IP intelligence and geolocation
- VPS security auditing
- Real-time monitoring dashboard
- Comprehensive API for integration

## Technologies

- Docker and Docker Compose
- Web-based dashboard
- Sigma rules for threat detection
- RESTful API
- Database for event storage
- JWT authentication

## Project Structure

- `api/` - Backend API implementation
- `collector/` - Log and event collection components
- `detection/` - Threat detection engine
- `docs/` - Comprehensive documentation
- `frontend/` - Web dashboard interface
- `iplookup/` - IP geolocation and intelligence
- `rules/` - Detection rules and signatures
- `tests/` - Test suite
- `vps-audit/` - VPS security auditing tools

## Installation

1. Clone the repository:
```bash
git clone https://github.com/cladkins/siembox.git
cd siembox
```

2. Initialize rules:
```bash
./init-rules.sh
```

3. Set required environment variables:
```bash
cp .env.example .env
```

4. Start the containers:
```bash
docker-compose up -d
```

5. Access the dashboard at http://localhost:3000

## Configuration

### Required Environment Variables

- DB_PASSWORD - Database password
- JWT_SECRET - API security key
- ENCRYPTION_KEY - Key for sensitive data
- GITHUB_REPOSITORY - Your GitHub repository

### Optional Environment Variables

- IPAPI_KEY - IP-API.com API key
- CROWDSEC_API_KEY - CrowdSec API key

## Documentation

Detailed documentation is available in the `docs` directory:
- System Architecture
- API Reference
- Monitoring Setup
- Backup Procedures
- Performance Tuning
- Security Features

## License

This project is licensed under the MIT License.
