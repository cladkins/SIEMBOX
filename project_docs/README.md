# SIEM Box - Developer Documentation

This directory contains developer and internal documentation for SIEM Box. This documentation is intended for developers, system architects, and technical contributors working on the SIEM Box project.

## 📋 Documentation Organization

**`project_docs/`** = Developer/Internal Documentation
- Architecture documentation
- Development setup guides
- API specifications
- Database schemas
- Internal project management

**`docs/`** = User-facing Documentation
- Installation guides
- User manuals
- Configuration guides
- Troubleshooting guides

## 🏗️ Architecture Documentation

### Core Architecture
- [**Service Architecture**](architecture/SERVICE_ARCHITECTURE.md) - Complete system architecture, component interactions, data flow patterns, deployment topologies, and scalability considerations
- [**Database Schema**](architecture/DATABASE_SCHEMA.md) - Comprehensive database design, table structures, relationships, indexes, and performance optimization
- [**API Reference**](architecture/API_REFERENCE.md) - Complete REST API documentation with endpoints, authentication, request/response formats, and SDK examples

### Frontend Development
- [**Frontend Development Guide**](frontend/DEVELOPMENT.md) - Complete frontend development setup, build configuration, deployment, and advanced technical details

### Project Management
- [**Project Plan**](project-management/Project%20Plan.md) - Comprehensive project plan with phased development approach
- [**Development Workflow**](project-management/DEVELOPMENT_WORKFLOW.md) - Git workflow and development process guidelines
- [**Project Compliance Verification**](project-management/PROJECT_COMPLIANCE_VERIFICATION.md) - Project completion status and compliance verification

## 🔧 Development Resources

### Getting Started
1. **Architecture Overview**: Start with [Service Architecture](architecture/SERVICE_ARCHITECTURE.md) to understand the system design
2. **Database Design**: Review [Database Schema](architecture/DATABASE_SCHEMA.md) for data models and relationships
3. **API Integration**: Use [API Reference](architecture/API_REFERENCE.md) for endpoint documentation
4. **Frontend Development**: See [Frontend Development Guide](frontend/DEVELOPMENT.md) for build setup and technical details

### Key Technical Concepts

#### System Components
- **Frontend**: React 18 + TypeScript + Material-UI
- **Backend**: FastAPI + Python 3.11 + SQLAlchemy
- **Database**: PostgreSQL 15 with advanced features
- **Message Queue**: Redis for background tasks
- **Log Processing**: Fluent Bit for multi-source ingestion

#### Architecture Patterns
- **Microservices-inspired**: Clear separation of concerns
- **Event-driven**: Asynchronous processing with message queues
- **API-first**: RESTful APIs with OpenAPI specifications
- **Container-native**: Docker-based deployment

## 📊 Technical Specifications

### Performance Characteristics
- **Log Processing**: 1000+ logs/minute sustained throughput
- **Detection Engine**: Real-time rule evaluation with <100ms latency
- **Database**: Optimized for time-series log data with partitioning
- **API**: Sub-second response times for most operations

### Scalability Targets
- **Single Node**: <1K logs/day (homelab environments)
- **Multi-Node**: 1K-10K logs/day (medium environments)
- **Kubernetes**: 10K+ logs/day (large environments)

## 🔍 Development Guidelines

### Code Organization
- **Backend**: `/backend/app/` - FastAPI application structure
- **Frontend**: `/frontend/src/` - React application structure
- **Database**: `/backend/migrations/` - Database schema migrations
- **Configuration**: `/backend/config/` - Default configurations

### API Development
- All endpoints documented in [API Reference](architecture/API_REFERENCE.md)
- OpenAPI 3.0 specifications available at `/docs` endpoint
- JWT-based authentication with role-based access control
- Comprehensive error handling and validation

### Database Development
- PostgreSQL with UUID primary keys
- JSONB for flexible log storage
- Strategic indexing for query performance
- Audit trails for all changes

## 🚀 Deployment Architecture

### Container Strategy
- **Multi-stage builds** for optimized image sizes
- **Health checks** for all services
- **Service discovery** through Docker networking
- **Volume persistence** for data storage

### Environment Support
- **Development**: Docker Compose with hot reloading
- **Production**: Docker Compose or Kubernetes deployment
- **Testing**: Isolated test environments with fixtures

## 📈 Project Status

**Current Version**: 1.0.0 (Production Ready)

### Completed Features
- ✅ Core log ingestion and parsing
- ✅ Real-time detection engine
- ✅ Multi-channel notification system
- ✅ Web-based management interface
- ✅ Vulnerability scanning integration
- ✅ Comprehensive API coverage

### Development Roadmap
- 🔄 Advanced analytics and reporting
- 🔄 Machine learning-based anomaly detection
- 🔄 Enhanced threat intelligence integration
- 🔄 Advanced correlation rules

## 🤝 Contributing

### Development Setup
1. Review [Service Architecture](architecture/SERVICE_ARCHITECTURE.md) for system understanding
2. Set up development environment using Docker Compose
3. Consult [API Reference](architecture/API_REFERENCE.md) for integration patterns
4. Follow database schema guidelines in [Database Schema](architecture/DATABASE_SCHEMA.md)
5. For frontend development, see [Frontend Development Guide](frontend/DEVELOPMENT.md)

### Code Standards
- **Python**: PEP 8 compliance with Black formatting
- **TypeScript**: ESLint + Prettier configuration
- **SQL**: Consistent naming conventions and indexing strategies
- **Documentation**: Comprehensive inline and external documentation

---

**Last Updated**: January 7, 2025  
**Documentation Version**: 2.0  
**Target Audience**: Developers, System Architects, Technical Contributors

For user-facing documentation, see [`docs/README.md`](../docs/README.md).