# SIEM Box - User Documentation

Welcome to **SIEM Box** - a self-hosted Security Information and Event Management (SIEM) solution designed for homelab environments.

## 🚀 Quick Start

- **New Users**: Start with the [Docker Deployment Guide](DOCKER_DEPLOYMENT.md)
- **Web Interface**: Access the [Frontend User Guide](frontend/USER_GUIDE.md)
- **Need Help?**: Check the [Troubleshooting Guide](TROUBLESHOOTING.md)

## 📋 Documentation Categories

### 🐳 Deployment & Getting Started
- [Docker Deployment Guide](DOCKER_DEPLOYMENT.md) - Complete containerized deployment instructions
- [Environment Configuration](../.env.example) - Environment variables and configuration options

### 👤 User Guides
- [Frontend User Guide](frontend/USER_GUIDE.md) - Complete web interface usage instructions
- [Frontend Configuration](frontend/CONFIGURATION.md) - Frontend setup and customization options

### 🔧 Configuration & Setup
- [Alert Configuration](alerts/ALERT_CONFIGURATION.md) - Alert setup, management, and notification configuration
- [Detection Rules Guide](detection/DETECTION_GUIDE.md) - Security rule configuration and custom rule creation
- [Parsing Configuration](parsing/PARSING_GUIDE.md) - Log parsing setup and custom parser development

### 🔒 Security & Monitoring
- [Vulnerability Scanning Guide](vulnerability-scanning.md) - Network and container security scanning setup
- [Notification Service Guide](notification-service.md) - Multi-channel notification configuration

### 🐳 Log Source Configuration
- [Log Source Configuration Examples](../ingestion_agents/examples/) - Setup guides for various log sources

## 📖 Documentation by User Type

### 🏠 Homelab Users
**Getting Started:**
1. [Docker Deployment Guide](DOCKER_DEPLOYMENT.md) - Quick setup and deployment
2. [Frontend User Guide](frontend/USER_GUIDE.md) - Using the web interface
3. [Alert Configuration](alerts/ALERT_CONFIGURATION.md) - Setting up security alerts

**Configuration:**
- [Unifi Syslog Setup](../ingestion_agents/examples/unifi-syslog-config.md)
- [OPNsense/pfSense Setup](../ingestion_agents/examples/opnsense-syslog-config.md)
- [Docker Log Collection](../ingestion_agents/examples/docker-logs-config.md)

### 🔧 System Administrators
**Advanced Configuration:**
- [Detection Rules Guide](detection/DETECTION_GUIDE.md) - Custom security rules
- [Parsing Configuration](parsing/PARSING_GUIDE.md) - Custom log parsing
- [Notification Service Guide](notification-service.md) - Advanced alerting setup
- [Vulnerability Scanning Guide](vulnerability-scanning.md) - Security scanning implementation

## 🔍 Quick Reference

### Essential Links
- **Main Repository**: [README.md](../README.md)
- **Deployment Guide**: [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)
- **Web Interface**: http://localhost:3000 (when running)
- **Developer Documentation**: [project_docs/README.md](../project_docs/README.md)

### Key Configuration Files
- **Docker Compose**: [`docker-compose.yml`](../docker-compose.yml)
- **Fluent Bit Config**: [`ingestion_agents/fluent-bit.conf`](../ingestion_agents/fluent-bit.conf)
- **Parser Config**: [`ingestion_agents/parsers.conf`](../ingestion_agents/parsers.conf)

### Default Credentials
- **Username**: `admin`
- **Password**: `admin123`
- **⚠️ Change immediately in production!**

## 🆘 Troubleshooting

### Common Issues
1. **Service Won't Start**: Check [Docker Deployment Guide](DOCKER_DEPLOYMENT.md#troubleshooting)
2. **No Logs Appearing**: Review [Log Source Configuration](../ingestion_agents/examples/)
3. **Frontend Issues**: See [Frontend Configuration](frontend/CONFIGURATION.md)

### Getting Help
- **Documentation Issues**: Check this index for the relevant guide
- **Configuration Problems**: Review the specific configuration guide
- **Technical Questions**: See [Developer Documentation](../project_docs/README.md)

## 📈 Project Status

**Current Status**: Production Ready SIEM Solution

### ✅ Completed Features
- **Core Infrastructure**: Log ingestion, parsing, and storage
- **Detection Engine**: Real-time security rule evaluation
- **Web Interface**: Complete management and monitoring interface
- **Vulnerability Scanning**: Network and container security scanning
- **Notification System**: Multi-channel alerting

### 🔄 Current Focus
- **Advanced Features**: Enhanced analytics and reporting
- **Production Hardening**: Security and performance optimization
- **Documentation**: Continuous improvement and updates

## 🤝 Contributing

Interested in contributing to SIEM Box? Check out the [Developer Documentation](../project_docs/README.md) for technical details and development guidelines.

---

**Last Updated**: January 7, 2025  
**Documentation Version**: 2.0  
**Project Status**: Production Ready

For technical and developer documentation, see [project_docs/README.md](../project_docs/README.md).