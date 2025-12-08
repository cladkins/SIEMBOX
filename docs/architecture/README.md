# SIEMBox Architecture Documentation

This directory contains architecture, design decisions, and technical specifications for SIEMBox.

## Contents

### [DOCUMENTATION-ARCHITECTURE.md](./DOCUMENTATION-ARCHITECTURE.md)
Documentation structure and organization strategy:
- Documentation hierarchy and categories
- File organization principles
- Navigation and cross-referencing
- Maintenance guidelines

### [HOMELAB-THREAT-MODEL.md](./HOMELAB-THREAT-MODEL.md)
Security threat model and architecture:
- Threat landscape for homelab environments
- Attack surfaces and vectors
- Security controls and mitigations
- Defense-in-depth strategy
- Risk assessment methodology

### [PARSER-RULE-IMPLEMENTATION-SPEC.md](./PARSER-RULE-IMPLEMENTATION-SPEC.md)
Technical specification for parser and rule implementation:
- Parser engine architecture
- Rule evaluation engine design
- Field extraction and normalization
- Condition matching algorithms
- Performance considerations

### [VAULTWARDEN-PARSER-IMPLEMENTATION.md](./VAULTWARDEN-PARSER-IMPLEMENTATION.md)
Implementation details for Vaultwarden password manager parser:
- Log format analysis
- Field extraction patterns
- Event categorization
- Integration with detection rules
- Testing and validation

## Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                        SIEMBox                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐      ┌──────────────┐                   │
│  │   Frontend   │──────│    Backend   │                   │
│  │   (Vue.js)   │      │  (Node.js)   │                   │
│  └──────────────┘      └───────┬──────┘                   │
│                                 │                           │
│                     ┌───────────┼───────────┐              │
│                     │           │           │              │
│               ┌─────▼────┐ ┌───▼───┐ ┌────▼────┐          │
│               │  Syslog  │ │ Parser│ │  Rules  │          │
│               │  Server  │ │Engine │ │ Engine  │          │
│               └─────┬────┘ └───┬───┘ └────┬────┘          │
│                     │          │          │               │
│                     └──────────┼──────────┘               │
│                                │                           │
│                         ┌──────▼───────┐                  │
│                         │  PostgreSQL  │                  │
│                         │   Database   │                  │
│                         └──────────────┘                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Log Ingestion**: Syslog messages arrive via UDP/TCP port 514
2. **Parsing**: Parser engine matches and extracts fields from logs
3. **Storage**: Parsed logs stored in PostgreSQL with JSONB fields
4. **Detection**: Rule engine evaluates logs against detection rules
5. **Alerting**: Matching events trigger alerts with severity levels
6. **Visualization**: Frontend displays logs, alerts, and analytics

### Key Design Principles

- **Modularity**: Parsers and rules are independent, reusable components
- **Extensibility**: Easy to add new parsers and detection rules
- **Performance**: PostgreSQL with JSONB for flexible, fast queries
- **Simplicity**: Self-contained Docker deployment, no external dependencies
- **Security**: Role-based access control, JWT authentication

## Related Documentation

- **Deployment**: [../../DEPLOYMENT.md](../../DEPLOYMENT.md)
- **Security Guide**: [../../SECURITY.md](../../SECURITY.md)
- **API Reference**: [../../API.md](../../API.md)
- **Parser Reference**: [../reference/PARSERS.md](../reference/PARSERS.md)
- **Rules Reference**: [../reference/RULES.md](../reference/RULES.md)

## Technology Stack

### Backend
- **Runtime**: Node.js + TypeScript
- **Framework**: Express.js
- **Database**: PostgreSQL 15 with JSONB
- **Authentication**: JWT tokens
- **Syslog**: Custom UDP/TCP server
- **Logging**: Winston

### Frontend
- **Framework**: Vue.js 3 (Composition API)
- **UI Library**: Element Plus
- **Build Tool**: Vite
- **State Management**: Vue Composition API + Pinia
- **HTTP Client**: Axios

### Infrastructure
- **Containerization**: Docker + Docker Compose
- **Reverse Proxy**: Nginx (production recommendation)
- **Log Shipper**: Alpine-based universal log forwarder

## Contributing to Architecture

When proposing architectural changes:
1. Document the problem and proposed solution
2. Consider performance, security, and maintainability impacts
3. Update relevant architecture documentation
4. Ensure backward compatibility or provide migration path
5. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for submission process
