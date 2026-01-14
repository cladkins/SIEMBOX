# SIEMBox Reference Documentation

This directory contains comprehensive reference documentation for SIEMBox parsers and detection rules.

## Contents

### [PARSERS.md](./PARSERS.md)
Complete parser reference guide including:
- Parser syntax and configuration
- Community-contributed parsers
- Built-in parser examples for common log sources:
  - Reverse proxies (Nginx, Traefik, Caddy, NPM)
  - Authentication services (Authelia, Authentik, Keycloak)
  - Applications (Nextcloud, Pi-hole, Vaultwarden)
  - Network devices (UniFi, pfSense)
  - System logs (SSH, systemd)
- Creating custom parsers
- Parser priority and matching order

### [RULES.md](./RULES.md)
Detection rules reference including:
- Rule syntax and configuration
- Built-in detection rules by category:
  - Authentication (SSH brute force, password spray, etc.)
  - Proxy security (SQL injection, XSS, path traversal)
  - Access control (unauthorized access, privilege escalation)
  - Infrastructure (port scans, high-volume requests)
  - Data exfiltration (large transfers, unusual uploads)
  - Application security (file uploads, API abuse)
  - IoT devices (compromise detection, unusual traffic)
  - Password managers (failed logins, new device access)
- Creating custom detection rules
- Rule conditions and thresholds
- Alert severity levels

## Quick Links

- **Main Documentation**: [../../README.md](../../README.md)
- **API Reference**: [../../API.md](../../API.md)
- **Deployment Guide**: [../../DEPLOYMENT.md](../../DEPLOYMENT.md)
- **Troubleshooting**: [../operations/TROUBLESHOOTING.md](../operations/TROUBLESHOOTING.md)

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines on contributing parsers and detection rules to the community.
