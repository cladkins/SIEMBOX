# SIEMBox Security Hardening Guide

Comprehensive security guidelines for deploying and maintaining a secure SIEMBox installation.

## Table of Contents

- [Security Overview](#security-overview)
- [Pre-Deployment Security](#pre-deployment-security)
- [Network Security](#network-security)
- [Authentication & Authorization](#authentication--authorization)
- [TLS/SSL Configuration](#tlsssl-configuration)
- [Database Security](#database-security)
- [Container Security](#container-security)
- [Application Security](#application-security)
- [Log Security](#log-security)
- [Monitoring & Alerting](#monitoring--alerting)
- [Incident Response](#incident-response)
- [Security Checklist](#security-checklist)
- [Compliance Considerations](#compliance-considerations)

---

## Security Overview

SIEMBox is a security monitoring tool that handles sensitive log data. Proper hardening is critical to prevent it from becoming a security liability.

### Threat Model

**What SIEMBox Protects:**
- Detection of security incidents across your infrastructure
- Centralized log storage and analysis
- Alert generation for suspicious activity

**What Attackers Target:**
- Syslog port (514) for log injection/DoS
- Web interface for unauthorized access
- API for data exfiltration
- Database for log tampering/deletion
- Log shippers for pivoting to other systems

### Security Principles

1. **Defense in Depth:** Multiple layers of security controls
2. **Least Privilege:** Minimal permissions required for operation
3. **Secure by Default:** Safe configuration out-of-the-box
4. **Fail Securely:** Errors don't expose sensitive data
5. **Audit Everything:** Comprehensive logging of security events

---

## Pre-Deployment Security

### Initial Setup

**CRITICAL: Change Default Credentials Immediately**

```bash
# 1. Update .env file before first deployment
nano .env
```

**Required Changes:**
```bash
# Database - Use strong random password (32+ characters)
DB_PASSWORD=$(openssl rand -base64 32)

# JWT Secret - Use cryptographically random string
JWT_SECRET=$(openssl rand -base64 64)

# Admin Password - Strong password (16+ characters)
DEFAULT_ADMIN_PASSWORD="YourSecurePasswordHere123!@#"
```

`DEFAULT_ADMIN_PASSWORD` is used once: it is the password of the `admin`
account the first start creates (when the database has no users yet). Changing
it later has no effect. Whatever it is, even a strong one, the first sign-in
must replace it (see [Required password changes](#required-password-changes)),
because the value stays in plain text in `.env`, in the compose environment and
in `docker inspect`.

**Password Requirements:**
- Minimum 16 characters (recommended)
- Mix of uppercase, lowercase, numbers, symbols
- Never use dictionary words
- Unique per installation
- Store securely (password manager)

### Environment File Security

```bash
# Set restrictive permissions on .env file
chmod 600 .env
chown root:root .env

# Verify it's not in git
git check-ignore .env  # Should return .env

# Never commit .env to version control
grep -r "DB_PASSWORD\|JWT_SECRET" .git/  # Should return nothing
```

### Secrets & Credential Encryption (v2)

SIEMBox encrypts sensitive secrets at rest (scanner credentials and the AI
builder's provider API key) using `CREDENTIAL_ENCRYPTION_KEY`.

```bash
# Generate a 64-char hex key (32 bytes)
CREDENTIAL_ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
```

- Set this **before** storing any credential or AI key from the UI. Without it,
  the backend cannot persist a UI-entered key (it will tell you to set the key or
  use an env var instead).
- Treat it like `JWT_SECRET`: unique per installation, `chmod 600` in `.env`,
  never committed. **Rotating it invalidates previously stored secrets**, which
  must be re-entered.
- As an alternative to storing the AI key encrypted, you can inject it at runtime
  via `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` and never persist it.
- No API route returns a provider key stored from the UI, not even to an admin.
  These are the AI builder, AI Analyst and AI Triage keys, the AbuseIPDB and OTX
  keys, and the Have I Been Pwned key. The settings pages report a key as
  configured or not, and `GET /api/settings` (admin-only) withholds them. An
  encrypted key together with `CREDENTIAL_ENCRYPTION_KEY` gives back the
  plaintext, so protect database backups like the `.env` file.
- A stored AI key only goes to the provider and base URL it was saved for: they
  are stored next to it, encrypted together with a hash of the key, and SIEMBox
  sends it nowhere else. Changing the provider or base URL of the AI builder,
  AI Analyst or AI Triage settings while a key is stored needs the key again
  in the same request (the API answers `400` otherwise and saves nothing), or
  removes the stored key. A key
  one of these configs inherits (the analyst uses the AI builder's, triage the
  analyst's) is only sent where the config it comes from sends it. So an admin,
  or a stolen admin session, can use the stored keys and replace them, but
  can't make the backend send them to another host. See
  [A saved key only goes where it was saved for](API.md#a-saved-key-only-goes-where-it-was-saved-for).
- A key set with `OPENAI_API_KEY` is not stored, so it isn't bound: it goes to
  whichever OpenAI base URL the settings name, and an admin can point that at
  another host. Store the OpenAI key in the UI instead if that matters. A key
  set with `ANTHROPIC_API_KEY` only goes to `api.anthropic.com`. The AbuseIPDB,
  OTX and Have I Been Pwned keys only go to those services' own hosts.

### AI Builder & Catalog Trust (v2)

- **AI builder data flow.** When you generate a parser or detection, the log
  sample or threat description you submit is sent to the configured provider.
  With **Anthropic** or **OpenAI** this leaves your network; with **Ollama** it
  stays on a host you control. Choose the provider per your data-sensitivity
  policy, and avoid pasting sensitive log content to a third-party provider —
  use a local Ollama endpoint for fully on-prem operation. The AI endpoints are
  admin-only.
- **Catalog source.** Catalog installs come from a GitHub repository (default
  `cladkins/siembox-parsers`). Pin `SIEMBOX_CATALOG_REPO` / `SIEMBOX_CATALOG_REF`
  to a source you trust. Every parser/detection is schema-validated and
  self-tested before it is stored, but a parser is still code-adjacent data — only
  install from sources you trust.

### Dependency Updates

Keep the container images current — `git pull && docker compose -f
compose.prod.yaml pull && up -d` ships the latest dependency fixes. Dependabot is
enabled on the repository; review and merge its security PRs promptly.

### Host System Hardening

**Update System:**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y
sudo apt install unattended-upgrades

# Enable automatic security updates
sudo dpkg-reconfigure -plow unattended-upgrades
```

**Disable Unnecessary Services:**
```bash
# List running services
systemctl list-units --type=service --state=running

# Disable unnecessary services
sudo systemctl disable <service-name>
sudo systemctl stop <service-name>
```

**Enable SELinux/AppArmor:**
```bash
# Ubuntu (AppArmor)
sudo aa-status  # Check status
sudo systemctl enable apparmor
sudo systemctl start apparmor

# RHEL/CentOS (SELinux)
getenforce  # Should return 'Enforcing'
```

---

## Network Security

### Firewall Configuration

**UFW (Ubuntu/Debian):**
```bash
# Reset firewall (careful on remote systems!)
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (if managing remotely)
sudo ufw allow 22/tcp comment 'SSH'

# Allow HTTPS only (recommended)
sudo ufw allow 443/tcp comment 'HTTPS SIEMBox'

# Restrict syslog to internal network only
sudo ufw allow from 10.0.0.0/8 to any port 514 comment 'Syslog Internal'
sudo ufw allow from 172.16.0.0/12 to any port 514 comment 'Syslog Internal'
sudo ufw allow from 192.168.0.0/16 to any port 514 comment 'Syslog Internal'

# Enable firewall
sudo ufw enable

# Verify rules
sudo ufw status numbered
```

**iptables (Advanced):**
```bash
# Flush existing rules
sudo iptables -F
sudo iptables -X

# Default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Allow HTTPS
sudo iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Allow syslog from internal network only
sudo iptables -A INPUT -p udp -s 192.168.0.0/16 --dport 514 -j ACCEPT
sudo iptables -A INPUT -p tcp -s 192.168.0.0/16 --dport 514 -j ACCEPT

# Rate limit syslog to prevent DoS
sudo iptables -A INPUT -p udp --dport 514 -m limit --limit 100/s --limit-burst 200 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 514 -j DROP

# Drop invalid packets
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Save rules
sudo netfilter-persistent save
```

### Network Segmentation

**Recommended Network Architecture:**

```
┌─────────────────────────────────────────────────────────┐
│ DMZ (Internet-Facing)                                   │
│  ┌──────────────────┐                                   │
│  │ Reverse Proxy    │  Port 443 HTTPS Only              │
│  │ (nginx/traefik)  │────────────────► Internet         │
│  └────────┬─────────┘                                   │
│           │ TLS Termination                             │
└───────────┼─────────────────────────────────────────────┘
            │
            │ Internal Only
┌───────────┼─────────────────────────────────────────────┐
│ Management Network (10.0.1.0/24)                        │
│           ▼                                              │
│  ┌──────────────────┐                                   │
│  │ SIEMBox          │  Port 8420 (Frontend)             │
│  │ Frontend/Backend │  Port 8421 (API)                  │
│  │ PostgreSQL       │  Port 5432 (DB)                   │
│  └──────────────────┘  Port 514 (Syslog)                │
│           ▲                                              │
└───────────┼─────────────────────────────────────────────┘
            │
            │ Syslog Only (UDP/TCP 514)
┌───────────┼─────────────────────────────────────────────┐
│ Production Network (10.0.10.0/24)                       │
│           │                                              │
│  ┌────────┴────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ Log Shippers    │  │ Servers     │  │ Firewalls   │ │
│  │                 │  │             │  │             │ │
│  └─────────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Key Points:**
- SIEMBox should NEVER be directly exposed to the internet
- Use reverse proxy for HTTPS termination in DMZ
- Restrict syslog port (514) to internal networks only
- Separate management and production networks
- Use VLANs or separate physical networks

### Port Security Matrix

| Port | Protocol | Exposure | Purpose | Restrict To |
|------|----------|----------|---------|-------------|
| 22 | TCP | External* | SSH Management | Admin IPs only |
| 80 | TCP | Internal | HTTP (redirect to 443) | Reverse proxy only |
| 443 | TCP | External | HTTPS Web UI/API | Reverse proxy |
| 514 | UDP/TCP | Internal | Syslog ingestion | Internal networks |
| 8420 | TCP | Internal | Frontend (dev) | Reverse proxy only |
| 8421 | TCP | Internal | Backend API | Frontend container |
| 5432 | TCP | Internal | PostgreSQL | Backend container |

*Only if managing remotely. Use bastion host or VPN for production.

### Syslog Security

**Prevent Log Injection:**
```bash
# Rate limiting (iptables)
iptables -A INPUT -p udp --dport 514 -m limit --limit 100/s --limit-burst 200 -j ACCEPT

# Source IP whitelisting
iptables -A INPUT -p udp --dport 514 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p udp --dport 514 -j DROP
```

**Syslog TLS (Recommended for production):**

SIEMBox currently uses plaintext syslog. For sensitive environments, use rsyslog/syslog-ng with TLS on shippers:

```bash
# On log shippers, configure rsyslog with TLS
# /etc/rsyslog.conf
$DefaultNetstreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
*.* @@siembox-server:6514
```

**Current Limitation:** SIEMBox doesn't support TLS syslog natively. Use stunnel or TLS-terminating proxy if required.

---

## Authentication & Authorization

### User Management

**Admin Account Security:**
```bash
# 1. The first sign-in must change the initial admin password: until it does,
#    the session gets 403 PASSWORD_CHANGE_REQUIRED from every other route.
#    Via API, with the token of that first sign-in:
curl -X PUT http://localhost:8421/api/auth/me/password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "currentPassword": "changeme",
    "newPassword": "YourStrongPasswordHere123!@#"
  }'
# Every session is signed out: sign in again with the new password.
```

**Create Least-Privilege Accounts:**
```bash
# Create analyst account (not admin)
curl -X POST http://localhost:8421/api/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "analyst1",
    "email": "analyst@company.com",
    "password": "SecurePassword123!",
    "role": "analyst",
    "enabled": true
  }'

# Create read-only viewer
curl -X POST http://localhost:8421/api/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "viewer1",
    "email": "viewer@company.com",
    "password": "SecurePassword123!",
    "role": "viewer",
    "enabled": true
  }'
```

### Role-Based Access Control (RBAC)

Four roles, each including the ones before it. The API checks the role on every
route (a role that may not make a call gets `403`), and the UI hides or disables
what a role can't use. The full permission table is in
[User Management](../guides/USER-MANAGEMENT.md#permission-table); every route and
the roles it allows are listed in `backend/src/routes/routeInventory.test.ts`,
which the test suite checks against the running API.

| Role | Permissions |
|------|-------------|
| **admin** | Full system access: users, every settings area, Endpoints (EDR), deleting alerts, the AI builders, Sigma import, Content Pack installs, shipper keys |
| **operator** | Everything an analyst can do, plus vulnerability, container, scheduled and Log Discovery scans, and managing log shippers (operators see shipper API keys) |
| **analyst** | Everything a viewer can do, plus alert triage, the AI Analyst, creating, editing, installing and deleting parsers and detection rules, asset inventory edits and discovery scans |
| **viewer** | Read-only: can view logs, alerts, parsers, rules and shippers, but cannot create, edit or delete anything; changes only its own password and MFA |

Reading `/api/settings` is admin-only too: other roles get `403` there, except
`GET /api/settings/syslog` (the syslog host and port that shippers send to).
Other areas' routes still show their own non-secret settings to every role, such
as the notification and Digital Risk switches and the Log Discovery scan scope.
`GET /api/ai/chat/health` tells every role only whether the AI Analyst is
configured; its provider, model and base URL are in the admin-only
`GET /api/settings/ai-chat`.

No route returns a stored provider API key (AI, AbuseIPDB, OTX, Have I Been
Pwned) to anyone, and a stored AI key is only sent to the provider and base URL
it was saved for; an admin can still point a key set with `OPENAI_API_KEY` at
another host (see
[Secrets & Credential Encryption](#secrets--credential-encryption-v2)). Two other
kinds of stored secret are shown to the roles that manage them:
- Each shipper's syslog API key, to admins and operators (`GET /api/shippers`
  and `GET /api/shippers/:id`). The key lets whoever holds it act as that
  shipper, so give the operator role only to people you'd trust with every
  shipper.
- Notification channel secrets (Slack webhook URL, ntfy token, SMTP password),
  to admins (`GET /api/notifications/channels`).

**Best Practices:**
- Use admin role only for initial setup and user management
- Daily operations should use analyst accounts
- Dashboards/reports use viewer accounts
- Give the operator role only to the people who run scans or manage shippers
- Disable accounts immediately when employees leave
- Review user accounts monthly

### Session Security

**Session Settings:**
- Session duration: 24 hours (configurable in code)
- Expired sessions are removed hourly (the `sign-in-housekeeping` job)
- A password change, or an admin's password reset, signs the account out
  everywhere and forgets its recognized browsers

**Session Management:**
```bash
# Remove expired sessions now (admin only; the hourly job does this too)
curl -X POST http://localhost:8421/api/auth/cleanup \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Sign one user out everywhere: reset their password on the Users page, or
docker exec siembox-backend node dist/scripts/auth-admin.js reset-password <username>

# Monitor active sessions (check database)
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT s.user_id, u.username, s.expires_at, s.created_at
   FROM sessions s
   JOIN users u ON s.user_id = u.id
   WHERE s.expires_at > NOW();"
```

### Multi-Factor Authentication (Future)

**Status:** Not currently supported

**Roadmap:**
- TOTP (Time-based One-Time Password) support
- WebAuthn/FIDO2 hardware keys
- SSO integration (SAML, OAuth)

**Workaround:** Use VPN or bastion host with MFA as additional layer.

---

## TLS/SSL Configuration

### Reverse Proxy with Let's Encrypt (Recommended)

**Using nginx:**

```bash
# Install nginx and certbot
sudo apt install nginx certbot python3-certbot-nginx

# Create nginx config for SIEMBox
sudo nano /etc/nginx/sites-available/siembox
```

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name siembox.company.com;

    return 301 https://$server_name$request_uri;
}

# HTTPS configuration
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name siembox.company.com;

    # SSL certificates (managed by certbot)
    ssl_certificate /etc/letsencrypt/live/siembox.company.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/siembox.company.com/privkey.pem;

    # Strong SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Everything, the API included, goes to SIEMBox's web UI container, which
    # forwards /api to the backend itself. Use the host's LAN address, not
    # localhost: Docker presents loopback clients of a published port as its
    # network gateway, an address SIEMBox never trusts.
    location / {
        proxy_pass http://192.168.1.10:8420;   # this host's LAN address
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # Append, never replace: SIEMBox takes the client from the entry
        # this proxy adds.
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (if needed in future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Long-running requests (the AI builder)
        proxy_read_timeout 300s;
    }

    # Rate limiting (the matching zone goes in the http block:
    #   limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;)
    limit_req zone=api_limit burst=20 nodelay;

    # Access logs
    access_log /var/log/nginx/siembox-access.log;
    error_log /var/log/nginx/siembox-error.log;
}
```

Then tell SIEMBox to believe this proxy's `X-Forwarded-For`, keeping the
bundled frontend in the list, and redeploy (`docker compose up -d`; a plain
restart keeps the old environment):

```bash
# .env
TRUSTED_PROXIES=frontend,192.168.1.10
```

Don't send `/api` straight to port 8421 from here: direct callers on 8421 are
identified by their TCP address, so every user would share the proxy's. Check
the result as an admin with `GET /api/admin/client-address` (see DEPLOYMENT.md,
"Client addresses and reverse proxies").

```bash
# Enable site and get certificate
sudo ln -s /etc/nginx/sites-available/siembox /etc/nginx/sites-enabled/
sudo nginx -t  # Test configuration
sudo certbot --nginx -d siembox.company.com
sudo systemctl restart nginx

# Auto-renewal is handled by certbot timer
sudo systemctl status certbot.timer
```

### Using Traefik (Alternative)

```yaml
# docker-compose.yml additions
services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=false"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.myresolver.acme.tlschallenge=true"
      - "--certificatesresolvers.myresolver.acme.email=admin@company.com"
      - "--certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./letsencrypt:/letsencrypt"
    networks:
      - siembox-network

  frontend:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.siembox.rule=Host(`siembox.company.com`)"
      - "traefik.http.routers.siembox.entrypoints=websecure"
      - "traefik.http.routers.siembox.tls.certresolver=myresolver"
      - "traefik.http.services.siembox.loadbalancer.server.port=80"

  backend:
    environment:
      # Believe Traefik's X-Forwarded-For (resolved through Docker DNS on
      # siembox-network); keep the bundled frontend in the list.
      TRUSTED_PROXIES: frontend,traefik
```

### Self-Signed Certificates (Dev/Internal Only)

**NEVER use self-signed certs in production - Use Let's Encrypt (free)**

```bash
# Generate self-signed certificate (1 year validity)
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout /etc/ssl/private/siembox-selfsigned.key \
  -out /etc/ssl/certs/siembox-selfsigned.crt \
  -subj "/C=US/ST=State/L=City/O=Company/CN=siembox.local"

# Use in nginx config
ssl_certificate /etc/ssl/certs/siembox-selfsigned.crt;
ssl_certificate_key /etc/ssl/private/siembox-selfsigned.key;
```

---

## Database Security

### PostgreSQL Hardening

**Update docker-compose.yml:**

```yaml
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: ${DB_NAME:-siembox}
      POSTGRES_USER: ${DB_USER:-siembox}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      # Security settings
      POSTGRES_INITDB_ARGS: "--auth-host=scram-sha-256"
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./postgres.conf:/etc/postgresql/postgresql.conf:ro
    command: postgres -c config_file=/etc/postgresql/postgresql.conf
    # Remove external port exposure (internal only)
    # ports:
    #   - "5432:5432"  # REMOVE THIS LINE
    networks:
      - siembox-network
    restart: unless-stopped
    shm_size: 256MB  # Shared memory for performance
```

**Custom PostgreSQL Configuration (postgres.conf):**

```ini
# Connection Settings
listen_addresses = '*'
max_connections = 100
superuser_reserved_connections = 3

# Authentication
password_encryption = scram-sha-256

# Security
ssl = off  # Handled by container network isolation
log_connections = on
log_disconnections = on
log_duration = off
log_hostname = off

# Performance
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 128MB

# WAL Settings
wal_level = replica
max_wal_size = 1GB
min_wal_size = 80MB

# Logging
log_destination = 'stderr'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_age = 1d
log_rotation_size = 100MB
log_line_prefix = '%m [%p] %u@%d '
log_timezone = 'UTC'

# Statement Logging (security auditing)
log_statement = 'ddl'  # Log all DDL statements
log_min_duration_statement = 1000  # Log slow queries (>1s)
```

### Database Access Control

**Restrict Database Access:**
```bash
# Inside PostgreSQL container
docker exec -it siembox-postgres psql -U siembox -d siembox

-- Revoke public schema permissions
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO siembox;

-- Ensure only siembox user has access
SELECT usename, usesuper FROM pg_user;

-- Create read-only user for reporting (optional)
CREATE USER siembox_readonly WITH PASSWORD 'readonly_password_here';
GRANT CONNECT ON DATABASE siembox TO siembox_readonly;
GRANT USAGE ON SCHEMA public TO siembox_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO siembox_readonly;
```

### Database Encryption

**Encryption at Rest:**
```bash
# Use encrypted volume for PostgreSQL data
# Option 1: LUKS encrypted partition
sudo cryptsetup luksFormat /dev/sdb1
sudo cryptsetup open /dev/sdb1 postgres_data
sudo mkfs.ext4 /dev/mapper/postgres_data
sudo mount /dev/mapper/postgres_data /var/lib/docker/volumes/postgres-data

# Option 2: Docker volume plugin with encryption
docker plugin install rexray/ebs REXRAY_PREEMPT=true EBS_ENCRYPTED=true
```

**Backup Encryption:**
```bash
# Encrypt backups with GPG
docker exec siembox-postgres pg_dump -U siembox siembox \
  | gzip \
  | gpg --symmetric --cipher-algo AES256 \
  > siembox-backup-$(date +%Y%m%d).sql.gz.gpg

# Restore encrypted backup
gpg --decrypt siembox-backup-20251130.sql.gz.gpg \
  | gunzip \
  | docker exec -i siembox-postgres psql -U siembox siembox
```

### Regular Database Auditing

```sql
-- Check for suspicious activity
SELECT usename, datname, application_name, client_addr, backend_start
FROM pg_stat_activity
WHERE usename != 'siembox' OR client_addr IS NOT NULL;

-- Review login attempts
SELECT * FROM pg_stat_database WHERE datname = 'siembox';

-- Check for unauthorized schema changes
SELECT schemaname, tablename, tableowner FROM pg_tables
WHERE schemaname = 'public';
```

---

## Container Security

### Docker Hardening

**Enable Docker Content Trust:**
```bash
# Verify image signatures
export DOCKER_CONTENT_TRUST=1

# Build images with signature
docker build --disable-content-trust=false -t siembox-backend:latest ./backend
```

**Run Containers with Security Options:**

Update `docker-compose.yml`:

```yaml
services:
  backend:
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined  # Or custom seccomp profile
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Required for port 514
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
    user: "1000:1000"  # Run as non-root

  postgres:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - DAC_OVERRIDE
      - SETUID
      - SETGID
    tmpfs:
      - /run
      - /tmp

  frontend:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp
      - /var/cache/nginx
      - /var/run
```

### Container Network Isolation

```yaml
# docker-compose.yml
networks:
  siembox-network:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.enable_icc: "false"  # Disable inter-container communication
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### Image Security Scanning

```bash
# Scan images for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image siembox-backend:latest

# Use Snyk
snyk container test siembox-backend:latest

# Anchore Engine
anchore-cli image add siembox-backend:latest
anchore-cli image wait siembox-backend:latest
anchore-cli image vuln siembox-backend:latest all
```

### Resource Limits

```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
      nproc:
        soft: 32768
        hard: 32768

  postgres:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 1G
```

---

## Application Security

### CORS Configuration

**Same-origin by default.** With `CORS_ORIGIN` empty (the default in both
compose files and `.env.example`) the API sends no CORS headers at all, so a
web page on another origin can't read its answers, and a browser won't send it
a JSON request or one with an `Authorization` header (the preflight gets an
empty `204` with no allow headers). The web UI needs no CORS: its nginx serves
it and proxies `/api` on the same origin, as the Vite dev server does in
development. Shippers, endpoint agents, scripts and `curl` aren't browsers and
are unaffected.

**Why it matters.** The API authenticates with a Bearer token, not a cookie.
With `CORS_ORIGIN=*`, any page a user on your network opens could use their
browser to script sign-in attempts against port 8421 (password spraying from
inside the network, past any firewall rule that keeps the internet out) and
read the answers of every call that needs no login.

**Only when a page of yours on another origin must call the API**, list exactly
its origin(s), comma-separated (`scheme://host[:port]`, no path, no wildcard):

```bash
# .env
CORS_ORIGIN=https://dash.example.com,http://localhost:5173
```

Listed origins get their own origin back in `Access-Control-Allow-Origin` (with
`Vary: Origin`); every other origin still gets nothing. An entry that isn't an
exact origin is ignored with a warning in the backend log. `CORS_ORIGIN=*`
still allows every origin, and the backend logs a warning about it at every
start. Details: DEPLOYMENT.md, "Browser access from other origins (CORS)".

What CORS does not stop: a page can still make a browser send a request that
needs no preflight (a plain form post) and never see the answer. A sign-in
sent that way is counted by sign-in protection like any other failure.

### Rate Limiting

**Current Implementation** (request limits in memory, per client address;
reset when the backend restarts):
- General: `API_RATE_LIMIT_MAX` (default 1000) requests per 15 minutes per
  address across `/api`. A `429` is JSON (`code: "RATE_LIMITED"`) with
  `Retry-After`.
- Sign-in: not a request limit but [sign-in protection](#sign-in-protection)
  (below), counted in Postgres.
- EDR agent routes (30000, `EDR_AGENT_RATE_MAX`) and HTTP log pushes (6000,
  `SHIPPER_LOG_PUSH_MAX`) have their own limits and skip the general one when
  they carry `X-Agent-ID` / `X-Shipper-ID` with the route's own method. Agent
  enrollment counts toward the general limit. The Pwned Passwords check allows
  30 per 15 minutes.
- Bodies sent to `/api/auth/*` are capped at 16 kB (`413` above that).

### Sign-in Protection

Failed sign-ins pause further attempts instead of locking accounts (details:
[API.md, "Sign-in Protection"](API.md#sign-in-protection); settings:
DEPLOYMENT.md, "Sign-in protection"):

- **Keys.** Each wrong password counts against the account from that network
  (pauses after 5), the network for any username (20; while paused it holds
  back a username only for 15 minutes after it failed from there, so one
  attacker on a shared address can't lock out everyone behind it, and the
  guesses it lets through never extend its pause) and the account from every
  network (20, `LOGIN_MAX_FAILURES_PER_ACCOUNT=0` turns it off); wrong
  MFA codes against the user's MFA key (5), wrong current passwords on a
  password change against their own key (5). A pause starts at 30 seconds and
  doubles with every further failure, up to 15, 30 or 60 minutes; a streak ends
  24 hours after its last failure.
- **Recognized browsers** sign in through a key of their own, so an attacker
  can slow down sign-in from new browsers but cannot lock an account's owner
  out of a browser they used before. A token only chooses the counter; it never
  skips the password or MFA. Only its sha256 is stored.
- **Checked before bcrypt, atomically**: a burst of parallel guesses gets
  exactly the threshold of password checks, and an attempt while paused is
  refused without one.
- **No enumeration**: unknown usernames, wrong passwords and disabled accounts
  with a wrong password get the same answer after the same work (one bcrypt
  compare, against a dummy hash when the user doesn't exist). Unknown usernames
  are stored only as a hash.
- **MFA**: a 6-digit code is only tried as TOTP and each works once; recovery
  codes are consumed in one statement. Roughly 35 guesses a day get through
  the MFA key, about a 1-in-10,000 chance of a hit per day.
- **Recovery**: wait; use a browser that signed in before; Users -> Unlock or
  Settings -> Sign-in protection; the `auth-admin` command line
  (TROUBLESHOOTING.md, "Locked out of SIEMBox"); or `LOGIN_PROTECTION=off`
  briefly.

Throttling can't stop a correct first guess of the default `admin` /
`changeme`; [required password changes](#required-password-changes) (below)
make the owner replace it at the first sign-in. Pages on other origins can no
longer try passwords through a user's browser and read the answer:
`CORS_ORIGIN` is same-origin only unless you set it (see [CORS
Configuration](#cors-configuration)).

The address can't be forged: the web UI's nginx reaches the backend over a
unix socket on a volume only those two containers mount, and a direct caller
on port 8421 is its TCP address, whatever `X-Forwarded-For` it sends. Only the
proxies in `TRUSTED_PROXIES` (default `frontend`) may name a client. See
DEPLOYMENT.md, "Client addresses and reverse proxies".

### Required password changes

An account signed in with a password it didn't choose itself, or with the
default one everyone knows, can do nothing except change it:

- **When.** The `admin` account the first start creates (with
  `DEFAULT_ADMIN_PASSWORD`, `changeme` when unset); any account found on the
  default `changeme` (admin accounts at every start, so an upgrade catches
  them before anyone signs in; every account at a correct sign-in with it);
  an account an admin created or whose password an admin set, unless they
  turned "Require a password change" off; and every `auth-admin
  reset-password`. `users.must_change_password`, with the reason and since
  when, holds it.
- **Enforced by the backend on every route.** `authenticate`, which every
  route that takes a login runs, answers a restricted session with `403
  {"code": "PASSWORD_CHANGE_REQUIRED", "reason": ...}` before any role check.
  Only `GET /api/auth/me`, `PUT /api/auth/me/password` and `POST
  /api/auth/logout` use the gate that lets it through; the route inventory
  test (`backend/src/routes/routeInventory.test.ts`) checks that list, and
  that every other route, including ones added later, refuses. The flag is
  read from the account on every request, so it restricts the account's
  existing sessions at once. There is no setting that turns it off.
- **Not weakened elsewhere.** MFA is still asked at sign-in before the
  restricted session is issued; MFA can't be enrolled or turned off while
  restricted (so someone holding a known default password can't bind an
  authenticator to the account). The change still needs the current password,
  counts wrong ones against the account's password-change key (5, then a
  pause), and signs every session out and forgets every recognized browser,
  so nothing earned with the old password outlives it. The new password, the
  lifted restriction and the sign-out are one transaction on the locked
  account (an admin's reset too), and a sign-in only gets its session and
  browser while the password it checked is still the account's: a sign-in
  with the old password still running when it changes gets `401`, and a
  restricted session's requests while the change finishes are refused, never
  let through. `changeme` in any letter case is refused as a new password
  everywhere.
- **Not affected:** log shippers, endpoint agents and enrollment tokens. They
  use API keys, never a sign-in session.
- **Seen.** A `siembox-auth` alert (critical for an admin) and a startup
  warning when an account is found on `changeme` (a disabled one, which
  can't sign in, gets a warning of its own and no alert until it is enabled
  again); audit rows
  `auth.password.change_required`, plus `passwordChangeRequired` on
  `auth.login.success`, `user.created` and `user.password_reset`, and `forced`
  on `auth.password.changed`. Refused requests are not audited one by one.
- **Recovery** stays possible through `auth-admin reset-password` (which sets
  a new temporary password) and, as the database owner's last resort, SQL
  (TROUBLESHOOTING.md).

**Residual risk.** This makes the *owner* replace the default at their next
sign-in; it does not stop someone who gets there first. Whoever signs in with
`changeme` first chooses the new password and takes the account. On an upgrade
the window is short (the account is restricted, the warning and the alert fire
at the first start); on a fresh install, keep ports 8420 and 8421 off untrusted
networks until you have signed in, or set a `DEFAULT_ADMIN_PASSWORD` only you
know before the first start.

**Enhanced Rate Limiting:**

Add to nginx config:
```nginx
# /etc/nginx/nginx.conf
http {
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;

    server {
        location /api/auth/login {
            limit_req zone=login_limit burst=3 nodelay;
        }

        location /api {
            limit_req zone=api_limit burst=20 nodelay;
        }
    }
}
```

### Input Validation

SIEMBox uses parameterized SQL queries to prevent injection. Verify:

```bash
# Check for SQL injection vulnerabilities
grep -r "query(" backend/src/ | grep -v "\$[0-9]"  # Should find none

# Ensure all inputs are validated
grep -r "req.body\|req.query\|req.params" backend/src/routes/
```

### Security Headers

Added via nginx reverse proxy (see TLS section above):
- `Strict-Transport-Security` - Force HTTPS
- `X-Frame-Options` - Prevent clickjacking
- `X-Content-Type-Options` - Prevent MIME sniffing
- `X-XSS-Protection` - Enable XSS filter
- `Referrer-Policy` - Control referrer information

---

## Log Security

### Protecting Log Data

**Log Encryption in Transit:**
- Use TLS for syslog (via rsyslog/syslog-ng with TLS)
- Or use log shipper over VPN tunnel

**Log Retention Security:**
```sql
-- Prevent log tampering by revoking delete permissions
REVOKE DELETE ON raw_logs FROM siembox;
REVOKE DELETE ON parsed_logs FROM siembox;

-- Only cleanup service should delete (via admin connection)
```

**Sensitive Data in Logs:**
```yaml
# Create parser to redact sensitive data
# Example: Credit card numbers
name: Redact Credit Cards
parser_type: regex
pattern: '(?<before>.*?)(?<cc>\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})(?<after>.*)'
field_mappings:
  1: before
  2: cc_redacted  # Map to different field
  3: after

# Then use detection rule to alert on sensitive data
name: Sensitive Data in Logs
conditions:
  - field: raw_message
    operator: regex
    value: '\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}'
alert:
  title: Credit card number detected in logs
  description: Possible PCI compliance violation
```

### Audit Logging

**Log All Administrative Actions:**

SIEMBox automatically logs:
- Sign-in, in `audit_logs` with the client address and how the request
  arrived (`details.via`): `auth.login.success`, `auth.login.failure` (reason
  `unknown_user`, `bad_password`, `disabled`, `mfa_invalid`, `mfa_replay`,
  `password_changed` for a right password changed while it was checked; an
  unknown username is a NULL user plus `details.usernameHash`),
  `auth.login.paused` (once per pause, never per refused attempt),
  `auth.logout`, `auth.unlock`, `auth.browser.revoked`
- Account changes: `auth.password.changed` (`forced: true` and the reason for
  a required change), `auth.password.change_failed`,
  `auth.password.change_required` (an account found on the default password,
  `details.by` `startup` or `sign-in`), `auth.mfa.enabled`,
  `auth.mfa.disabled`, `auth.mfa.recovery_used`, `user.created`,
  `user.updated`, `user.deleted`, `user.password_reset` (`user.created` and
  `user.password_reset` carry `passwordChangeRequired`, as does
  `auth.login.success` for a restricted session)
- Parser/rule changes
- Shipper configuration updates

`auth.login.failure` rows are kept `AUTH_FAILURE_AUDIT_RETENTION_DAYS` (default
90; `0` keeps them). Refused attempts are summed up in one backend log line
every 5 minutes ("Sign-in attempts refused while paused").

**Review Audit Logs:**
```bash
# Sign-in events of the last day
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT timestamp, action, user_id, ip_address, details FROM audit_logs
   WHERE action LIKE 'auth.%' AND timestamp > NOW() - INTERVAL '1 day' ORDER BY id DESC LIMIT 100;"

# Backend logs
docker logs siembox-backend | grep -E "User logged in|Login failed|Sign-in paused|User (created|deleted)"

# Database audit trail
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT * FROM shipper_activity ORDER BY timestamp DESC LIMIT 100;"
```

---

## Monitoring & Alerting

### System Monitoring

**Monitor Critical Metrics:**
```bash
# CPU/Memory usage
docker stats siembox-backend siembox-postgres siembox-frontend

# Disk space (critical for log storage)
df -h /var/lib/docker/volumes/

# Network connections
netstat -tuln | grep -E "514|8420|8421|5432"

# Failed sign-ins (log lines carry the client address and the reason)
docker logs siembox-backend | grep "Login failed" | wc -l
```

**Automated Monitoring with Prometheus:**

```yaml
# docker-compose.yml addition
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"
    networks:
      - siembox-network

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3002:8420"
    volumes:
      - grafana-data:/var/lib/grafana
    networks:
      - siembox-network
```

### Security Event Detection

**Attacks on SIEMBox's own sign-in raise alerts** (source `siembox-auth`, no
rule needed; `AUTH_ALERTS=off` turns them off). They appear on the Alerts page
and go to the notification channels like any alert (Settings -> Notifications:
the default minimum severity is high):

| Alert | Severity |
|-------|----------|
| A network's sign-in pause starts | medium |
| An existing account's pause from new browsers starts | high (critical for an admin) |
| A user's MFA codes are paused (their password was right each time) | critical |
| A new browser signs in while the account is being paused | high |
| A sign-in succeeds after 5 or more failures in a row | medium |
| A recognized browser is forgotten after 20 failures | high |
| More than 100 failed checks in 10 minutes, across everything | high (at most once an hour) |

Each is raised once per streak of failures (its `event_id` names the trigger,
a hash of the key and when the streak started). The network-pause and
success-after-failures alerts, which anyone can set off cheaply (a new network,
or their own wrong-then-right sign-ins), are capped at 20 an hour together; the
others need an existing account or browser and are never capped, so a flood of
cheap alerts can't hide an attack on an admin.

### Health Checks

**Docker Health Checks:**

```yaml
services:
  backend:
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8421/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  postgres:
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER:-siembox}"]
      interval: 10s
      timeout: 5s
      retries: 5

  frontend:
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80"]
      interval: 30s
      timeout: 10s
      retries: 3
```

**Check Health Status:**
```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

---

## Incident Response

### Incident Response Plan

**Preparation:**
1. Document all admin credentials securely
2. Maintain offline backups
3. Have rollback procedures documented
4. Keep emergency contact list

**Detection:**
1. Monitor security alerts from SIEMBox itself
2. Watch for unusual login patterns
3. Check for unauthorized configuration changes
4. Review audit logs daily

**Containment:**
```bash
# Immediately isolate SIEMBox
sudo ufw default deny incoming
sudo ufw allow from <your-ip> to any port 22

# Stop all services
docker-compose down

# Create forensic backup
docker run --rm -v siembox_postgres-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/postgres-forensic-$(date +%Y%m%d-%H%M%S).tar.gz /data
```

**Eradication:**
```bash
# Review all user accounts
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT * FROM users WHERE enabled = true;"

# Disable suspicious accounts
curl -X PUT http://localhost:8421/api/users/<user-id> \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"enabled": false}'

# Rotate all credentials
# 1. Change database password
# 2. Regenerate JWT secret
# 3. Force all users to change passwords
# 4. Regenerate shipper API keys
```

**Recovery:**
```bash
# Restore from backup
docker-compose down
docker volume rm siembox_postgres-data
docker volume create siembox_postgres-data

# Restore database
cat backup_20251130.sql | docker exec -i siembox-postgres psql -U siembox siembox

# Restart services
docker-compose up -d

# Verify integrity
docker-compose logs -f
```

**Post-Incident:**
1. Review all logs for indicators of compromise
2. Document timeline and actions taken
3. Update security controls to prevent recurrence
4. Conduct post-mortem review
5. Update incident response procedures

### Forensic Data Collection

```bash
# Collect all logs
docker logs siembox-backend > backend-$(date +%Y%m%d).log 2>&1
docker logs siembox-postgres > postgres-$(date +%Y%m%d).log 2>&1
docker logs siembox-frontend > frontend-$(date +%Y%m%d).log 2>&1

# Export database for analysis
docker exec siembox-postgres pg_dump -U siembox siembox > forensic-dump-$(date +%Y%m%d).sql

# Collect system logs
journalctl -u docker > docker-journal-$(date +%Y%m%d).log
```

---

## Security Checklist

### Pre-Deployment Checklist

- [ ] Set a `DEFAULT_ADMIN_PASSWORD` only you know, or kept 8420/8421 off untrusted networks until the first sign-in
- [ ] Generated strong random JWT_SECRET (64+ characters)
- [ ] Generated strong random DB_PASSWORD (32+ characters)
- [ ] Verified .env file has 600 permissions
- [ ] Confirmed .env is in .gitignore
- [ ] Updated system packages
- [ ] Configured firewall (UFW/iptables)
- [ ] Restricted syslog port to internal networks only
- [ ] Set up TLS/SSL with Let's Encrypt
- [ ] Configured reverse proxy (nginx/traefik)
- [ ] Left `CORS_ORIGIN` empty, or listed only the origins that need it (not `*`)
- [ ] Enabled automatic security updates

### Post-Deployment Checklist

- [ ] Signed in as `admin` and chose a new password (required at the first sign-in)
- [ ] Created least-privilege user accounts
- [ ] Tested firewall rules
- [ ] Verified TLS is working (SSL Labs test)
- [ ] Confirmed logs are being ingested
- [ ] Set up database backups
- [ ] Configured retention policies
- [ ] Enabled audit logging
- [ ] Set up health check monitoring
- [ ] Documented emergency procedures
- [ ] Tested backup restoration
- [ ] Reviewed all user accounts

### Monthly Security Review

- [ ] Review active user accounts (disable unused)
- [ ] Check for security updates
- [ ] Review audit logs for anomalies
- [ ] Verify backups are working
- [ ] Test incident response procedures
- [ ] Review firewall rules
- [ ] Check disk space usage
- [ ] Scan containers for vulnerabilities
- [ ] Rotate API keys for shippers
- [ ] Review detection rule effectiveness

### Quarterly Security Tasks

- [ ] Full security audit
- [ ] Penetration testing (if required)
- [ ] Update documentation
- [ ] Review and update incident response plan
- [ ] Compliance review (if applicable)
- [ ] Disaster recovery drill

---

## Compliance Considerations

### GDPR Compliance

**Data Protection:**
- Log data may contain personal information
- Implement data retention policies (configurable in SIEMBox)
- Provide data export/deletion capabilities
- Document data processing activities

**User Rights:**
```bash
# Right to access - Export user's data
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "COPY (SELECT * FROM parsed_logs WHERE parsed_data->>'user' = 'john.doe')
   TO '/tmp/user_data.csv' CSV HEADER;"

# Right to erasure - Delete user's data
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "DELETE FROM parsed_logs WHERE parsed_data->>'user' = 'john.doe';"
```

### PCI DSS Compliance

**Requirements:**
- Encrypt data in transit (TLS)
- Restrict access to cardholder data
- Maintain audit trails
- Regular security testing

**SIEMBox Considerations:**
- DO NOT log credit card numbers
- Use parsers to redact sensitive data
- Implement strict access controls
- Enable comprehensive audit logging

### HIPAA Compliance

**Requirements:**
- Encrypt PHI at rest and in transit
- Implement access controls
- Audit log access to PHI
- Business Associate Agreement (BAA)

**SIEMBox is NOT HIPAA-compliant out-of-the-box:**
- Lacks encryption at rest by default
- No BAA from vendor (open source)
- Requires extensive additional hardening

### SOC 2 Compliance

**Relevant Controls:**
- Access control (RBAC implemented)
- Encryption in transit (via TLS)
- Logging and monitoring (built-in)
- Change management (audit logs)
- Incident response (requires documentation)

---

## Additional Resources

### Security Tools

- **Vulnerability Scanning:** Trivy, Snyk, Anchore
- **SIEM for SIEMBox:** Send SIEMBox logs to another SIEM for meta-monitoring
- **Intrusion Detection:** Suricata, Zeek for network monitoring
- **File Integrity:** AIDE, Tripwire for host monitoring

### References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CIS Docker Benchmark: https://www.cisecurity.org/benchmark/docker
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- Docker Security Best Practices: https://docs.docker.com/engine/security/

### Support

- **Security Issues:** Report to https://github.com/cladkins/SIEMBOX/security/advisories
- **General Support:** https://github.com/cladkins/SIEMBOX/discussions
- **Documentation:** https://github.com/cladkins/SIEMBOX

---

## Security Disclosure Policy

**Reporting Security Vulnerabilities:**

If you discover a security vulnerability in SIEMBox:

1. **DO NOT** open a public GitHub issue
2. Email security details to: [maintainer-email]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested remediation (if any)

**Response Timeline:**
- Acknowledgment: Within 48 hours
- Initial assessment: Within 7 days
- Fix development: Varies by severity
- Public disclosure: After fix is released

---

**Document Version:** 1.0
**Last Updated:** 2025-12-02
**Maintained By:** SIEMBox Project

**This is a living document. Security practices should be reviewed and updated regularly.**
