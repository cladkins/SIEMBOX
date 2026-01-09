# SIEMBox Development Roadmap

**Project:** SIEMBox - Lightweight Self-Hosted SIEM
**Current Status:** Pre-v1.0 Active Development
**Target:** v1.0 Production Release

---

## Milestone: v1.0 Production Release

### Phase 1: Test Coverage Foundation
**Goal:** Establish comprehensive test suite to ensure code quality and prevent regressions

**Deliverables:**
- Backend unit tests for all services (parser engine, rules engine, syslog server)
- Backend integration tests for critical workflows (log ingestion → parsing → detection → alerting)
- Frontend component tests for core views (Dashboard, Logs, Alerts, Parsers, Rules)
- API endpoint tests with authentication/authorization coverage
- Achieve 80%+ code coverage (backend) and 70%+ (frontend)
- CI/CD integration with automated test runs

**Success Criteria:**
- All services have unit test coverage
- Critical user workflows have integration tests
- Tests run automatically in CI/CD
- Code coverage meets targets
- Documentation: Testing best practices guide

**Research Needed:**
- [ ] Review existing test infrastructure (Jest, Vitest configs)
- [ ] Identify critical paths requiring integration tests
- [ ] Determine mocking strategy for external dependencies (NMAP, PostgreSQL)

---

### Phase 2: Database Migration System
**Goal:** Implement proper database migration tracking for production deployments

**Deliverables:**
- Migration tracking table (`schema_migrations`)
- Migration runner with up/down support
- Split `001_initial_schema.sql` into incremental migrations
- Seed data management (parsers, rules, admin user)
- Migration rollback capabilities
- Documentation: Database migration guide

**Success Criteria:**
- Migration system tracks applied migrations
- Fresh installs work correctly
- Upgrades from previous versions work
- Rollback functionality tested
- Documentation: Migration procedures

**Research Needed:**
- [ ] Evaluate migration libraries (node-pg-migrate, db-migrate, custom)
- [ ] Design migration naming convention
- [ ] Plan backward compatibility strategy

---

### Phase 3: API Versioning & Stability
**Goal:** Establish stable API contract with versioning support

**Deliverables:**
- API versioning strategy (URL-based: `/api/v1/`)
- Version all endpoints with `/api/v1/` prefix
- API changelog documentation
- Deprecation policy and timeline
- API stability guarantees documentation
- OpenAPI/Swagger specification

**Success Criteria:**
- All endpoints versioned
- OpenAPI spec generated
- API documentation includes version info
- Breaking changes process documented
- Backward compatibility policy defined

**Research Needed:**
- [ ] Review current API surface area
- [ ] Identify potential breaking changes
- [ ] Plan versioning strategy (URL vs header vs query param)

---

### Phase 4: Performance Benchmarking
**Goal:** Establish performance baselines and optimization targets

**Deliverables:**
- Performance test suite (log ingestion rate, query response times)
- Benchmark documentation with test methodology
- Performance tuning guide (PostgreSQL, backend config)
- Load testing scenarios (sustained load, burst traffic)
- Resource usage documentation (CPU, memory, disk I/O)
- Performance regression tests in CI/CD

**Success Criteria:**
- Documented performance baselines
- Load testing scenarios defined and executed
- Performance tuning recommendations documented
- Performance regression detection in CI/CD
- Known bottlenecks identified and documented

**Research Needed:**
- [ ] Select load testing tools (k6, Artillery, custom)
- [ ] Define realistic test scenarios
- [ ] Identify performance metrics to track

---

### Phase 5: Security Audit & Hardening
**Goal:** Complete security review and address vulnerabilities

**Deliverables:**
- Security audit report
- Address dependency vulnerabilities (33 identified by Dependabot)
- Input validation audit across all API endpoints
- SQL injection prevention review
- XSS prevention audit (frontend)
- Authentication/authorization audit
- Security best practices documentation update
- Penetration testing report

**Success Criteria:**
- Zero critical/high vulnerabilities in dependencies
- All API inputs validated
- Security audit passed
- Penetration testing completed
- Updated SECURITY.md with findings
- Security checklist for deployments

**Research Needed:**
- [ ] Review Dependabot vulnerability report
- [ ] Plan dependency update strategy (breaking changes?)
- [ ] Identify security testing tools/services

---

### Phase 6: Production-Ready Documentation
**Goal:** Complete all documentation for production deployments

**Deliverables:**
- Production deployment guide (beyond Docker Compose)
- Backup and recovery procedures
- Disaster recovery plan
- Monitoring and observability guide
- Troubleshooting runbooks for common issues
- Upgrade procedures documentation
- Scaling guide (vertical scaling limits, when to scale)
- Performance tuning playbook

**Success Criteria:**
- Production deployment guide tested
- Backup/restore procedures verified
- All runbooks tested
- Upgrade path documented and tested
- Scaling recommendations documented

**Research Needed:**
- [ ] Identify common production deployment patterns
- [ ] Review production issues from existing users (if any)
- [ ] Plan backup strategy (database, config)

---

### Phase 7: v1.0 Release Preparation
**Goal:** Package and release v1.0 with stability guarantees

**Deliverables:**
- Release notes and changelog
- Migration guide from pre-v1.0 to v1.0
- Version tags and GitHub release
- Docker images published to registry
- Release announcement
- Community parser/rule submission process
- v1.0 stability guarantees documented

**Success Criteria:**
- All prior phases completed
- GitHub release created with artifacts
- Docker images published
- Migration guide tested
- Release announcement published
- Community contribution process documented

**Research Needed:**
- [ ] Plan release process (GitHub Actions automation?)
- [ ] Define versioning strategy post-v1.0 (semver)
- [ ] Plan Docker image registry (Docker Hub, GHCR)

---

## Post-v1.0 Roadmap (Future)

### Phase 8: Real-Time Features
**Goal:** Add WebSocket support for real-time updates

**Deliverables:**
- WebSocket server integration
- Real-time alert notifications
- Live log streaming
- Dashboard auto-refresh
- Frontend WebSocket client

---

### Phase 9: Alert Notification Channels
**Goal:** Implement email, webhook, and Slack/Teams integrations

**Deliverables:**
- Email notification system
- Webhook integration
- Slack integration
- Microsoft Teams integration
- Notification channel management UI

---

### Phase 10: Advanced Correlation Rules
**Goal:** Implement multi-stage correlation and threat hunting capabilities

**Deliverables:**
- Multi-event correlation engine
- Time-based aggregation rules
- Threat hunting query language
- Saved searches and dashboards

---

### Phase 11: Horizontal Scaling Support
**Goal:** Enable multi-node deployment for high availability

**Deliverables:**
- Stateless backend design
- Redis for session storage
- Message queue for async processing (RabbitMQ/Redis)
- Load balancer configuration
- PostgreSQL replication setup
- Scaling architecture documentation

---

### Phase 12: Plugin/Extension System
**Goal:** Enable community-contributed parsers, rules, and integrations

**Deliverables:**
- Plugin API design
- Plugin management UI
- Community plugin marketplace
- Plugin development SDK
- Plugin security sandboxing

---

## Notes

**Current Branch:** `develop`
**Target Release Date:** TBD (based on phase completion)
**Priority:** Phases 1-7 are required for v1.0
**Community Input:** Roadmap may be adjusted based on community feedback

**Key Decisions:**
- Pre-v1.0: Direct schema changes in `001_initial_schema.sql` acceptable
- Post-v1.0: Proper migration system required
- API stability: No breaking changes post-v1.0 without major version bump
- Testing: Comprehensive tests required before v1.0 release
