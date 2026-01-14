# SIEMBox Documentation Archive

This directory contains archived documentation that is no longer actively maintained but preserved for historical reference.

## Purpose

The archive preserves:
- **Incident documentation** from resolved issues
- **Completed implementation phases** and their documentation
- **Temporary fix guides** for issues that have been permanently resolved
- **Historical planning documents** from past development cycles
- **Superseded documentation** that has been replaced by newer versions

## Archive Categories

### Incidents
Historical incident response documentation:

#### SIEMBOX-DB-001 (Database Migration Issue, 2025-12-03)
- **[incidents/SIEMBOX-DB-001/HOTFIX_PLAN.md](./incidents/SIEMBOX-DB-001/HOTFIX_PLAN.md)** - Hotfix strategy and implementation
- **[incidents/SIEMBOX-DB-001/INCIDENT_ANALYSIS.md](./incidents/SIEMBOX-DB-001/INCIDENT_ANALYSIS.md)** - Root cause analysis
- **[incidents/SIEMBOX-DB-001/INCIDENT_SUMMARY.md](./incidents/SIEMBOX-DB-001/INCIDENT_SUMMARY.md)** - Executive summary
- **[incidents/SIEMBOX-DB-001/DIAGNOSTIC_SCRIPT.md](./incidents/SIEMBOX-DB-001/DIAGNOSTIC_SCRIPT.md)** - Diagnostic tool documentation
- **[incidents/SIEMBOX-DB-001/DEPLOYMENT_INSTRUCTIONS.md](./incidents/SIEMBOX-DB-001/DEPLOYMENT_INSTRUCTIONS.md)** - Temporary deployment workaround
- **[INCIDENT_RESPONSE_COMPLETE.md](./INCIDENT_RESPONSE_COMPLETE.md)** - Final incident response report

**Issue**: Database migration failed on fresh deployments due to dependency ordering
**Resolution**: Migration system refactored, issue permanently resolved in commit c8e85c1
**Status**: ✅ Resolved and archived

### Deployment Fixes (Resolved Issues)
- **[DEPLOYMENT-FIX-GUIDE.md](./DEPLOYMENT-FIX-GUIDE.md)** - Workaround for 2025-12-08 database initialization bug (now fixed)
- **[FRESH-INSTALL-FIX.md](./FRESH-INSTALL-FIX.md)** - Fix for database volume persistence issue (now fixed)
- **[DEPLOYMENT-GUIDE.md](./DEPLOYMENT-GUIDE.md)** - Superseded by consolidated DEPLOYMENT.md

### Phase Implementation (Completed Phases)
Documentation from completed development phases:

#### Phase 3A: Authentication Rules
- **[phase-implementation/AUTHENTICATION-RULES-PHASE-3A.md](./phase-implementation/AUTHENTICATION-RULES-PHASE-3A.md)** - Implementation of 11 authentication detection rules

#### Phase 3B: Proxy Security Rules
- **[phase-implementation/PHASE-3B-IMPLEMENTATION-SUMMARY.md](./phase-implementation/PHASE-3B-IMPLEMENTATION-SUMMARY.md)** - Implementation summary for proxy security rules
- **[phase-implementation/PHASE-3B-QUICK-REFERENCE.md](./phase-implementation/PHASE-3B-QUICK-REFERENCE.md)** - Quick reference guide

#### Phase 3C: Additional Detection Categories
- **[phase-implementation/PHASE-3C-IMPLEMENTATION-SUMMARY.md](./phase-implementation/PHASE-3C-IMPLEMENTATION-SUMMARY.md)** - Implementation summary
- **[phase-implementation/PHASE-3C-QUICK-REFERENCE.md](./phase-implementation/PHASE-3C-QUICK-REFERENCE.md)** - Quick reference guide

### Planning Documents
- **[PHASE-4-IMPLEMENTATION-PLAN.md](./PHASE-4-IMPLEMENTATION-PLAN.md)** - Historical planning document for Phase 4 features

### Historical Documentation
- **[DOCUMENTATION-MAP.md](./DOCUMENTATION-MAP.md)** - Previous documentation organization structure
- **[INCIDENT-RESOLUTION-SUMMARY.md](./INCIDENT-RESOLUTION-SUMMARY.md)** - Summary of past incident resolutions
- **[SESSION-HANDOFF.md](./SESSION-HANDOFF.md)** - Historical session handoff documentation
- **[PLAN.md](./PLAN.md)** - Original project planning document

## When to Use Archived Documentation

### ✅ Good Reasons to Reference Archive:
- Understanding how a past incident was handled
- Learning from previous implementation strategies
- Reviewing decision-making processes
- Understanding why certain approaches were abandoned
- Historical project context

### ⛔ Do NOT Use Archive For:
- Current deployment procedures (use [../../DEPLOYMENT.md](../../DEPLOYMENT.md))
- Active troubleshooting (use [../operations/TROUBLESHOOTING.md](../operations/TROUBLESHOOTING.md))
- Current API reference (use [../../API.md](../../API.md))
- Current parser/rule documentation (use [../reference/](../reference/))

## Archive Organization Policy

Documents are archived when:
1. **Incidents are resolved** and permanent fixes are implemented
2. **Implementation phases complete** and features are in production
3. **Temporary fixes** are replaced by permanent solutions
4. **Documentation is superseded** by newer, consolidated versions
5. **Planning documents** are completed or no longer relevant

Documents are kept in archive for:
- **Minimum 1 year** for incident documentation
- **Indefinitely** for major implementation phases
- **Until next major version** for superseded documentation

## Related Current Documentation

For current, actively maintained documentation:
- **Project Overview**: [../../README.md](../../README.md)
- **Deployment Guide**: [../../DEPLOYMENT.md](../../DEPLOYMENT.md)
- **API Reference**: [../../API.md](../../API.md)
- **Security Guide**: [../../SECURITY.md](../../SECURITY.md)
- **Parser Reference**: [../reference/PARSERS.md](../reference/PARSERS.md)
- **Rules Reference**: [../reference/RULES.md](../reference/RULES.md)
- **Troubleshooting**: [../operations/TROUBLESHOOTING.md](../operations/TROUBLESHOOTING.md)
- **Architecture**: [../architecture/](../architecture/)

## Questions?

If you're unsure whether to reference archived documentation or need clarification on archived incidents:
- Check [GitHub Issues](https://github.com/cladkins/SIEMBOX/issues)
- Review [GitHub Discussions](https://github.com/cladkins/SIEMBOX/discussions)
- See [CONTRIBUTING.md](../../CONTRIBUTING.md) for how to ask questions
