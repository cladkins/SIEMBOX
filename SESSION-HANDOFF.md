# SIEMBox Parser/Rule Redesign - Session Handoff

## Current Session Summary (Session 1)

**Date:** 2025-12-03
**Branch:** develop
**Status:** Phase 2 In Progress - Authentication Parsers

### What We Accomplished This Session

#### Phase 1: Foundation (100% Complete) ✅
1. **HOMELAB-THREAT-MODEL.md** - 40 detection rules designed, threat analysis, response playbooks
2. **PARSER-RULE-IMPLEMENTATION-SPEC.md** - Complete technical specification, templates, conventions
3. **DOCUMENTATION-ARCHITECTURE.md** - Documentation redesign, templates, style guide

#### Phase 2: Parser Development (30% Complete) ✅
1. **REVERSE-PROXY-PARSERS.md** - 6 parsers for 4 applications:
   - NGINX Proxy Manager (access + error)
   - Traefik (access)
   - Caddy (access)
   - Standard NGINX (access + error)

### Current State

**Files Created:**
- `/Users/chrisadkins/Projects/SIEMBox/HOMELAB-THREAT-MODEL.md`
- `/Users/chrisadkins/Projects/SIEMBox/PARSER-RULE-IMPLEMENTATION-SPEC.md`
- `/Users/chrisadkins/Projects/SIEMBox/DOCUMENTATION-ARCHITECTURE.md`
- `/Users/chrisadkins/Projects/SIEMBox/REVERSE-PROXY-PARSERS.md`
- `/Users/chrisadkins/Projects/SIEMBox/SESSION-HANDOFF.md` (this file)

**Branch:** develop
**Commits:** All work committed and pushed to GitHub

**Next Task:** Authentication Service Parsers (Authelia, authentik, Keycloak)

---

## How to Start the Next Session

### Option A: Continue Where We Left Off (Recommended)

**Exact prompt to use:**

```
I'm continuing the SIEMBox parser/rule redesign project from the previous session.

Context:
- Working directory: /Users/chrisadkins/Projects/SIEMBox
- Branch: develop
- Read the SESSION-HANDOFF.md file for complete status

Current status:
- Phase 1 (Foundation) is complete
- Phase 2A (Reverse Proxy Parsers) is complete - 6 parsers done
- Phase 2B (Authentication Parsers) is next

Task:
Continue Phase 2 by developing authentication service parsers (Authelia, authentik, Keycloak) using the backend-architect agent. Follow the same pattern as REVERSE-PROXY-PARSERS.md.

Reference documents:
- PARSER-RULE-IMPLEMENTATION-SPEC.md (implementation standards)
- HOMELAB-THREAT-MODEL.md (threat context)
- DOCUMENTATION-ARCHITECTURE.md (documentation templates)
- REVERSE-PROXY-PARSERS.md (example of completed work)

Start by using the Task tool with subagent_type='backend-architect' to develop authentication parsers.
```

### Option B: Start Fresh with Context

**Exact prompt to use:**

```
I need help with the SIEMBox parser/rule redesign project. This is a continuation from a previous session.

Background:
- SIEMBox is a self-hosted SIEM for homelabbers
- We're redesigning parsers and rules based on 2025 Self-Hosted Survey data
- Working directory: /Users/chrisadkins/Projects/SIEMBox
- Branch: develop

Previous session completed:
- Phase 1: Created threat model, implementation spec, documentation architecture (all in /Users/chrisadkins/Projects/SIEMBox/)
- Phase 2A: Created 6 reverse proxy parsers (REVERSE-PROXY-PARSERS.md)

Read these files to understand what's been done:
- SESSION-HANDOFF.md (this is the handoff document)
- HOMELAB-THREAT-MODEL.md
- PARSER-RULE-IMPLEMENTATION-SPEC.md
- DOCUMENTATION-ARCHITECTURE.md
- REVERSE-PROXY-PARSERS.md

Next step: Continue Phase 2 by developing authentication parsers (Authelia, authentik, Keycloak). Use the agent-organizer or go directly to backend-architect agent.
```

### Option C: Quick Status Check First

**Exact prompt to use:**

```
Read /Users/chrisadkins/Projects/SIEMBox/SESSION-HANDOFF.md and give me a status summary of the SIEMBox parser/rule redesign project. Then wait for my instructions on what to do next.
```

---

## What Happens Next (Remaining Work)

### Phase 2: Parser Development (Continue)

#### Phase 2B: Authentication Service Parsers (NEXT - In Progress)
**Priority:** HIGH - 1,169 combined users
**Applications:**
1. Authelia (390 users)
2. authentik (268 users)
3. Keycloak (158 users)

**Deliverable:** AUTHENTICATION-PARSERS.md (similar to REVERSE-PROXY-PARSERS.md)

**Estimated:** 3-5 parsers (access, error, audit logs)

#### Phase 2C: Critical Application Parsers
**Priority:** CRITICAL - Security-sensitive applications
**Applications:**
1. Vaultwarden (152 users) - PASSWORD MANAGER - HIGHEST SECURITY
2. Nextcloud (118 users) - File sharing
3. Pi-hole (50 users) - DNS security

**Deliverable:** CRITICAL-APPLICATION-PARSERS.md

**Estimated:** 4-6 parsers

#### Phase 2D: Additional Parsers (Optional - Future Session)
**Applications:**
- Home Assistant (588 users) - Smart home
- Jellyfin (522 users) - Media server
- Immich (429 users) - Photo management
- Plex (208 users) - Media server

**Note:** These can be deferred to a future session if needed.

### Phase 3: Detection Rules (After Phase 2)

**Task:** Implement 40 detection rules from HOMELAB-THREAT-MODEL.md

**Categories:**
1. Authentication Attacks (10 rules)
2. Reverse Proxy Exploitation (8 rules)
3. Password Manager Security (4 rules)
4. Access Control Violations (4 rules)
5. Data Exfiltration (3 rules)
6. Infrastructure Attacks (4 rules)
7. Application-Specific Threats (4 rules)
8. IoT/Smart Home (3 rules)

**Deliverable:** Detection rules in YAML format, ready for database import

### Phase 4: Documentation Updates

**Tasks:**
1. Reorganize PARSERS.md with new parser categories
2. Reorganize RULES.md with new rule categories
3. Create integration-guides/ directory structure
4. Write integration guides for top 15 applications
5. Create quick start guide
6. Create migration guide

### Phase 5: Testing & Validation

**Tasks:**
1. Test parsers with real log samples
2. Test rules trigger correctly
3. Validate integration guides
4. End-to-end workflow testing

---

## Important Context for New Session

### Project Goals
- Make SIEMBox the go-to SIEM for homelabbers
- Focus on applications homelabbers actually use (survey-driven)
- 20+ parsers for popular homelab applications
- 40 detection rules for homelab threat scenarios
- Beginner-friendly documentation

### Key Principles
1. **Survey-Driven:** Base all decisions on 2025 Self-Hosted Survey data
2. **Security-First:** Prioritize parsers/rules by security impact
3. **Beginner-Friendly:** Documentation assumes users are technical but not security experts
4. **Consistent:** Follow templates and conventions from foundation documents
5. **Tested:** Every parser needs 3-5 test samples with expected output
6. **Documented:** Follow templates from DOCUMENTATION-ARCHITECTURE.md

### Standards to Follow
- **Naming:** `[application]-[logtype]` (e.g., `authelia-access`)
- **Priority:** 60-80 for application-specific parsers
- **Fields:** snake_case, use standard field registry from spec
- **Tags:** kebab-case for detection rules
- **Test Samples:** 3-5 per parser with expected output

### Critical Reference Files
1. **PARSER-RULE-IMPLEMENTATION-SPEC.md** - HOW to implement parsers/rules
2. **HOMELAB-THREAT-MODEL.md** - WHY we're detecting these threats
3. **DOCUMENTATION-ARCHITECTURE.md** - HOW to document everything
4. **REVERSE-PROXY-PARSERS.md** - EXAMPLE of completed parser work

---

## Git State

### Current Branch
```bash
git branch
# Should show: * develop
```

### Files to Commit (if any work is done)
```bash
# After completing authentication parsers:
git add AUTHENTICATION-PARSERS.md
git commit -m "feat: Add authentication service parsers (Authelia, authentik, Keycloak)

- Authelia access and error log parsers
- authentik audit and event log parsers
- Keycloak admin and user event parsers
- Complete with test samples and documentation

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"

git push origin develop
```

### How to Check Current State
```bash
# See what's been done
ls -la *.md

# Check git status
git status

# See recent commits
git log --oneline -10

# See what branch you're on
git branch
```

---

## Troubleshooting

### If You Get Lost
1. Read this file (SESSION-HANDOFF.md)
2. Check the todo list with TodoWrite tool
3. Read DOCUMENTATION-ARCHITECTURE.md for structure
4. Look at REVERSE-PROXY-PARSERS.md as an example

### If Files Are Missing
```bash
# Make sure you're in the right directory
pwd
# Should show: /Users/chrisadkins/Projects/SIEMBox

# Check if files exist
ls -la HOMELAB-THREAT-MODEL.md
ls -la PARSER-RULE-IMPLEMENTATION-SPEC.md
ls -la DOCUMENTATION-ARCHITECTURE.md
ls -la REVERSE-PROXY-PARSERS.md
```

### If You Need to Start Over
Don't! The foundation work is solid. Just continue from where we left off.

### If Conventions Are Unclear
1. Check PARSER-RULE-IMPLEMENTATION-SPEC.md (Section 4: Conventions)
2. Look at REVERSE-PROXY-PARSERS.md for examples
3. Use the templates from DOCUMENTATION-ARCHITECTURE.md

---

## Success Metrics

### Parser Quality Checklist
- [ ] Follows naming convention: `[application]-[logtype]`
- [ ] Priority: 60-80 range
- [ ] Field names: snake_case from standard registry
- [ ] Test samples: 3-5 with expected output
- [ ] Documentation: Follows template
- [ ] SQL: INSERT statements ready
- [ ] Security relevance: Clearly explained

### Rule Quality Checklist
- [ ] Name: Descriptive and action-oriented
- [ ] Severity: Appropriate for threat
- [ ] Threshold: Tuned for homelabs (small user base)
- [ ] Conditions: Use extracted fields from parsers
- [ ] Tags: From standard tag registry
- [ ] Description: Clear threat explanation
- [ ] Response: Immediate actions documented

---

## Quick Reference Commands

### Start New Agent Task
```
Use the Task tool with:
- subagent_type: 'backend-architect' (for parsers)
- subagent_type: 'security-auditor' (for rules)
- subagent_type: 'documentation-expert' (for guides)
- subagent_type: 'qa-expert' (for testing)
```

### Check Todo List
```
Use TodoWrite tool to see current task status
```

### Commit Work
```bash
git add <files>
git commit -m "descriptive message"
git push origin develop
```

---

## Contact & Support

**Project:** SIEMBox Parser/Rule Redesign
**Repository:** https://github.com/cladkins/SIEMBOX
**Branch:** develop
**Documentation:** All specs in /Users/chrisadkins/Projects/SIEMBox/

**Key Files to Reference:**
1. SESSION-HANDOFF.md (this file)
2. HOMELAB-THREAT-MODEL.md
3. PARSER-RULE-IMPLEMENTATION-SPEC.md
4. DOCUMENTATION-ARCHITECTURE.md
5. REVERSE-PROXY-PARSERS.md

---

## Session End Checklist

Before ending this session:
- [x] All work committed to git
- [x] SESSION-HANDOFF.md created
- [x] Next steps clearly documented
- [x] Foundation documents complete
- [x] Example parser work done (reverse proxies)
- [x] Clear instructions for next session

**Ready to continue!** Just use one of the prompts above to start the next session.
