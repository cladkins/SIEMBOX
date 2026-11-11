# Security Policy

SIEMBOX collects and stores security logs from your network. A flaw in SIEMBOX puts your entire lab at risk. We take every report seriously.

## Supported Versions

We patch security issues in the latest release only. Update to the newest version before you report a bug.

| Version | Supported |
| ------- | --------- |
| Latest release | Yes |
| Older releases | No |

## Report a Vulnerability

Do not open a public issue, discussion, or pull request for a security flaw.

Use one of these private channels:

1. GitHub private reporting. Go to the Security tab of this repo and click "Report a vulnerability."
2. Email cladkins@gmail.com . Put "SIEMBOX Security" in the subject line.

Include:

- The SIEMBOX version and how you deployed it (Docker, bare metal, other).
- The affected component (ingest, parser, rules engine, alerting, MCP server, web UI).
- Steps to reproduce the issue.
- The impact you observed or expect.
- A proof of concept, if you have one.

Scrub all real IP addresses, hostnames, usernames, tokens, and passwords from your report.

## What to Expect

| Step | Timeline |
| ---- | -------- |
| Acknowledge your report | Within 3 days |
| Confirm or reject the issue | Within 10 days |
| Release a fix for critical issues | Within 30 days |
| Release a fix for other issues | Next scheduled release |

We will keep you updated through each step. Once we release a fix, we will publish a GitHub security advisory and credit you by name, unless you ask to stay anonymous.

## In Scope

- Authentication or authorization bypass.
- Unauthenticated access to logs, alerts, or settings.
- Injection flaws in log ingest or parsing, including malicious log lines.
- Remote code execution.
- MCP server actions beyond read-only access.
- Secrets exposed in logs, configs, or API responses.
- Cross-site scripting or request forgery in the web UI.

## Out of Scope

- Issues in third-party dependencies with no SIEMBOX-specific impact. Report those upstream.
- Attacks requiring physical access or existing root access to the host.
- Denial of service from flooding the ingest port with traffic.
- Findings from automated scanners with no proof of impact.
- Misconfigurations, such as exposing SIEMBOX to the internet without authentication.

## Safe Harbor

We will not pursue legal action against researchers who:

- Test only on SIEMBOX instances they own.
- Avoid accessing or changing other people's data.
- Give us reasonable time to fix the issue before public disclosure.

## Hardening Tips

- Keep SIEMBOX behind a VPN or an authenticating reverse proxy.
- Never expose the ingest or web ports to the internet.
- Use strong, unique credentials for every account.
- Restrict MCP server access to trusted clients.
- Update to each new release.
