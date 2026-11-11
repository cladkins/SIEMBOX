name: Feature Request
description: Suggest a new feature or improvement for SIEMBOX
title: "[Feature]: "
labels: ["enhancement", "triage"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for helping improve SIEMBOX. Search existing issues first to avoid duplicates.

        Do not use this form for security flaws. Follow the process in SECURITY.md instead.

  - type: textarea
    id: problem
    attributes:
      label: Problem
      description: What problem does this feature solve? Describe what you tried to do and what stopped you.
      placeholder: I want to monitor my pfSense firewall, but SIEMBOX does not parse its filterlog format.
    validations:
      required: true

  - type: textarea
    id: solution
    attributes:
      label: Proposed Solution
      description: Describe the feature you want and how you expect to use it.
      placeholder: Add a pfSense filterlog parser with fields for action, interface, source, destination, and port.
    validations:
      required: true

  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives Considered
      description: List workarounds or other approaches you tried.
      placeholder: I wrote a custom regex rule, but the fields don't show up in parsed log search.
    validations:
      required: false

  - type: dropdown
    id: component
    attributes:
      label: Component
      description: Which part of SIEMBOX does this affect?
      multiple: true
      options:
        - Log ingest
        - Source discovery and onboarding
        - Parsers
        - Detection rules
        - Alerting
        - Search
        - MCP server
        - Web UI
        - Deployment and configuration
        - Documentation
        - Other
    validations:
      required: true

  - type: input
    id: log-source
    attributes:
      label: Log Source
      description: If this request involves a specific device, app, or log format, name it here.
      placeholder: pfSense 2.7, Proxmox VE 9, Authentik, Nginx Proxy Manager
    validations:
      required: false

  - type: textarea
    id: sample-logs
    attributes:
      label: Sample Logs
      description: Paste 3 to 5 sample log lines if relevant. Scrub IP addresses, hostnames, usernames, tokens, and passwords first.
      render: text
    validations:
      required: false

  - type: dropdown
    id: priority
    attributes:
      label: Impact
      description: How much does this affect your use of SIEMBOX?
      options:
        - Nice to have
        - Important, I have a workaround
        - Blocking, no workaround
    validations:
      required: true

  - type: dropdown
    id: contribute
    attributes:
      label: Contribution
      description: Do you want to help build this?
      options:
        - I will submit a pull request
        - I will help test
        - No, request only
    validations:
      required: true

  - type: checkboxes
    id: checks
    attributes:
      label: Checklist
      options:
        - label: I searched existing issues and found no duplicate.
          required: true
        - label: I removed sensitive data from all logs and screenshots.
          required: true
        - label: I agree to follow the SIEMBOX Code of Conduct.
          required: true
