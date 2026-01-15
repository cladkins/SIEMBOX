# Nuclei Templates Directory

This directory is bind-mounted to `/root/nuclei-templates` in the SIEMBox backend container.

## Automatic Template Download

Nuclei templates are automatically downloaded when you run your first vulnerability scan. The `-update-templates` flag is included with each scan to keep templates current.

## Adding Custom Templates

You can add custom Nuclei templates by placing them in this directory:

```
nuclei-templates/
├── custom/
│   ├── my-custom-template.yaml
│   └── company-specific/
│       └── internal-app-check.yaml
└── README.md
```

Custom templates will be available in the "custom" category in the UI.

## Template Structure

Each template is a YAML file with the following structure:

```yaml
id: my-custom-template
info:
  name: My Custom Vulnerability Check
  author: your-name
  severity: high
  description: Description of what this template detects
  tags: custom,webapp

http:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
    matchers:
      - type: word
        words:
          - "vulnerable response"
```

## Official Templates

The official Nuclei templates repository contains thousands of templates:
https://github.com/projectdiscovery/nuclei-templates

## Template Categories

After templates are downloaded, you'll see categories like:
- `cves/` - Known CVE vulnerabilities
- `vulnerabilities/` - General vulnerability checks
- `exposures/` - Sensitive data exposures
- `misconfiguration/` - Security misconfigurations
- `technologies/` - Technology detection
- `default-logins/` - Default credential checks

## More Information

- [Nuclei Template Guide](https://docs.projectdiscovery.io/templates/introduction)
- [Template Examples](https://github.com/projectdiscovery/nuclei-templates)
