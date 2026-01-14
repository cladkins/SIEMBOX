# SIEMBox Database Scripts

This directory contains utility scripts for database maintenance, validation, and fixes.

## Available Scripts

### 1. Fix Vaultwarden Parser (`utilities/fix_vaultwarden_parser.sql`)

**Purpose**: Updates the existing vaultwarden-access parser in the database with the corrected JavaScript-compatible regex pattern.

**Background**: Migration 005 originally created the parser with Python-style regex syntax (`(?P<name>...)`), which is incompatible with JavaScript. This script directly updates the database record to fix the issue.

**Usage**:
```bash
# Using psql
psql -h localhost -U siembox -d siembox -f backend/scripts/utilities/fix_vaultwarden_parser.sql

# Using Docker
docker exec -i siembox-postgres psql -U siembox -d siembox < backend/scripts/utilities/fix_vaultwarden_parser.sql
```

**What it does**:
1. Updates the vaultwarden-access parser pattern to use JavaScript syntax
2. Verifies the update was successful
3. Checks for any other parsers with Python-style regex syntax

### 2. Validate All Parsers (`utilities/validate-parsers.ts`)

**Purpose**: Comprehensive validation of all parsers in the database for JavaScript regex compatibility and test sample coverage.

**Usage**:
```bash
# From project root
npx ts-node backend/scripts/utilities/validate-parsers.ts

# With custom database connection
POSTGRES_HOST=localhost \
POSTGRES_PORT=5432 \
POSTGRES_DB=siembox \
POSTGRES_USER=siembox \
POSTGRES_PASSWORD=siembox \
npx ts-node backend/scripts/utilities/validate-parsers.ts
```

**What it validates**:
- ✓ Regex syntax (checks for Python-style `(?P<...)`  vs JavaScript `(?<...>`)
- ✓ Regex compilation (ensures patterns are valid JavaScript RegExp)
- ✓ Test samples (runs each parser against its test samples)
- ✓ Field mapping coverage
- ✓ Parser type validity

**Exit codes**:
- `0` - All parsers valid
- `1` - One or more parsers failed validation

### 3. Validate All Detection Rules (`utilities/validate-rules.ts`)

**Purpose**: Comprehensive validation of all detection rules in the database for correct JSON structure, condition syntax, and regex patterns.

**Usage**:
```bash
# From project root
npx ts-node backend/scripts/utilities/validate-rules.ts

# With custom database connection
POSTGRES_HOST=localhost \
POSTGRES_PORT=5432 \
POSTGRES_DB=siembox \
POSTGRES_USER=siembox \
POSTGRES_PASSWORD=siembox \
npx ts-node backend/scripts/utilities/validate-rules.ts
```

**What it validates**:
- ✓ Severity levels (critical, high, medium, low, info)
- ✓ Conditions structure and required fields
- ✓ Regex patterns in conditions (checks for Python-style syntax)
- ✓ Aggregation configuration (field, timeframe, threshold)
- ✓ Rule logic consistency
- ✓ JSON structure validity

**Exit codes**:
- `0` - All rules valid
- `1` - One or more rules failed validation

### 4. Comprehensive Validation Query (`utilities/validate_all_parsers_and_rules.sql`)

**Purpose**: SQL-based validation report that can be run directly in psql without TypeScript dependencies.

**Usage**:
```bash
# Using psql
psql -h localhost -U siembox -d siembox -f backend/scripts/utilities/validate_all_parsers_and_rules.sql

# Using Docker
docker exec -i siembox-postgres psql -U siembox -d siembox < backend/scripts/utilities/validate_all_parsers_and_rules.sql
```

**What it reports**:
1. Parsers with Python-style regex syntax
2. All regex parsers validation status
3. Parser statistics by type
4. All parsers ordered by priority
5. Detection rule statistics by severity
6. Rules using regex conditions
7. Rules with JSON structure issues
8. All detection rules summary
9. Overall system counts
10. Critical issues summary

## Common Use Cases

### After Fresh Database Setup
```bash
# Validate all parsers
npx ts-node backend/scripts/utilities/validate-parsers.ts

# Validate all rules
npx ts-node backend/scripts/utilities/validate-rules.ts
```

### After Migration 005 Has Already Run
```bash
# Fix the vaultwarden parser
psql -h localhost -U siembox -d siembox -f backend/scripts/utilities/fix_vaultwarden_parser.sql

# Validate the fix worked
npx ts-node backend/scripts/utilities/validate-parsers.ts
```

### Troubleshooting Parser Errors
```bash
# Get detailed SQL report
psql -h localhost -U siembox -d siembox -f backend/scripts/utilities/validate_all_parsers_and_rules.sql

# Run TypeScript validation for detailed error messages
npx ts-node backend/scripts/utilities/validate-parsers.ts
```

### CI/CD Pipeline Integration
```bash
#!/bin/bash
# Add to your CI/CD pipeline

echo "Validating parsers..."
npx ts-node backend/scripts/utilities/validate-parsers.ts || exit 1

echo "Validating detection rules..."
npx ts-node backend/scripts/utilities/validate-rules.ts || exit 1

echo "All validations passed!"
```

## Environment Variables

All TypeScript scripts support these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_HOST` | `localhost` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_DB` | `siembox` | Database name |
| `POSTGRES_USER` | `siembox` | Database user |
| `POSTGRES_PASSWORD` | `siembox` | Database password |

## Troubleshooting

### "Invalid regular expression" errors in production

This typically means a parser has Python-style regex syntax. Run:
```bash
# Check for Python-style patterns
psql -c "SELECT name, substring(pattern, 1, 100) FROM parsers WHERE pattern LIKE '%(?P<%';"

# Fix vaultwarden parser specifically
psql -f backend/scripts/fix_vaultwarden_parser.sql
```

### TypeScript execution errors

Ensure you have dependencies installed:
```bash
cd backend
npm install
```

Required packages:
- `typescript`
- `ts-node`
- `pg` (PostgreSQL client)
- `@types/pg`

### Connection errors

Verify your database is running and credentials are correct:
```bash
psql -h localhost -U siembox -d siembox -c "SELECT version();"
```

For Docker deployments:
```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT version();"
```

## Development

To add new validation scripts:

1. Create `.sql` file for direct database queries
2. Create `.ts` file for complex validation logic
3. Update this README with usage instructions
4. Add to CI/CD pipeline if appropriate

## Related Documentation

- [PARSERS.md](../../docs/PARSERS.md) - Parser creation guide
- [RULES.md](../../docs/RULES.md) - Detection rule documentation
- [TROUBLESHOOTING.md](../../docs/operations/TROUBLESHOOTING.md) - Common issues and solutions
