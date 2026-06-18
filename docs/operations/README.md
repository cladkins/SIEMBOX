# SIEMBox Operations Documentation

This directory contains operational guides and checklists for running and maintaining SIEMBox.

## Contents

### [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)
Comprehensive troubleshooting guide including:
- Common deployment issues and solutions
- Database connection problems
- Log ingestion troubleshooting
- Parser and rule debugging
- Performance optimization
- Container and Docker issues
- Network and firewall configuration

### [RULE-DEPLOYMENT-CHECKLIST.md](./RULE-DEPLOYMENT-CHECKLIST.md)
Pre-deployment verification checklist for:
- Testing new detection rules
- Validating rule logic
- Preventing false positives
- Rule performance testing
- Rollback procedures

## Related Documentation

- **Deployment**: [../../DEPLOYMENT.md](../../DEPLOYMENT.md)
- **Security**: [../../SECURITY.md](../../SECURITY.md)
- **API Reference**: [../../API.md](../../API.md)
- **Parser Reference**: [../reference/PARSERS.md](../reference/PARSERS.md)
- **Rules Reference**: [../reference/RULES.md](../reference/RULES.md)

## Quick Start Operations

### Monitor Log Ingestion
```bash
# Check recent logs
docker compose logs backend | grep -i "log received"

# Check log counts
curl http://localhost:8421/api/logs/stats
```

### Check Alert Status
```bash
# View recent alerts
curl http://localhost:8421/api/alerts?limit=10

# Check alert counts by severity
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT severity, COUNT(*)
FROM alerts
GROUP BY severity;
"
```

### Database Health
```bash
# Check database size
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT pg_size_pretty(pg_database_size('siembox'));
"

# Check table sizes
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  relname as table_name,
  pg_size_pretty(pg_total_relation_size(relid)) as size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
"
```

## Support

If you encounter issues not covered in the troubleshooting guide:
- Check [GitHub Issues](https://github.com/cladkins/SIEMBOX/issues)
- Review [GitHub Discussions](https://github.com/cladkins/SIEMBOX/discussions)
- See [CONTRIBUTING.md](../../CONTRIBUTING.md) for how to report bugs
