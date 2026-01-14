# Pre-v1.0 Database Management

## Current Status: Pre-Release Development

SIEMBox is currently in **pre-v1.0 development**. The schema is evolving rapidly as features are added and refined.

## Database Schema Changes

During pre-v1.0 development, database schema changes may require a fresh start. This is **intentional** - we're focusing on getting the schema right before the v1.0 release.

### When Schema Changes Occur

If you pull an update that includes database schema changes, you'll see an error like:
```
ERROR: column "app_name" does not exist
```

### How to Apply Schema Changes

**Simple reset (recommended for development):**

```bash
# Stop containers
docker-compose down

# Remove the database volume (THIS DELETES ALL DATA)
docker volume rm siembox_postgres-data

# Start fresh with new schema
docker-compose up -d
```

**Or just run this one-liner:**
```bash
docker-compose down && docker volume rm siembox_postgres-data && docker-compose up -d
```

### Preserving Test Data (Optional)

If you have test parsers or rules you want to keep:

1. **Export before reset:**
   ```bash
   # Export parsers
   curl http://localhost:3001/api/parsers > parsers-backup.json

   # Export detection rules
   curl http://localhost:3001/api/rules > rules-backup.json
   ```

2. **Reset database** (commands above)

3. **Re-import after reset:**
   ```bash
   # Re-import parsers
   # (Use the UI or API to recreate your custom parsers)
   ```

## What Happens at v1.0 Release

Once we release v1.0:
- The schema will be considered **stable**
- Future updates will use **proper migrations** that preserve data
- Users with production data won't need to reset
- Migration tracking system will be implemented

## Why This Approach?

**For pre-v1.0:**
- Simpler development workflow
- Faster iteration on schema design
- No migration complexity during active development
- Focus on getting features right, not migration scripts

**After v1.0:**
- Robust migration system
- Safe upgrades with data preservation
- Version tracking
- Rollback capability

## Current Schema Version

Check `backend/migrations/001_initial_schema.sql` for the current complete schema.

Last major schema update: **2025-12-10** (added app_name field for source identification)

## For Developers

If you're contributing to SIEMBox pre-v1.0:
1. Make schema changes directly in `001_initial_schema.sql`
2. Document the change in git commit
3. Note in PR description: "⚠️ Requires database reset"
4. Don't worry about migration scripts - we'll build those for v1.0

## Questions?

- **Q: Will I lose my parsers/rules?**
  A: Yes, if you reset the database. Export them first if you want to keep them.

- **Q: Can I just run SQL to add the column?**
  A: Yes! If you don't want to reset, you can manually apply the changes. Check the git diff on `001_initial_schema.sql` to see what changed.

- **Q: When will proper migrations be added?**
  A: As part of the v1.0 release preparation. We'll add migration tracking and safe upgrade paths before declaring v1.0 stable.
