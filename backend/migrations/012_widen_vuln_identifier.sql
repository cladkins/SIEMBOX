-- Migration 012: widen vulnerabilities.cve_id so non-CVE Nuclei findings persist.
--
-- The Nuclei scanner stores non-CVE findings (misconfigurations, exposures, etc.)
-- under a synthetic identifier "NUCLEI-<template-id>" in vulnerabilities.cve_id
-- (the column doubles as the dedupe key for the ON CONFLICT upsert). Template ids
-- such as "NUCLEI-http-missing-security-headers" routinely exceed the original
-- VARCHAR(20), so the INSERT failed with "value too long for type", the
-- surrounding BEGIN…COMMIT rolled back, and the finding was silently dropped —
-- producing the "22 found, 1 stored" mismatch. Widen the column to VARCHAR(255).
--
-- Real CVE ids still live here too; the frontend distinguishes them with a
-- /^CVE-/ test, so no semantic change is required. cwe_id is left at VARCHAR(20)
-- (CWE ids are short, e.g. "CWE-79").
--
-- Idempotent: the guard skips the ALTER once the column is already >= 255, so
-- re-running on every startup is a no-op and never triggers a table rewrite.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'vulnerabilities'
      AND column_name = 'cve_id'
      AND character_maximum_length IS NOT NULL
      AND character_maximum_length < 255
  ) THEN
    ALTER TABLE vulnerabilities ALTER COLUMN cve_id TYPE VARCHAR(255);
  END IF;
END $$;
