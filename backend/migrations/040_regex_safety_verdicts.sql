-- Migration 040: cached ReDoS verdicts (services/regex/regexSafety.ts).
--
-- Every regex SIEMBox stores (parser patterns and derivations, detection-rule
-- `regex` conditions) is analyzed with recheck before it is saved, and every
-- stored one is analyzed again at startup. One analysis takes from a few
-- hundred milliseconds to the time budget (REGEX_SAFETY_CHECK_TIMEOUT_MS,
-- 5 s by default), so the verdict is kept here: each distinct regex is analyzed
-- once per checker, not on every save, install or restart.
--
-- regex_key: sha256 hex of flags NUL source (content-addressed: the same regex
--   in two parsers, or reinstalled from the catalog, is one row).
-- checker: what produced the verdict, e.g. "recheck@4.5.0;timeout=5000". A row
--   from a different checker is ignored and overwritten, so a recheck upgrade
--   or a new time budget re-analyzes.
-- status: 'safe', 'vulnerable' (an attack string exists; the regex is refused at
--   write time and flagged in the UI) or 'unknown' (not decided within the
--   budget; accepted with a warning).
--
-- Holds no user data beyond the hash; deleting rows only costs re-analysis.
-- Idempotent: CREATE TABLE IF NOT EXISTS.
CREATE TABLE IF NOT EXISTS regex_safety_verdicts (
  regex_key CHAR(64) PRIMARY KEY,
  checker TEXT NOT NULL,
  status VARCHAR(16) NOT NULL CHECK (status IN ('safe', 'vulnerable', 'unknown')),
  complexity TEXT,
  detail TEXT,
  attack TEXT,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
