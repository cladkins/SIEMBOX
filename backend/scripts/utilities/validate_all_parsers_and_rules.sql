-- Validation Script: Check All Parsers and Detection Rules
-- Date: 2025-12-08
-- Purpose: Comprehensive validation of all parsers and detection rules for compatibility

-- ============================================================================
-- PART 1: PARSER VALIDATION
-- ============================================================================

-- Check 1: Find all parsers with Python-style regex syntax
SELECT
  '=== PARSERS WITH PYTHON-STYLE REGEX SYNTAX ===' as check_name,
  '' as spacer;

SELECT
  id,
  name,
  parser_type,
  enabled,
  priority,
  substring(pattern, 1, 150) as pattern_preview,
  CASE
    WHEN pattern LIKE '%(?P<%' THEN 'Python syntax found: (?P<name>...)'
    ELSE 'OK'
  END as issue
FROM parsers
WHERE pattern LIKE '%(?P<%'
  AND parser_type IN ('regex', 'grok')
ORDER BY priority, name;

-- Check 2: Test all regex parsers for JavaScript compatibility
SELECT
  '=== ALL REGEX PARSERS ===' as check_name,
  '' as spacer;

SELECT
  id,
  name,
  parser_type,
  enabled,
  priority,
  substring(pattern, 1, 100) as pattern_start,
  CASE
    WHEN pattern ~ '\(\?P<' THEN 'FAIL: Python syntax'
    WHEN pattern ~ '\(\?<[a-zA-Z_][a-zA-Z0-9_]*>' THEN 'OK: JavaScript named groups'
    WHEN parser_type = 'regex' THEN 'WARN: No named groups found'
    ELSE 'OK'
  END as validation_status
FROM parsers
WHERE parser_type IN ('regex', 'grok')
ORDER BY
  CASE
    WHEN pattern ~ '\(\?P<' THEN 1
    ELSE 2
  END,
  priority,
  name;

-- Check 3: Parser statistics
SELECT
  '=== PARSER STATISTICS ===' as check_name,
  '' as spacer;

SELECT
  parser_type,
  COUNT(*) as total_parsers,
  SUM(CASE WHEN enabled THEN 1 ELSE 0 END) as enabled_parsers,
  SUM(CASE WHEN pattern LIKE '%(?P<%' THEN 1 ELSE 0 END) as python_syntax_issues,
  SUM(CASE WHEN jsonb_array_length(test_samples::jsonb) > 0 THEN 1 ELSE 0 END) as with_test_samples
FROM parsers
GROUP BY parser_type
ORDER BY parser_type;

-- Check 4: List all parsers with their priority and status
SELECT
  '=== ALL PARSERS (ORDERED BY PRIORITY) ===' as check_name,
  '' as spacer;

SELECT
  priority,
  name,
  parser_type,
  enabled,
  jsonb_array_length(test_samples::jsonb) as test_sample_count,
  LENGTH(pattern) as pattern_length,
  created_at::date as created_date
FROM parsers
ORDER BY priority, name;

-- ============================================================================
-- PART 2: DETECTION RULES VALIDATION
-- ============================================================================

-- Check 5: Detection rule statistics
SELECT
  '=== DETECTION RULE STATISTICS ===' as check_name,
  '' as spacer;

SELECT
  severity,
  COUNT(*) as total_rules,
  SUM(CASE WHEN enabled THEN 1 ELSE 0 END) as enabled_rules,
  SUM(CASE WHEN conditions::text LIKE '%regex%' THEN 1 ELSE 0 END) as using_regex
FROM detection_rules
GROUP BY severity
ORDER BY
  CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
    WHEN 'info' THEN 5
  END;

-- Check 6: Rules with regex conditions (potential syntax issues)
SELECT
  '=== DETECTION RULES USING REGEX ===' as check_name,
  '' as spacer;

SELECT
  id,
  name,
  severity,
  enabled,
  conditions::text as conditions_preview
FROM detection_rules
WHERE conditions::text LIKE '%regex%'
ORDER BY
  CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
    WHEN 'info' THEN 5
  END,
  name;

-- Check 7: Rules with invalid JSON structure
SELECT
  '=== DETECTION RULES WITH POTENTIAL JSON ISSUES ===' as check_name,
  '' as spacer;

SELECT
  id,
  name,
  severity,
  enabled,
  CASE
    WHEN conditions IS NULL THEN 'NULL conditions'
    WHEN jsonb_typeof(conditions) != 'object' THEN 'Not a JSON object'
    ELSE 'OK'
  END as issue
FROM detection_rules
WHERE conditions IS NULL
   OR jsonb_typeof(conditions) != 'object'
ORDER BY name;

-- Check 8: All detection rules summary
SELECT
  '=== ALL DETECTION RULES ===' as check_name,
  '' as spacer;

SELECT
  id,
  name,
  severity,
  enabled,
  CASE
    WHEN conditions::text LIKE '%regex%' THEN 'Uses regex'
    ELSE 'No regex'
  END as uses_regex,
  created_at::date as created_date
FROM detection_rules
ORDER BY
  CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
    WHEN 'info' THEN 5
  END,
  name;

-- ============================================================================
-- PART 3: CROSS-CHECK PARSERS AND RULES
-- ============================================================================

-- Check 9: Count totals
SELECT
  '=== OVERALL SYSTEM COUNTS ===' as check_name,
  '' as spacer;

SELECT
  (SELECT COUNT(*) FROM parsers) as total_parsers,
  (SELECT COUNT(*) FROM parsers WHERE enabled) as enabled_parsers,
  (SELECT COUNT(*) FROM parsers WHERE pattern LIKE '%(?P<%') as parsers_with_python_syntax,
  (SELECT COUNT(*) FROM detection_rules) as total_rules,
  (SELECT COUNT(*) FROM detection_rules WHERE enabled) as enabled_rules,
  (SELECT COUNT(*) FROM detection_rules WHERE conditions::text LIKE '%regex%') as rules_using_regex;

-- ============================================================================
-- SUMMARY: CRITICAL ISSUES FOUND
-- ============================================================================

SELECT
  '=== CRITICAL ISSUES SUMMARY ===' as check_name,
  '' as spacer;

SELECT
  'Parsers with Python syntax' as issue_type,
  COUNT(*) as count,
  string_agg(name, ', ') as affected_items
FROM parsers
WHERE pattern LIKE '%(?P<%'
  AND parser_type IN ('regex', 'grok')
UNION ALL
SELECT
  'Detection rules with NULL conditions' as issue_type,
  COUNT(*) as count,
  string_agg(name, ', ') as affected_items
FROM detection_rules
WHERE conditions IS NULL
UNION ALL
SELECT
  'Detection rules with invalid JSON' as issue_type,
  COUNT(*) as count,
  string_agg(name, ', ') as affected_items
FROM detection_rules
WHERE jsonb_typeof(conditions) != 'object';
