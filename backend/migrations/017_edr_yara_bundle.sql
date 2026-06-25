-- 017_edr_yara_bundle.sql — server-delivered YARA rule packs for the EDR agent.
--
-- Additive to the EDR feature (016). The endpoint agent pulls a curated YARA
-- bundle when the `yara_rules_version` in its AgentConfig increases. Bundles are
-- stored here (one row per version); the server always serves the highest version
-- from GET /api/edr/agents/:id/yara.
--
-- How a new bundle reaches agents WITHOUT mutating any agent row here: the served
-- config_version is computed as (edr_agents.config_version + current yara version).
-- Inserting a higher-version bundle therefore raises every agent's config_version,
-- so the agent re-pulls its config on the next heartbeat, sees the new
-- yara_rules_version, and downloads the bundle. That keeps this migration fully
-- idempotent (it runs on every startup): seeding v1 is all that's needed.
--
-- Idempotent (CREATE TABLE IF NOT EXISTS / INSERT ... ON CONFLICT DO NOTHING).

CREATE TABLE IF NOT EXISTS edr_yara_bundle (
    version     INTEGER PRIMARY KEY,
    rules       TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    source      TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Seed a small, valid, permissively-licensed starter bundle as version 1. The
-- agent appends its OWN embedded baseline, so identifiers here are SIEMBox_-prefixed
-- to avoid colliding with baseline rule names (a duplicate identifier would fail the
-- agent's combined compile). The sha256 is computed from the exact stored text so
-- the hash always matches the rules.
INSERT INTO edr_yara_bundle (version, rules, sha256, source)
SELECT 1, r, encode(sha256(convert_to(r, 'UTF8')), 'hex'), 'siembox-builtin'
FROM (SELECT $YARABODY$/*
 * SIEMBox EDR — built-in starter YARA bundle (version 1).
 * Curated starter rules served to endpoint agents. Extend with the YARA-Forge
 * refresh job (EDR_YARA_FORGE_ENABLED=true) or POST /api/edr/yara/refresh.
 * The agent appends its embedded baseline (which matches SIEMBOX_YARA_SELFTEST).
 */

rule SIEMBox_EICAR_Test_File
{
    meta:
        author = "SIEMBox"
        description = "EICAR anti-malware test file (standard, harmless test string)"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule SIEMBox_Reverse_Shell_OneLiner
{
    meta:
        author = "SIEMBox"
        description = "Common *nix reverse-shell one-liners written to disk"
    strings:
        $a = "bash -i >& /dev/tcp/" ascii
        $b = "/dev/tcp/" ascii
        $c = "nc -e /bin/sh" ascii
        $d = "import socket,subprocess,os" ascii
    condition:
        any of them
}

rule SIEMBox_Webshell_Generic_PHP
{
    meta:
        author = "SIEMBox"
        description = "Generic PHP webshell exec sinks on user-controlled input"
    strings:
        $e1 = "eval($_POST" ascii nocase
        $e2 = "eval($_GET" ascii nocase
        $e3 = "system($_REQUEST" ascii nocase
        $e4 = "passthru($_GET" ascii nocase
        $e5 = "assert($_POST" ascii nocase
    condition:
        any of them
}
$YARABODY$ AS r) AS seed
ON CONFLICT (version) DO NOTHING;
