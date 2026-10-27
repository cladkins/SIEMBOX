-- Migration 055: machine performance from the endpoint agent.
--
-- Agents that report the 'perf_metrics' capability send a sample about once
-- a minute (CPU, memory, swap, load, uptime, disk use per local mount,
-- network throughput per interface) and the top processes every few minutes
-- to POST /api/edr/metrics (src/services/edr/edrPerformance.ts).
--
--   edr_perf_samples      raw per-minute samples, kept EDR_PERF_RAW_DAYS (7).
--                         Disks and interfaces stay JSONB arrays on the row
--                         (at most 32 / 16 entries): one row per agent and
--                         minute, ~10k rows per endpoint per week.
--   edr_perf_hourly       one row per agent and hour, recomputed from the raw
--                         rows of that hour whenever new samples for it arrive
--                         (so replays and late spooled samples are idempotent),
--                         kept EDR_PERF_HOURLY_DAYS (90). The 7/30/90-day charts
--                         read these: 168 rows per endpoint per week.
--   edr_perf_processes    top processes by CPU and by memory, kept 7 days.
--   edr_perf_latest       the newest sample's headline numbers per agent, for
--                         the Endpoints list (one row per agent, upserted).
--   edr_perf_alert_state  the open performance alert per agent, metric and
--                         target (a disk's mount point, '' for CPU/memory).
--                         A row exists only while its alert is open, so an
--                         episode raises one alert; recovery deletes the row
--                         and notes the recovery on the alert.
--   edr_scan_policies.performance
--                         per policy: metrics on/off, process sampling on/off
--                         and the cpu / memory / disk alert thresholds. The
--                         agent config carries the on/off switches; the
--                         thresholds are evaluated on the server.
--
-- Defaults are configuration, not catalog content: metrics and processes on,
-- alerts on for CPU > 95% for 10 minutes, memory > 95% for 10 minutes and a
-- disk > 90% full.
--
-- Idempotent: re-runs on every start.

CREATE TABLE IF NOT EXISTS edr_perf_samples (
  agent_id    UUID        NOT NULL REFERENCES edr_agents(agent_id) ON DELETE CASCADE,
  ts          TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  cpu_pct     REAL        NOT NULL,
  cpu_count   SMALLINT,
  mem_total   BIGINT      NOT NULL,
  mem_used    BIGINT      NOT NULL,
  swap_total  BIGINT      NOT NULL DEFAULT 0,
  swap_used   BIGINT      NOT NULL DEFAULT 0,
  load1       REAL,
  load5       REAL,
  load15      REAL,
  uptime_s    BIGINT,
  -- [{ "mount": "/", "fs": "ext4", "total": n, "used": n, "free": n, "pct": 41.2 }]
  disks       JSONB       NOT NULL DEFAULT '[]'::jsonb,
  -- [{ "iface": "eth0", "rx": bytes/s, "tx": bytes/s }]
  net         JSONB       NOT NULL DEFAULT '[]'::jsonb,
  PRIMARY KEY (agent_id, ts)
);
-- Retention deletes by time across all agents; rows arrive roughly in time
-- order, which is what BRIN needs (a few pages instead of a B-tree).
CREATE INDEX IF NOT EXISTS idx_edr_perf_samples_ts_brin ON edr_perf_samples USING BRIN (ts);

CREATE TABLE IF NOT EXISTS edr_perf_hourly (
  agent_id      UUID        NOT NULL REFERENCES edr_agents(agent_id) ON DELETE CASCADE,
  hour          TIMESTAMPTZ NOT NULL,
  samples       INTEGER     NOT NULL,
  cpu_avg       REAL        NOT NULL,
  cpu_max       REAL        NOT NULL,
  mem_used_avg  BIGINT      NOT NULL,
  mem_used_max  BIGINT      NOT NULL,
  mem_total     BIGINT      NOT NULL,
  swap_used_avg BIGINT      NOT NULL DEFAULT 0,
  swap_total    BIGINT      NOT NULL DEFAULT 0,
  load1_avg     REAL,
  load1_max     REAL,
  load5_avg     REAL,
  load15_avg    REAL,
  uptime_max    BIGINT,
  -- [{ "mount": "/", "pct_avg": 41.2, "pct_max": 41.3, "used": n, "total": n }]
  disks         JSONB       NOT NULL DEFAULT '[]'::jsonb,
  -- [{ "iface": "eth0", "rx_avg": n, "tx_avg": n, "rx_max": n, "tx_max": n }]
  net           JSONB       NOT NULL DEFAULT '[]'::jsonb,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (agent_id, hour)
);
CREATE INDEX IF NOT EXISTS idx_edr_perf_hourly_hour ON edr_perf_hourly (hour);

CREATE TABLE IF NOT EXISTS edr_perf_processes (
  agent_id UUID        NOT NULL REFERENCES edr_agents(agent_id) ON DELETE CASCADE,
  ts       TIMESTAMPTZ NOT NULL,
  -- [{ "pid": 1, "name": "nginx", "user": "www-data", "cpu_pct": 3.1, "mem_rss": n, "mem_pct": 0.4 }]
  by_cpu   JSONB       NOT NULL DEFAULT '[]'::jsonb,
  by_mem   JSONB       NOT NULL DEFAULT '[]'::jsonb,
  PRIMARY KEY (agent_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_edr_perf_processes_ts ON edr_perf_processes (ts);

CREATE TABLE IF NOT EXISTS edr_perf_latest (
  agent_id       UUID        PRIMARY KEY REFERENCES edr_agents(agent_id) ON DELETE CASCADE,
  ts             TIMESTAMPTZ NOT NULL,
  cpu_pct        REAL        NOT NULL,
  mem_pct        REAL,
  disk_max_pct   REAL,
  disk_max_mount TEXT,
  load1          REAL,
  uptime_s       BIGINT,
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS edr_perf_alert_state (
  agent_id     UUID        NOT NULL REFERENCES edr_agents(agent_id) ON DELETE CASCADE,
  metric       TEXT        NOT NULL CHECK (metric IN ('cpu', 'memory', 'disk')),
  target       TEXT        NOT NULL DEFAULT '',
  alert_id     INTEGER     REFERENCES alerts(id) ON DELETE SET NULL,
  opened_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  opened_value REAL        NOT NULL,
  last_value   REAL        NOT NULL,
  -- When the target was last in a sample (a mount that stops being reported
  -- for an hour closes its alert).
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (agent_id, metric, target)
);

ALTER TABLE edr_scan_policies ADD COLUMN IF NOT EXISTS performance JSONB;
UPDATE edr_scan_policies
   SET performance = '{
         "metrics": true,
         "processes": true,
         "thresholds": {
           "cpu":    {"enabled": true, "percent": 95, "minutes": 10, "severity": "medium"},
           "memory": {"enabled": true, "percent": 95, "minutes": 10, "severity": "medium"},
           "disk":   {"enabled": true, "percent": 90, "minutes": 0,  "severity": "high"}
         }
       }'::jsonb
 WHERE performance IS NULL;
