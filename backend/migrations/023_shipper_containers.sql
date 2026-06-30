-- Container inventory reported by log shippers. Each shipper mounts the Docker
-- socket for log collection; it also reports the images backing its host's
-- containers so SIEMBox can scan them (Trivy) beyond just the SIEMBox host.
-- A report fully replaces a shipper's rows, so this is always the current set.
CREATE TABLE IF NOT EXISTS shipper_containers (
  id SERIAL PRIMARY KEY,
  shipper_id INTEGER NOT NULL REFERENCES log_shippers(id) ON DELETE CASCADE,
  image TEXT NOT NULL,
  image_id TEXT,
  container_names JSONB NOT NULL DEFAULT '[]'::jsonb,
  running INTEGER NOT NULL DEFAULT 0,
  scannable BOOLEAN NOT NULL DEFAULT FALSE,
  reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (shipper_id, image)
);

CREATE INDEX IF NOT EXISTS idx_shipper_containers_shipper ON shipper_containers (shipper_id);
