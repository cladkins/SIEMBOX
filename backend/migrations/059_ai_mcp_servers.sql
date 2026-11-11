-- MCP servers the AI Analyst may call (Settings -> AI -> MCP servers). Each row
-- is one remote MCP server reached over Streamable HTTP. `tools` is the tool
-- list as it stood at the last admin-triggered sync: [{ name, description,
-- inputSchema, readOnly, enabled }]. The model only ever sees that stored copy,
-- and only the entries an admin enabled. `auth_value` is the optional request
-- header value, encrypted (CredentialEncryption), and is never returned.
CREATE TABLE IF NOT EXISTS ai_mcp_servers (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  url TEXT NOT NULL,
  auth_header TEXT,
  auth_value TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  triage_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  tools JSONB NOT NULL DEFAULT '[]'::jsonb,
  last_sync_at TIMESTAMPTZ,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
