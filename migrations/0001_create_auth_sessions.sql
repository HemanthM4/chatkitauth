CREATE TABLE IF NOT EXISTS auth_sessions (
  session_id TEXT PRIMARY KEY,

  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  email TEXT NOT NULL,
  user_oid TEXT NOT NULL,

  role TEXT NOT NULL CHECK (role IN ('office', 'engineer')),
  licence_type TEXT NOT NULL,

  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,

  auth_source TEXT NOT NULL,
  auth_level TEXT NOT NULL,
  state_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_oid
ON auth_sessions (user_oid);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_email
ON auth_sessions (email);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at
ON auth_sessions (expires_at);