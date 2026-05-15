CREATE TABLE IF NOT EXISTS auth_login_attempts (
  attempt_id TEXT PRIMARY KEY,
  session_id TEXT,

  success INTEGER NOT NULL CHECK (success IN (0, 1)),

  first_name TEXT,
  last_name TEXT,
  email TEXT,
  user_oid TEXT,

  role TEXT CHECK (role IN ('office', 'engineer')),
  licence_type TEXT,

  created_at INTEGER NOT NULL,
  expires_at INTEGER,

  auth_source TEXT NOT NULL,
  auth_level TEXT NOT NULL,
  state_version INTEGER NOT NULL DEFAULT 1,

  error_code TEXT,
  error_message TEXT,

  user_agent TEXT,
  ip_country TEXT,
  ip_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_email
ON auth_login_attempts (email);

CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_user_oid
ON auth_login_attempts (user_oid);

CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_created_at
ON auth_login_attempts (created_at);

CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_success
ON auth_login_attempts (success);
