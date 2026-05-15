PRAGMA defer_foreign_keys=TRUE;
CREATE TABLE d1_migrations(
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		name       TEXT UNIQUE,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);
CREATE TABLE auth_sessions (
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
DELETE FROM sqlite_sequence;
CREATE INDEX idx_auth_sessions_user_oid
ON auth_sessions (user_oid);
CREATE INDEX idx_auth_sessions_email
ON auth_sessions (email);
CREATE INDEX idx_auth_sessions_expires_at
ON auth_sessions (expires_at);

CREATE TABLE auth_login_attempts (
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

CREATE INDEX idx_auth_login_attempts_email
ON auth_login_attempts (email);
CREATE INDEX idx_auth_login_attempts_user_oid
ON auth_login_attempts (user_oid);
CREATE INDEX idx_auth_login_attempts_created_at
ON auth_login_attempts (created_at);
CREATE INDEX idx_auth_login_attempts_success
ON auth_login_attempts (success);
