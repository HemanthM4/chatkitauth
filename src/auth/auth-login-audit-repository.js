const INSERT_AUTH_LOGIN_ATTEMPT_SQL = `
  INSERT INTO auth_login_attempts (
    attempt_id,
    session_id,
    success,
    first_name,
    last_name,
    email,
    user_oid,
    role,
    licence_type,
    created_at,
    expires_at,
    auth_source,
    auth_level,
    state_version,
    error_code,
    error_message,
    user_agent,
    ip_country,
    ip_hash
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

export class AuthLoginAuditRepository {
  constructor(db) {
    this.db = db;
  }

  async recordAttempt(attempt) {
    if (!this.db) {
      throw new Error("D1 binding is not configured");
    }

    await this.db.prepare(INSERT_AUTH_LOGIN_ATTEMPT_SQL).bind(
      attempt.attemptId,
      attempt.sessionId,
      attempt.success,
      attempt.firstName,
      attempt.lastName,
      attempt.email,
      attempt.userOid,
      attempt.role,
      attempt.licenceType,
      attempt.createdAt,
      attempt.expiresAt,
      attempt.authSource,
      attempt.authLevel,
      attempt.stateVersion,
      attempt.errorCode,
      attempt.errorMessage,
      attempt.userAgent,
      attempt.ipCountry,
      attempt.ipHash,
    ).run();
  }
}
