const INSERT_AUTH_SESSION_SQL = `
  INSERT INTO auth_sessions (
    session_id,
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
    state_version
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

export class AuthSessionRepository {
  constructor(db) {
    this.db = db;
  }

  async create(session) {
    if (!this.db) {
      throw new Error("D1 binding is not configured");
    }

    await this.db.prepare(INSERT_AUTH_SESSION_SQL).bind(
      session.sessionId,
      session.firstName,
      session.lastName,
      session.email,
      session.userOid,
      session.role,
      session.licenceType,
      session.createdAt,
      session.expiresAt,
      session.authSource,
      session.authLevel,
      session.stateVersion,
    ).run();
  }
}
