const MAX_ERROR_MESSAGE_LENGTH = 500;
const MAX_ERROR_CODE_LENGTH = 100;
const MAX_USER_AGENT_LENGTH = 500;
const MAX_TEXT_LENGTH = 255;

function truncateText(value, maxLength) {
  if (value === null || value === undefined) return null;
  const normalized = String(value).replace(/\s+/g, " ").trim();
  if (!normalized) return null;
  return normalized.length > maxLength ? normalized.slice(0, maxLength) : normalized;
}

function normalizeRole(role) {
  return role === "office" || role === "engineer" ? role : null;
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export class AuthAuditService {
  constructor({ auditRepository, ipHashSalt = "", logger = console.error }) {
    this.auditRepository = auditRepository;
    this.ipHashSalt = ipHashSalt;
    this.logger = logger;
  }

  async recordLoginStarted({
    request,
    authSource,
    authLevel = "login_started",
    stateVersion = 1,
    sessionId = null,
    createdAt = Math.floor(Date.now() / 1000),
  }) {
    const requestMetadata = await this.getRequestMetadata(request);
    return this.persistAttempt({
      attemptId: crypto.randomUUID(),
      sessionId,
      success: 0,
      firstName: null,
      lastName: null,
      email: null,
      userOid: null,
      role: null,
      licenceType: null,
      createdAt,
      expiresAt: null,
      authSource,
      authLevel,
      stateVersion,
      errorCode: null,
      errorMessage: null,
      ...requestMetadata,
    });
  }

  async recordSuccess({ request, session, authSource, authLevel = "authenticated", stateVersion = 1 }) {
    const requestMetadata = await this.getRequestMetadata(request);
    return this.persistAttempt({
      attemptId: crypto.randomUUID(),
      sessionId: session.sessionId || null,
      success: 1,
      firstName: truncateText(session.firstName, MAX_TEXT_LENGTH),
      lastName: truncateText(session.lastName, MAX_TEXT_LENGTH),
      email: truncateText(session.email, MAX_TEXT_LENGTH),
      userOid: truncateText(session.oid, MAX_TEXT_LENGTH),
      role: normalizeRole(session.role),
      licenceType: truncateText(session.licenseType, MAX_TEXT_LENGTH),
      createdAt: session.createdAt,
      expiresAt: session.sessionTokenExp || session.exp || null,
      authSource,
      authLevel,
      stateVersion,
      errorCode: null,
      errorMessage: null,
      ...requestMetadata,
    });
  }

  async recordFailure({
    request,
    authSource,
    authLevel,
    stateVersion = 1,
    errorCode,
    errorMessage,
    sessionId = null,
    firstName = null,
    lastName = null,
    email = null,
    userOid = null,
    role = null,
    licenceType = null,
    createdAt = Math.floor(Date.now() / 1000),
    expiresAt = null,
  }) {
    const requestMetadata = await this.getRequestMetadata(request);
    return this.persistAttempt({
      attemptId: crypto.randomUUID(),
      sessionId,
      success: 0,
      firstName: truncateText(firstName, MAX_TEXT_LENGTH),
      lastName: truncateText(lastName, MAX_TEXT_LENGTH),
      email: truncateText(email, MAX_TEXT_LENGTH),
      userOid: truncateText(userOid, MAX_TEXT_LENGTH),
      role: normalizeRole(role),
      licenceType: truncateText(licenceType, MAX_TEXT_LENGTH),
      createdAt,
      expiresAt,
      authSource,
      authLevel,
      stateVersion,
      errorCode: truncateText(errorCode, MAX_ERROR_CODE_LENGTH),
      errorMessage: truncateText(errorMessage, MAX_ERROR_MESSAGE_LENGTH),
      ...requestMetadata,
    });
  }

  async getRequestMetadata(request) {
    const userAgent = truncateText(request.headers.get("user-agent"), MAX_USER_AGENT_LENGTH);
    const ipCountry = truncateText(request.headers.get("cf-ipcountry"), 16);
    const ipAddress = truncateText(
      request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for"),
      128,
    );

    return {
      userAgent,
      ipCountry,
      ipHash: ipAddress ? await sha256Hex(`${this.ipHashSalt}:${ipAddress}`) : null,
    };
  }

  async persistAttempt(attempt) {
    try {
      await this.auditRepository.recordAttempt(attempt);
    } catch (error) {
      this.logger("Failed to persist auth audit row", {
        authLevel: attempt.authLevel,
        error: error.message,
      });
    }
  }
}
