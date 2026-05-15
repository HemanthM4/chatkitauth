const HANDOFF_QUERY_PARAM = "handoff_token";

function toBase64Url(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function importHmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function signValue(value, secret) {
  const key = await importHmacKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(signature));
}

async function createSignedToken(payload, secret) {
  const body = toBase64Url(JSON.stringify(payload));
  const signature = await signValue(body, secret);
  return `${body}.${signature}`;
}

export class AuthHandoffService {
  constructor({ worker2RedirectUrl, secret, tokenTtlSeconds = 60 }) {
    this.worker2RedirectUrl = worker2RedirectUrl;
    this.secret = secret;
    this.tokenTtlSeconds = tokenTtlSeconds;
  }

  assertConfigured() {
    if (!this.worker2RedirectUrl) {
      throw new Error("WORKER2_REDIRECT_URL is not configured");
    }

    if (!this.secret) {
      throw new Error("HANDOFF_SECRET is not configured");
    }
  }

  buildPayload(session) {
    const issuedAt = Math.floor(Date.now() / 1000);
    return {
      session_id: session.sessionId,
      first_name: session.firstName || null,
      last_name: session.lastName || null,
      email: session.email || null,
      user_oid: session.oid || null,
      role: session.role,
      licence_type: session.licenseType || null,
      created_at: session.createdAt,
      expires_at: session.sessionTokenExp || session.exp,
      auth_source: "microsoft_entra",
      auth_level: "authenticated",
      iat: issuedAt,
      exp: issuedAt + this.tokenTtlSeconds,
    };
  }

  async createRedirect(session) {
    this.assertConfigured();
    const payload = this.buildPayload(session);
    const token = await createSignedToken(payload, this.secret);
    const url = new URL(this.worker2RedirectUrl);
    url.searchParams.set(HANDOFF_QUERY_PARAM, token);
    return url.toString();
  }
}
