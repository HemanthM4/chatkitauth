import { AuthAuditService } from "./auth/auth-audit-service.js";
import { AuthHandoffService } from "./auth/auth-handoff-service.js";
import { AuthLoginAuditRepository } from "./auth/auth-login-audit-repository.js";
import { AuthSessionRepository } from "./auth/auth-session-repository.js";

const rolePermissions = {
  office: ["view_invoices", "view_client_records", "approve_status_changes"],
  engineer: ["view_service_reports", "view_engineer_jobs", "update_job_status"],
};

const svgLogo = `<svg width="64" height="64" viewBox="0 0 35 35" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<path d="M34.1277 14.6954L24.7885 1.26829C24.2403 0.472108 23.332 0 22.3677 0H2.94901C1.32445 0 0 1.3243 0 2.94867V32.0513C0 33.6757 1.32445 35 2.94901 35H22.3597C23.324 35 24.2283 34.5279 24.7805 33.7357L34.1237 20.3046C35.2921 18.6243 35.2921 16.3717 34.1237 14.6914" fill="#27549D"/>
<path d="M4.80566 6.04923C4.80566 5.37308 5.35385 4.82495 6.03008 4.82495H9.15515C9.49127 4.82495 9.76736 5.10101 9.76736 5.43709V9.72207C9.76736 10.0581 9.49127 10.3342 9.15515 10.3342H6.03008C5.35385 10.3342 4.80566 9.78609 4.80566 9.10993V6.04923Z" fill="#F1FF24"/>
<path d="M4.80566 13.2151C4.80566 12.539 5.35385 11.9908 6.03008 11.9908H9.15515C9.49127 11.9908 9.76736 12.2669 9.76736 12.603V16.888C9.76736 17.228 9.49127 17.5001 9.15515 17.5001H6.03008C5.35385 17.5001 4.80566 16.952 4.80566 16.2758V13.2151Z" fill="#F1FF24"/>
<path d="M16.9338 29.5626C16.9338 29.8987 16.6577 30.1748 16.3216 30.1748H6.03008C5.35385 30.1748 4.80566 29.6266 4.80566 28.9505V26.99C4.80566 26.3139 5.35385 25.7657 6.03008 25.7657H16.3176C16.6577 25.7657 16.9298 26.0418 16.9298 26.3779V29.5626H16.9338Z" fill="#F1FF24"/>
<path d="M16.9338 23.5015C16.9338 23.8376 16.6577 24.1136 16.3216 24.1136H6.03008C5.35385 24.1136 4.80566 23.5655 4.80566 22.8893V20.3808C4.80566 19.7046 5.35385 19.1565 6.03008 19.1565H16.3176C16.6577 19.1565 16.9298 19.4326 16.9298 19.7686V23.5055L16.9338 23.5015Z" fill="#F1FF24"/>
<path d="M28.9495 19.6003L21.9551 29.6506C21.727 29.9787 21.3509 30.1747 20.9507 30.1747H19.1981C18.862 30.1747 18.5859 29.8987 18.5859 29.5626V12.6027C18.5859 12.2627 18.3098 11.9906 17.9737 11.9906H17.5456C17.2054 11.9906 16.9334 12.2667 16.9334 12.6027V16.2756C16.9334 16.9517 16.3852 17.4998 15.7089 17.4998H12.6479C11.9717 17.4998 11.4235 16.9517 11.4235 16.2756V5.43709C11.4235 5.09701 11.6996 4.82495 12.0357 4.82495H20.9547C21.3549 4.82495 21.731 5.021 21.9591 5.34907L28.9495 15.3994C29.8258 16.6597 29.8258 18.332 28.9495 19.5963" fill="#F1FF24"/>
</svg>`;

const MICROSOFT_SCOPES = "openid profile email offline_access User.Read";
const SESSION_COOKIE = "chumley_session";
const STATE_COOKIE = "chumley_oauth_state";
const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 hours
const AUTH_SOURCE = "microsoft_entra";
const AUTH_STATE_VERSION = 1;

// ── LOGGING ──────────────────────────────────────────────
function log(label, msg, data = "") {
  const out = data ? `[${label}] ${msg} → ${JSON.stringify(data)}` : `[${label}] ${msg}`;
  console.log(out);
}

function sanitizeAuthQueryParams(params) {
  const sensitiveKeys = new Set(["code", "state", "code_challenge", "code_verifier", "access_token", "refresh_token", "id_token", "handoff_token"]);
  const entries = params instanceof URLSearchParams ? params.entries() : Object.entries(params || {});
  const sanitized = {};

  for (const [key, value] of entries) {
    sanitized[key] = sensitiveKeys.has(key) ? "[redacted]" : value;
  }

  return sanitized;
}

function sanitizeRedirectLocation(location) {
  try {
    const url = new URL(location);
    for (const key of ["code", "state", "code_challenge", "code_verifier", "access_token", "refresh_token", "id_token", "handoff_token"]) {
      if (url.searchParams.has(key)) {
        url.searchParams.set(key, "[redacted]");
      }
    }
    return url.toString();
  } catch {
    return location;
  }
}

// ── URL / CORS ────────────────────────────────────────────
function getRedirectUri(request, env) {
  if (env.AUTH_REDIRECT_URI) {
    log("getRedirectUri", "Using AUTH_REDIRECT_URI from env", env.AUTH_REDIRECT_URI);
    return env.AUTH_REDIRECT_URI;
  }
  const uri = `${new URL(request.url).origin}/auth/callback`;
  log("getRedirectUri", "Auto-built redirect URI", uri);
  return uri;
}

function getCorsHeaders(origin) {
  return {
    "access-control-allow-origin": origin || "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization",
    vary: "Origin",
  };
}

function jsonResponse(data, status = 200, origin = "*", extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json;charset=UTF-8", ...getCorsHeaders(origin), ...extraHeaders },
  });
}

function htmlResponse(html, status = 200, extraHeaders = {}) {
  return new Response(html, {
    status,
    headers: { "content-type": "text/html;charset=UTF-8", "cache-control": "no-store", ...extraHeaders },
  });
}

function redirectResponse(location, cookies = []) {
  log("redirectResponse", "Redirecting to", sanitizeRedirectLocation(location));
  const headers = new Headers({ location, "cache-control": "no-store" });
  for (const cookie of cookies) headers.append("Set-Cookie", cookie);
  return new Response(null, { status: 302, headers });
}

// ── BASE64 HELPERS ────────────────────────────────────────
function toBase64Url(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(input) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "===".slice((normalized.length + 3) % 4);
  return atob(padded);
}

function decodeJsonBase64Url(input) {
  return JSON.parse(fromBase64Url(input));
}

function randomBase64Url(bytes = 32) {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(digest));
}

// ── COOKIES ───────────────────────────────────────────────
function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  for (const part of cookieHeader.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (!rawName) continue;
    cookies[rawName] = rawValue.join("=");
  }
  return cookies;
}

function getCookieOptions(request, maxAge = SESSION_TTL_SECONDS) {
  const url = new URL(request.url);
  const secure = url.protocol === "https:";
  return ["Path=/", "HttpOnly", "SameSite=Lax", secure ? "Secure" : "", `Max-Age=${maxAge}`]
    .filter(Boolean).join("; ");
}

function buildCookie(name, value, request, maxAge = SESSION_TTL_SECONDS) {
  return `${name}=${value}; ${getCookieOptions(request, maxAge)}`;
}

function buildExpiredCookie(name, request) {
  return `${name}=; ${getCookieOptions(request, 0)}`;
}

// ── SIGNED TOKENS (session security) ─────────────────────
async function importHmacKey(secret) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
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

async function verifySignedToken(token, secret) {
  if (!token || !token.includes(".")) {
    log("verifySignedToken", "❌ Token missing or has no dot separator");
    return null;
  }
  const [body, signature] = token.split(".");
  const expectedSignature = await signValue(body, secret);
  if (signature !== expectedSignature) {
    log("verifySignedToken", "❌ Signature mismatch - token tampered or wrong secret");
    return null;
  }
  const payload = decodeJsonBase64Url(body);
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    log("verifySignedToken", "❌ Token expired");
    return null;
  }
  log("verifySignedToken", "✅ Token valid");
  return payload;
}

function decodeJwtPart(token, index) {
  return decodeJsonBase64Url(token.split(".")[index]);
}

// ── MICROSOFT AUTH ────────────────────────────────────────
async function getMicrosoftOpenIdConfiguration(tenantId) {
  const configUrl = `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`;
  log("getMicrosoftOpenIdConfiguration", "Fetching OpenID config from", configUrl);
  const response = await fetch(configUrl);
  if (!response.ok) throw new Error(`Failed to load OpenID config: ${response.status}`);
  log("getMicrosoftOpenIdConfiguration", "✅ OpenID config loaded");
  return response.json();
}

function isAllowedCompanyUser(claims, env) {
  log("isAllowedCompanyUser", "Checking tenant", { claimTid: claims.tid, envTid: env.MICROSOFT_TENANT_ID });
  if (claims.tid !== env.MICROSOFT_TENANT_ID) {
    log("isAllowedCompanyUser", "❌ Tenant ID mismatch - user is from wrong organisation");
    return false;
  }
  if (env.ALLOWED_EMAIL_DOMAIN) {
    const email = (claims.preferred_username || claims.email || "").toLowerCase();
    const allowed = email.endsWith(`@${env.ALLOWED_EMAIL_DOMAIN.toLowerCase()}`);
    log("isAllowedCompanyUser", allowed ? "✅ Email domain allowed" : "❌ Email domain not allowed", email);
    return allowed;
  }
  log("isAllowedCompanyUser", "✅ User allowed (no domain restriction set)");
  return true;
}

function getRoleFromClaims(claims) {
  log("getRoleFromClaims", "Checking roles claim", claims.roles);
  const roles = Array.isArray(claims.roles) ? claims.roles : [];
  const normalized = roles.map((r) => String(r).toLowerCase());
  if (normalized.includes("engineer")) { log("getRoleFromClaims", "✅ Role: engineer"); return "engineer"; }
  if (normalized.includes("office"))   { log("getRoleFromClaims", "✅ Role: office");   return "office"; }
  log("getRoleFromClaims", "⚠️ No role found in token — defaulting to office");
  return "office";
}

async function verifyIdToken(idToken, tenantId, clientId) {
  log("verifyIdToken", "Starting ID token verification...");
  const config = await getMicrosoftOpenIdConfiguration(tenantId);

  log("verifyIdToken", "Fetching signing keys from", config.jwks_uri);
  const keysResponse = await fetch(config.jwks_uri);
  if (!keysResponse.ok) throw new Error(`Failed to load signing keys: ${keysResponse.status}`);

  const { keys } = await keysResponse.json();
  log("verifyIdToken", `Got ${keys.length} signing keys from Microsoft`);

  const header = decodeJwtPart(idToken, 0);
  const claims = decodeJwtPart(idToken, 1);
  log("verifyIdToken", "Token header kid", header.kid);
  log("verifyIdToken", "Token claims", { aud: claims.aud, tid: claims.tid, iss: claims.iss, exp: claims.exp, name: claims.name });

  const jwk = keys.find((key) => key.kid === header.kid);
  if (!jwk) throw new Error(`No matching signing key found for kid: ${header.kid}`);
  log("verifyIdToken", "✅ Found matching signing key");

  const cryptoKey = await crypto.subtle.importKey("jwk", jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);

  const [encodedHeader, encodedPayload, encodedSignature] = idToken.split(".");
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey,
    Uint8Array.from(fromBase64Url(encodedSignature), (c) => c.charCodeAt(0)),
    new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`));

  if (!valid) throw new Error("❌ Token signature verification failed");
  log("verifyIdToken", "✅ Signature valid");

  const now = Math.floor(Date.now() / 1000);
  if (claims.aud !== clientId) throw new Error(`❌ Token audience mismatch. Got: ${claims.aud} | Expected: ${clientId}`);
  if (claims.tid !== tenantId) throw new Error(`❌ Token tenant mismatch. Got: ${claims.tid} | Expected: ${tenantId}`);
  if (claims.exp <= now)       throw new Error(`❌ Token expired at ${new Date(claims.exp * 1000).toISOString()}`);

  const expectedIssuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;
  if (claims.iss !== expectedIssuer) throw new Error(`❌ Issuer mismatch. Got: ${claims.iss} | Expected: ${expectedIssuer}`);

  log("verifyIdToken", "✅ ALL checks passed — token is valid!");
  return claims;
}

async function exchangeCodeForTokens({ code, request, env, codeVerifier }) {
  const tokenUrl = `https://login.microsoftonline.com/${env.MICROSOFT_TENANT_ID}/oauth2/v2.0/token`;
  const redirectUri = getRedirectUri(request, env);
  log("exchangeCodeForTokens", "Exchanging code for tokens", { tokenUrl, redirectUri });

  const body = new URLSearchParams({
    client_id:     env.MICROSOFT_CLIENT_ID,
    client_secret: env.MICROSOFT_CLIENT_SECRET,
    grant_type:    "authorization_code",
    code,
    redirect_uri:  redirectUri,
    scope:         MICROSOFT_SCOPES,
    code_verifier: codeVerifier || "",
  });

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });

  const data = await response.json();
  if (!response.ok) {
    log("exchangeCodeForTokens", "❌ Token exchange failed", { error: data.error, description: data.error_description });
    throw new Error(data.error_description || data.error || "Token exchange failed");
  }
  log("exchangeCodeForTokens", "✅ Token exchange successful");
  return data;
}

function microsoftAuthorizeUrl(request, env, state) {
  const redirectUri = getRedirectUri(request, env);
  log("microsoftAuthorizeUrl", "Building authorize URL", { redirectUri });
  const params = new URLSearchParams({
    client_id:     env.MICROSOFT_CLIENT_ID,
    response_type: "code",
    redirect_uri:  redirectUri,
    response_mode: "query",
    scope:         MICROSOFT_SCOPES,
    state,
    prompt:        "select_account",
  });
  return `https://login.microsoftonline.com/${env.MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize?${params.toString()}`;
}

// ── MICROSOFT GRAPH API ───────────────────────────────────
async function getUserGraphDetails(accessToken, oid) {
  log("getUserGraphDetails", "Fetching Graph data for OID", oid);

  let firstName = "";
  let lastName  = "";
  try {
    const meRes = await fetch("https://graph.microsoft.com/v1.0/me?$select=givenName,surname",
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    if (meRes.ok) {
      const me = await meRes.json();
      firstName = me.givenName || "";
      lastName  = me.surname   || "";
      log("getUserGraphDetails", "✅ /me profile fetched", { firstName, lastName });
    } else {
      log("getUserGraphDetails", "⚠️ /me fetch failed", { status: meRes.status });
    }
  } catch (e) {
    log("getUserGraphDetails", "⚠️ /me fetch error", e.message);
  }

  let licenseType = "Unknown";
  try {
    const licenseRes = await fetch(
      `https://graph.microsoft.com/v1.0/users/${oid}/licenseDetails`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    if (licenseRes.ok) {
      const licenseData = await licenseRes.json();
      licenseType = licenseData.value?.[0]?.skuPartNumber || "No licence assigned";
      log("getUserGraphDetails", "✅ Licence fetched", licenseType);
    } else {
      const errText = await licenseRes.text();
      log("getUserGraphDetails", "⚠️ Licence fetch failed", { status: licenseRes.status, body: errText });
    }
  } catch (e) {
    log("getUserGraphDetails", "⚠️ Licence fetch error", e.message);
  }

  let roleId = "Unknown";
  try {
    const rolesRes = await fetch(
      `https://graph.microsoft.com/v1.0/users/${oid}/appRoleAssignments`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    if (rolesRes.ok) {
      const rolesData = await rolesRes.json();
      roleId = rolesData.value?.[0]?.appRoleId || "No role assigned";
      log("getUserGraphDetails", "✅ Role ID fetched", roleId);
    } else {
      const errText = await rolesRes.text();
      log("getUserGraphDetails", "⚠️ Role assignment fetch failed", { status: rolesRes.status, body: errText });
    }
  } catch (e) {
    log("getUserGraphDetails", "⚠️ Role assignment fetch error", e.message);
  }

  return { licenseType, roleId, firstName, lastName };
}

// ── SESSION ───────────────────────────────────────────────

// ✅ NEW: Helper to format a Unix timestamp as a readable date string
function formatExpiry(unixSeconds) {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toUTCString();
}

// ✅ MODIFIED: now accepts tokenData from the MS token exchange response
function buildSessionPayload(claims, licenseType = "Unknown", roleId = "Unknown", firstName = "", lastName = "", tokenData = {}, sessionId = crypto.randomUUID()) {
  const now  = Math.floor(Date.now() / 1000);
  const role = getRoleFromClaims(claims);
  const nameParts = (claims.name || "").trim().split(/\s+/);

  // ── Token expiry times ──────────────────────────────────
  // Access token: Microsoft returns expires_in (seconds from now), default 3600 (1 hr)
  const accessTokenExp   = now + (tokenData.expires_in   || 3600);

  // Refresh token: Microsoft default is 90 days inactive / 1 year max.
  // ext_expires_in is sometimes returned; otherwise we default to 90 days.
  const refreshTokenExp  = now + (tokenData.ext_expires_in || 90 * 24 * 60 * 60);

  // ID token: expiry is embedded in the claims itself
  const idTokenExp       = claims.exp || (now + 3600);

  // Session token: our own cookie TTL (8 hours)
  const sessionTokenExp  = now + SESSION_TTL_SECONDS;

  const session = {
    sessionId,
    name:        claims.name || claims.preferred_username,
    firstName:   firstName || claims.given_name  || nameParts[0] || "",
    lastName:    lastName  || claims.family_name || nameParts.slice(1).join(" ") || "",
    email:       claims.preferred_username || claims.email || "",
    role,
    roleId,
    licenseType,
    oid:         claims.oid,
    tid:         claims.tid,
    permissions: rolePermissions[role] || [],

    // ✅ Token expiry timestamps (Unix seconds)
    createdAt:        now,
    accessTokenExp,
    refreshTokenExp,
    idTokenExp,
    sessionTokenExp,

    // exp drives cookie/session verification (keep = sessionTokenExp)
    exp: sessionTokenExp,
  };

  log("buildSessionPayload", "Session built with token expiry", {
    accessTokenExp:  formatExpiry(accessTokenExp),
    refreshTokenExp: formatExpiry(refreshTokenExp),
    idTokenExp:      formatExpiry(idTokenExp),
    sessionTokenExp: formatExpiry(sessionTokenExp),
  });

  return session;
}

async function getSession(request, env) {
  log("getSession", "Checking for existing session cookie...");
  const cookies = parseCookies(request.headers.get("Cookie"));
  if (!cookies[SESSION_COOKIE]) {
    log("getSession", "❌ No session cookie found");
    return null;
  }
  const session = await verifySignedToken(cookies[SESSION_COOKIE], env.SESSION_SECRET || env.MICROSOFT_CLIENT_SECRET);
  if (session) log("getSession", "✅ Session valid for", session.email);
  return session;
}

// ── HTML PAGES ────────────────────────────────────────────
function loginPage(errorMessage = "") {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Chumley Support AI</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;700;800&display=swap" rel="stylesheet" />
    <style>
      :root { --bg:#9bb6df;--card:rgba(255,255,255,0.97);--ink:#17315c;--muted:#5f6f94;--brand:#4d61b8;--brand-strong:#394d9e;--line:rgba(40,69,138,0.12);--shadow:0 36px 90px rgba(31,61,126,0.18); }
      * { box-sizing:border-box; }
      body {
        margin:0;
        min-height:100vh;
        font-family:'Montserrat',sans-serif;
        color:var(--ink);
        background:
          linear-gradient(135deg, rgba(255,255,255,0.22) 0 32%, rgba(255,255,255,0) 32.2%),
          linear-gradient(196deg, rgba(122,153,210,0.34) 0 36%, rgba(122,153,210,0) 36.2%),
          linear-gradient(180deg, rgba(255,255,255,0.1), rgba(255,255,255,0.1)),
          radial-gradient(95% 78% at 44% 98%, rgba(111,142,199,0.78) 0 58%, rgba(111,142,199,0) 58.4%),
          linear-gradient(180deg, #9cb6de 0%, #8eaad4 100%);
        display:grid;
        place-items:center;
        overflow:hidden;
      }
      .shell { width:min(92vw,448px);padding:20px; }
      .card { background:var(--card);border-radius:24px;box-shadow:var(--shadow);border:1px solid rgba(255,255,255,0.7);padding:48px;text-align:center;animation:rise 400ms ease-out; }
      .logo { width:96px;height:96px;margin:0 auto 20px;display:grid;place-items:center; }
      .logo svg { width:100%;height:100%; }
      h1 { margin:0 0 8px;font-size:1.875rem;line-height:1.2;letter-spacing:-0.01em;font-weight:700; }
      p { margin:0 0 32px;color:var(--muted);font-size:0.95rem; }
      .error { margin:0 0 16px;padding:12px 16px;border-radius:12px;background:rgba(229,73,83,0.09);color:#ac2431;font-size:0.9rem;text-align:left;line-height:1.5; }
      .signin { display:inline-flex;align-items:center;justify-content:center;gap:12px;width:100%;padding:16px 24px;border-radius:16px;color:#fff;background:var(--brand);text-decoration:none;font-size:1rem;font-weight:700;box-shadow:0 10px 24px rgba(57,87,168,0.28);transition:background 180ms ease,box-shadow 180ms ease,transform 180ms ease; }
      .signin:hover { background:var(--brand-strong);box-shadow:0 14px 28px rgba(57,87,168,0.34);transform:translateY(-1px); }
      .ms { display:grid;grid-template-columns:repeat(2,9px);grid-template-rows:repeat(2,9px);gap:2px; }
      .ms span:nth-child(1){background:#f35325} .ms span:nth-child(2){background:#81bc06} .ms span:nth-child(3){background:#05a6f0} .ms span:nth-child(4){background:#ffba08}
      .footer { margin-top:24px;padding-top:20px;border-top:1px solid var(--line);display:flex;justify-content:center;align-items:center;gap:10px;color:#65749a;font-size:0.9rem; }
      .footer strong { color:var(--ink);font-weight:700; }
      @keyframes rise { from{opacity:0;transform:translateY(14px)} to{opacity:1;transform:translateY(0)} }
    </style>
  </head>
  <body>
    <main class="shell">
      <section class="card">
        <div class="logo">${svgLogo}</div>
        <h1>Chumley Support AI</h1>
        <p>Sign in to access the dashboard</p>
        ${errorMessage ? `<div class="error">⚠️ ${errorMessage}</div>` : ""}
        <a class="signin" href="/auth/login">
          <span class="ms" aria-hidden="true"><span></span><span></span><span></span><span></span></span>
          <span>Sign in with Microsoft</span>
        </a>
        <div class="footer"><span>☎</span><span><strong>Chumley Support AI</strong></span></div>
      </section>
    </main>
  </body>
</html>`;
}

// ✅ NEW: Build a single token row for the expiry table
function tokenRow(label, expiryUnix, defaultLabel) {
  const expiryStr = expiryUnix ? new Date(expiryUnix * 1000).toLocaleString() : "—";
  return `
    <tr data-exp="${expiryUnix || 0}">
      <td><strong>${label}</strong><br><span style="color:#66779f;font-size:0.78rem;">${defaultLabel}</span></td>
      <td style="font-size:0.82rem;color:#444;">${expiryStr}</td>
      <td class="remaining" style="font-size:0.9rem;font-weight:700;color:#17315c;font-variant-numeric:tabular-nums;">—</td>
      <td class="status-cell"><span class="status-badge" style="display:inline-block;padding:3px 10px;border-radius:999px;font-size:0.78rem;font-weight:700;">—</span></td>
    </tr>`;
}

function dashboardPage(session) {
  const permissions = session.permissions.map((p) => `<li>${p.replace(/_/g, " ")}</li>`).join("");

  // ✅ Token expiry table rows
  const tokenRows = [
    tokenRow("Access Token",   session.accessTokenExp,   "Default: 1 hour"),
    tokenRow("Refresh Token",  session.refreshTokenExp,  "Default: 90 days"),
    tokenRow("ID Token",       session.idTokenExp,       "Default: 1 hour"),
    tokenRow("Session Token",  session.sessionTokenExp,  "Default: 8 hours (this app)"),
  ].join("");

  const loginTime = session.createdAt
    ? new Date(session.createdAt * 1000).toLocaleString()
    : "—";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Chumley Support AI Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;700;800&display=swap" rel="stylesheet" />
    <style>
      :root{--page:#f5f7fb;--surface:#ffffff;--ink:#17315c;--muted:#66779f;--brand:#3957a8;--line:#dbe5fb;--ok:#eaf7eb;}
      *{box-sizing:border-box;}
      body{margin:0;min-height:100vh;font-family:'Montserrat',sans-serif;color:var(--ink);background:linear-gradient(180deg,#f7f9fc 0%,#eef3f9 100%);padding:28px;}
      .wrap{max-width:1180px;margin:0 auto;}
      .topbar{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:24px;padding:8px 0;}
      .brand{display:flex;align-items:center;gap:14px;}
      .brand svg{width:48px;height:48px;}
      .brand h1{margin:0;font-size:clamp(1.4rem,3vw,2.2rem);}
      .brand p{margin:4px 0 0;color:var(--muted);}
      .logout{display:inline-flex;align-items:center;justify-content:center;padding:12px 18px;border-radius:999px;border:1px solid #cfd8eb;background:var(--surface);color:var(--ink);text-decoration:none;font-weight:700;box-shadow:0 8px 20px rgba(23,49,92,0.06);}
      .grid{display:grid;grid-template-columns:1.2fr 0.8fr;gap:20px;margin-bottom:20px;}
      .panel{background:var(--surface);border:1px solid var(--line);border-radius:24px;padding:24px;box-shadow:0 14px 32px rgba(29,58,126,0.08);}
      .eyebrow{display:inline-block;background:var(--ok);color:#2f7a37;padding:8px 12px;border-radius:999px;font-size:0.86rem;font-weight:700;}
      h2{margin:16px 0 10px;font-size:1.6rem;}
      h3{margin:0 0 16px;font-size:1.1rem;color:var(--ink);}
      ul{margin:16px 0 0;padding-left:20px;color:var(--muted);}
      li+li{margin-top:10px;}
      .stat{margin-top:18px;padding:16px;border-radius:18px;background:#f7f9ff;border:1px solid var(--line);}
      .meta{display:grid;gap:14px;}
      .meta strong{display:block;margin-bottom:6px;}
      .muted{color:var(--muted);}
      .badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:0.8rem;font-weight:700;background:#e8eeff;color:var(--brand);}

      /* ── Token expiry table (inside profile panel) ── */
      .divider { margin:18px 0;border:none;border-top:1px solid var(--line); }
      .section-label { display:flex;align-items:center;gap:8px;margin-bottom:14px;font-size:0.82rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--brand); }
      .token-table { width:100%;border-collapse:collapse;font-size:0.82rem; }
      .token-table thead th { text-align:left;padding:8px 10px;background:#f0f4ff;color:var(--brand);font-weight:700;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.04em; }
      .token-table thead th:first-child { border-radius:10px 0 0 10px; }
      .token-table thead th:last-child  { border-radius:0 10px 10px 0; }
      .token-table tbody td { padding:10px 10px;border-bottom:1px solid var(--line);vertical-align:middle; }
      .token-table tbody tr:last-child td { border-bottom:none; }
      .token-table tbody tr:hover td { background:#f7f9ff; }
      .login-time { margin-top:12px;padding:8px 12px;border-radius:10px;background:#f7f9ff;border:1px solid var(--line);font-size:0.8rem;color:var(--muted); }
      .login-time strong { color:var(--ink); }

      @media(max-width:860px){body{padding:18px;}.topbar{align-items:flex-start;flex-direction:column;}.grid{grid-template-columns:1fr;}}
    </style>
  </head>
  <body>
    <div class="wrap">
      <header class="topbar">
        <div class="brand">${svgLogo}<div><h1>Chumley SUPPORT AI</h1><p>Signed in as <strong>${escapeHtml(session.role)}</strong></p></div></div>
        <a class="logout" href="/auth/logout">Sign out</a>
      </header>

      <!-- ── Top row: welcome + profile ── -->
      <section class="grid">
        <article class="panel">
          <span class="eyebrow">✅ Authenticated</span>
          <h2>Welcome, ${escapeHtml(session.firstName || session.name)}</h2>
          <p class="muted">Your role is <strong>${escapeHtml(session.role)}</strong> — secured by Microsoft Entra.</p>
          <div class="stat"><strong>Your permissions</strong><ul>${permissions}</ul></div>
        </article>
        <aside class="panel meta">
          <!-- Profile fields -->
          <div><strong>First Name</strong><span class="muted">${escapeHtml(session.firstName || "—")}</span></div>
          <div><strong>Last Name</strong><span class="muted">${escapeHtml(session.lastName  || "—")}</span></div>
          <div><strong>Email</strong><span class="muted">${escapeHtml(session.email)}</span></div>
          <div><strong>Role Name</strong><span class="badge">${escapeHtml(session.role)}</span></div>
          <div><strong>User ID (OID)</strong><span class="muted">${escapeHtml(session.oid || "—")}</span></div>
          <div><strong>Licence Type</strong><span class="badge">${escapeHtml(session.licenseType || "—")}</span></div>
          <div><strong>Tenant ID</strong><span class="muted">${escapeHtml(session.tid)}</span></div>

          <!-- ✅ Token expiry table — same panel, below profile -->
          <hr class="divider" />
          <div class="section-label">🔐 Token &amp; Session Expiry</div>
          <table class="token-table">
            <thead>
              <tr>
                <th>Token Type</th>
                <th>Expires At</th>
                <th>Remaining</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${tokenRows}
            </tbody>
          </table>
          <div class="login-time">🕐 Session started: <strong>${escapeHtml(loginTime)}</strong></div>
        </aside>
      </section>
    </div>
    <script>
      function fmtRemaining(sec) {
        if (sec <= 0) return "Expired";
        const d = Math.floor(sec / 86400);
        const h = Math.floor((sec % 86400) / 3600);
        const m = Math.floor((sec % 3600) / 60);
        const s = sec % 60;
        if (d > 0) return d + "d " + h + "h " + m + "m " + String(s).padStart(2,"0") + "s";
        if (h > 0) return h + "h " + m + "m " + String(s).padStart(2,"0") + "s";
        return m + "m " + String(s).padStart(2,"0") + "s";
      }

      function tick() {
        const now = Math.floor(Date.now() / 1000);
        document.querySelectorAll("tr[data-exp]").forEach(function(row) {
          const exp = parseInt(row.dataset.exp, 10);
          if (!exp) return;
          const remaining = exp - now;
          const remCell  = row.querySelector(".remaining");
          const badge    = row.querySelector(".status-badge");
          if (!remCell || !badge) return;

          remCell.textContent = fmtRemaining(remaining);

          if (remaining <= 0) {
            badge.textContent = "Expired";
            badge.style.background = "#fdecea";
            badge.style.color = "#ac2431";
            remCell.style.color = "#ac2431";
          } else if (remaining < 300) {
            badge.textContent = "< 5 min";
            badge.style.background = "#fdecea";
            badge.style.color = "#ac2431";
            remCell.style.color = "#ac2431";
          } else if (remaining < 600) {
            badge.textContent = "Expiring";
            badge.style.background = "#fef3cd";
            badge.style.color = "#b45309";
            remCell.style.color = "#b45309";
          } else {
            badge.textContent = "Active";
            badge.style.background = "#eaf7eb";
            badge.style.color = "#2f7a37";
            remCell.style.color = "#17315c";
          }
        });
      }

      tick();
      setInterval(tick, 1000);
    </script>
  </body>
</html>`;
}

function escapeHtml(value) {
  return String(value).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;");
}

function createAuthPersistence(env) {
  const db = env.chumley_auth_db;
  return {
    sessionRepository: new AuthSessionRepository(db),
    auditService: new AuthAuditService({
      auditRepository: new AuthLoginAuditRepository(db),
      ipHashSalt: env.SESSION_SECRET || env.MICROSOFT_CLIENT_SECRET || "",
      logger: (message, data) => log("AuthAuditService", message, data),
    }),
    handoffService: new AuthHandoffService({
      worker2RedirectUrl: env.WORKER2_REDIRECT_URL,
      secret: env.HANDOFF_SECRET,
    }),
  };
}

function buildPersistedSession(session) {
  return {
    sessionId: session.sessionId,
    firstName: session.firstName || "",
    lastName: session.lastName || "",
    email: session.email || "",
    userOid: session.oid || "",
    role: session.role,
    licenceType: session.licenseType || "",
    createdAt: session.createdAt,
    expiresAt: session.sessionTokenExp || session.exp,
    authSource: AUTH_SOURCE,
    authLevel: "authenticated",
    stateVersion: AUTH_STATE_VERSION,
  };
}

// ── MAIN WORKER ───────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || url.origin;
    const { sessionRepository, auditService, handoffService } = createAuthPersistence(env);

    log("Worker", `▶ ${request.method} ${url.pathname}`);

    if (request.method === "OPTIONS") {
      log("Worker", "OPTIONS preflight — returning 204");
      return new Response(null, { status: 204, headers: getCorsHeaders(origin) });
    }

    log("Worker", "Checking env secrets...");
    log("Worker", `MICROSOFT_CLIENT_ID:     ${env.MICROSOFT_CLIENT_ID     ? "✅ loaded" : "❌ MISSING"}`);
    log("Worker", `MICROSOFT_TENANT_ID:     ${env.MICROSOFT_TENANT_ID     ? "✅ loaded" : "❌ MISSING"}`);
    log("Worker", `MICROSOFT_CLIENT_SECRET: ${env.MICROSOFT_CLIENT_SECRET ? "✅ loaded" : "❌ MISSING"}`);
    log("Worker", `SESSION_SECRET:          ${env.SESSION_SECRET          ? "✅ loaded" : "⚠️ not set (using client secret)"}`);
    log("Worker", `AUTH_REDIRECT_URI:       ${env.AUTH_REDIRECT_URI       ? "✅ " + env.AUTH_REDIRECT_URI : "⚠️ not set (will auto-build)"}`);
    log("Worker", `WORKER2_REDIRECT_URL:    ${env.WORKER2_REDIRECT_URL    ? "✅ " + env.WORKER2_REDIRECT_URL : "❌ MISSING"}`);
    log("Worker", `HANDOFF_SECRET:         ${env.HANDOFF_SECRET         ? "✅ loaded" : "❌ MISSING"}`);

    if (!env.MICROSOFT_CLIENT_ID || !env.MICROSOFT_TENANT_ID || !env.MICROSOFT_CLIENT_SECRET) {
      log("Worker", "❌ Missing required env secrets — returning 500");
      return jsonResponse({ ok: false, error: "Missing Microsoft auth configuration in Worker secrets." }, 500, origin);
    }

    if (url.pathname === "/api/health") {
      log("Worker", "Health check ✅");
      return jsonResponse({ ok: true, service: "auth-role-worker-poc" }, 200, origin);
    }

    // ── Step 1: Start login ──
    if (url.pathname === "/auth/login") {
      log("Worker", "Starting OAuth login flow...");
      try {
        handoffService.assertConfigured();
      } catch (error) {
        log("Worker", "❌ Missing Worker 2 handoff configuration", { error: error.message });
        return htmlResponse(loginPage("Sign-in is temporarily unavailable. Please contact support."), 500);
      }

      const loginStartedAt = Math.floor(Date.now() / 1000);
      const loginAttemptSessionId = crypto.randomUUID();
      const codeVerifier = randomBase64Url(64);
      const codeChallenge = await sha256Base64Url(codeVerifier);
      const statePayload = {
        loginAttemptSessionId,
        codeVerifier,
        exp: Math.floor(Date.now() / 1000) + 600,
      };
      const signedState = await createSignedToken(statePayload, env.SESSION_SECRET || env.MICROSOFT_CLIENT_SECRET);
      const authorizeUrl = new URL(microsoftAuthorizeUrl(request, env, signedState));
      authorizeUrl.searchParams.set("code_challenge", codeChallenge);
      authorizeUrl.searchParams.set("code_challenge_method", "S256");
      await auditService.recordLoginStarted({
        request,
        authSource: AUTH_SOURCE,
        authLevel: "login_started",
        stateVersion: AUTH_STATE_VERSION,
        sessionId: loginAttemptSessionId,
        createdAt: loginStartedAt,
      });
      log("Worker", "Redirecting to Microsoft authorize URL");
      return redirectResponse(authorizeUrl.toString());
    }

    // ── Step 2: Microsoft callback ──
    if (url.pathname === "/auth/callback") {
      log("Worker", "Received callback from Microsoft");
      log("Worker", "Callback query params", sanitizeAuthQueryParams(url.searchParams));

      const msError = url.searchParams.get("error");
      const msErrorDesc = url.searchParams.get("error_description");
      if (msError) {
        log("Worker", "❌ Microsoft returned an error", { msError, msErrorDesc });
        await auditService.recordFailure({
          request,
          authSource: AUTH_SOURCE,
          authLevel: "callback_failed",
          stateVersion: AUTH_STATE_VERSION,
          errorCode: msError,
          errorMessage: msErrorDesc || msError,
        });
        return htmlResponse(loginPage("Microsoft sign-in was cancelled or failed. Please try again."), 401);
      }

      log("Worker", "Verifying state token from callback...");
      const incomingSignedState = url.searchParams.get("state");
      log("Worker", `State param present: ${!!incomingSignedState}`);

      let savedState;
      try {
        savedState = await verifySignedToken(incomingSignedState, env.SESSION_SECRET || env.MICROSOFT_CLIENT_SECRET);
      } catch (error) {
        await auditService.recordFailure({
          request,
          authSource: AUTH_SOURCE,
          authLevel: "callback_failed",
          stateVersion: AUTH_STATE_VERSION,
          errorCode: "oauth_state_verification_error",
          errorMessage: error.message,
        });
        return htmlResponse(loginPage("We could not verify your sign-in request. Please try again."), 400);
      }

      if (!savedState) {
        log("Worker", "❌ State verification failed — possible CSRF or login timeout");
        await auditService.recordFailure({
          request,
          authSource: AUTH_SOURCE,
          authLevel: "callback_failed",
          stateVersion: AUTH_STATE_VERSION,
          errorCode: "oauth_state_invalid",
          errorMessage: "OAuth state verification failed",
        });
        return htmlResponse(loginPage("Session state mismatch. This can happen if cookies are blocked or the login took too long. Please try again."), 400);
      }
      log("Worker", "✅ State verified");

      const code = url.searchParams.get("code");
      if (!code) {
        log("Worker", "❌ No code in callback");
        await auditService.recordFailure({
          request,
          authSource: AUTH_SOURCE,
          authLevel: "callback_failed",
          stateVersion: AUTH_STATE_VERSION,
          errorCode: "missing_authorization_code",
          errorMessage: "Microsoft callback did not include an authorization code",
          sessionId: savedState.loginAttemptSessionId || null,
        });
        return htmlResponse(loginPage("Microsoft did not return an authorization code."), 400);
      }
      log("Worker", "✅ Auth code received");

      try {
        let tokens;
        try {
          tokens = await exchangeCodeForTokens({ code, request, env, codeVerifier: savedState.codeVerifier });
        } catch (error) {
          await auditService.recordFailure({
            request,
            authSource: AUTH_SOURCE,
            authLevel: "token_exchange_failed",
            stateVersion: AUTH_STATE_VERSION,
            errorCode: "token_exchange_failed",
            errorMessage: error.message,
            sessionId: savedState.loginAttemptSessionId || null,
          });
          return htmlResponse(loginPage("Sign-in could not be completed. Please try again."), 401);
        }

        log("Worker", "✅ Tokens received — verifying ID token...");
        log("Worker", "Token lifetimes from MS", {
          expires_in:     tokens.expires_in,
          ext_expires_in: tokens.ext_expires_in,
        });

        let claims;
        try {
          claims = await verifyIdToken(tokens.id_token, env.MICROSOFT_TENANT_ID, env.MICROSOFT_CLIENT_ID);
        } catch (error) {
          await auditService.recordFailure({
            request,
            authSource: AUTH_SOURCE,
            authLevel: "id_token_invalid",
            stateVersion: AUTH_STATE_VERSION,
            errorCode: "id_token_invalid",
            errorMessage: error.message,
            sessionId: savedState.loginAttemptSessionId || null,
          });
          return htmlResponse(loginPage("We could not verify your Microsoft sign-in. Please try again."), 401);
        }

        log("Worker", "✅ ID token verified for user", claims.preferred_username);

        if (!isAllowedCompanyUser(claims, env)) {
          log("Worker", "❌ User not from allowed company/domain");
          await auditService.recordFailure({
            request,
            authSource: AUTH_SOURCE,
            authLevel: "tenant_not_allowed",
            stateVersion: AUTH_STATE_VERSION,
            errorCode: "tenant_not_allowed",
            errorMessage: "User is not part of the allowed tenant or email domain",
            sessionId: savedState.loginAttemptSessionId || null,
            email: claims.preferred_username || claims.email || null,
            userOid: claims.oid || null,
          });
          return htmlResponse(loginPage("Access is restricted to approved company Microsoft accounts only."), 403);
        }

        log("Worker", "Fetching Graph API details...");
        let graphDetails;
        try {
          graphDetails = await getUserGraphDetails(tokens.access_token, claims.oid);
        } catch (error) {
          await auditService.recordFailure({
            request,
            authSource: AUTH_SOURCE,
            authLevel: "graph_lookup_failed",
            stateVersion: AUTH_STATE_VERSION,
            errorCode: "graph_lookup_failed",
            errorMessage: error.message,
            sessionId: savedState.loginAttemptSessionId || null,
            email: claims.preferred_username || claims.email || null,
            userOid: claims.oid || null,
            role: getRoleFromClaims(claims),
          });
          return htmlResponse(loginPage("Sign-in could not be completed. Please try again later."), 401);
        }

        const { licenseType, roleId, firstName, lastName } = graphDetails;

        const session = buildSessionPayload(
          claims,
          licenseType,
          roleId,
          firstName,
          lastName,
          tokens,
          savedState.loginAttemptSessionId || crypto.randomUUID(),
        );

        try {
          await sessionRepository.create(buildPersistedSession(session));
        } catch (error) {
          log("AuthSessionRepository", "Failed to persist auth session row", { error: error.message });
        }

        await auditService.recordSuccess({
          request,
          session,
          authSource: AUTH_SOURCE,
          authLevel: "authenticated",
          stateVersion: AUTH_STATE_VERSION,
        });

        const worker2Redirect = await handoffService.createRedirect(session);
        log("Worker", "✅ Session created — redirecting to Worker 2");
        return redirectResponse(worker2Redirect);

      } catch (authError) {
        log("Worker", "❌ Auth error in callback", authError.message);
        await auditService.recordFailure({
          request,
          authSource: AUTH_SOURCE,
          authLevel: "callback_failed",
          stateVersion: AUTH_STATE_VERSION,
          errorCode: "callback_exception",
          errorMessage: authError.message,
        });
        return htmlResponse(loginPage("Sign-in failed. Please try again later."), 401);
      }
    }

    // ── Logout ──
    if (url.pathname === "/auth/logout") {
      log("Worker", "Logging out — clearing cookies");
      return redirectResponse("/", [buildExpiredCookie(SESSION_COOKIE, request), buildExpiredCookie(STATE_COOKIE, request)]);
    }

    // ── API: get current session ──
    if (url.pathname === "/api/auth/me") {
      log("Worker", "/api/auth/me called");
      const session = await getSession(request, env);
      if (!session) return jsonResponse({ authenticated: false, error: "No active session" }, 401, origin);
      log("Worker", "✅ Returning session for", session.email);
      return jsonResponse({
        authenticated: true,
        userType: session.role,
        user: {
          name:        session.name,
          firstName:   session.firstName,
          lastName:    session.lastName,
          email:       session.email,
          oid:         session.oid,
          licenseType: session.licenseType,
        },
        agentState: {
          role:        session.role,
          roleId:      session.roleId,
          source:      "cloudflare-worker-poc",
          permissions: session.permissions,
        },
        // ✅ Token expiry info exposed in API response
        tokenExpiry: {
          sessionStarted:  session.createdAt       ? new Date(session.createdAt       * 1000).toISOString() : null,
          accessTokenExp:  session.accessTokenExp  ? new Date(session.accessTokenExp  * 1000).toISOString() : null,
          refreshTokenExp: session.refreshTokenExp ? new Date(session.refreshTokenExp * 1000).toISOString() : null,
          idTokenExp:      session.idTokenExp      ? new Date(session.idTokenExp      * 1000).toISOString() : null,
          sessionTokenExp: session.sessionTokenExp ? new Date(session.sessionTokenExp * 1000).toISOString() : null,
        },
      }, 200, origin);
    }

    // ── Dashboard page ──
    if (url.pathname === "/dashboad") {
      return redirectResponse("/dashboard");
    }

    if (url.pathname === "/dashboard") {
      log("Worker", "Dashboard requested");
      const session = await getSession(request, env);
      if (!session) { log("Worker", "No session — redirecting to login"); return redirectResponse("/"); }
      log("Worker", "✅ Serving dashboard for", session.email);
      return htmlResponse(dashboardPage(session));
    }

    // ── Root / index ──
    if (url.pathname === "/" || url.pathname === "/index.html") {
      log("Worker", "Root page requested");
      const session = await getSession(request, env);
      if (session) { log("Worker", "Session exists — redirecting to dashboard"); return redirectResponse("/dashboard"); }
      log("Worker", "No session — showing login page");
      return htmlResponse(loginPage());
    }

    log("Worker", `❌ No route matched: ${request.method} ${url.pathname}`);
    return jsonResponse({ error: "Not found" }, 404, origin);
  },
};
