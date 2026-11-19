export interface OidcConfig {
  baseUrl: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  backendApiUrl: string;
}

export interface TokenSession {
  accessToken: string;
  idToken?: string;
  tokenType: string;
  expiresIn: number;
  issuedAt: number;
  mode: "live" | "demo";
}

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

const VERIFIER_STORAGE_KEY = "wso2_pkce_code_verifier";
const STATE_STORAGE_KEY = "wso2_oidc_state";
const SESSION_STORAGE_KEY = "wso2_oidc_session";

export function getOidcConfig(): OidcConfig {
  return {
    baseUrl: (import.meta.env.VITE_WSO2_BASE_URL || "https://localhost:9443").replace(/\/+$/, ""),
    clientId: import.meta.env.VITE_CLIENT_ID || "",
    redirectUri: import.meta.env.VITE_REDIRECT_URI || `${window.location.origin}/callback`,
    scope: import.meta.env.VITE_SCOPE || "openid profile email groups",
    backendApiUrl: (import.meta.env.VITE_BACKEND_API_URL || "http://localhost:5050").replace(/\/+$/, "")
  };
}

function base64UrlEncode(buffer: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < buffer.byteLength; i += 1) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeJson(data: Record<string, unknown>): string {
  const bytes = new TextEncoder().encode(JSON.stringify(data));
  return base64UrlEncode(bytes);
}

export function generateRandomString(byteLength = 32): string {
  const randomBytes = new Uint8Array(byteLength);
  crypto.getRandomValues(randomBytes);
  return base64UrlEncode(randomBytes);
}

export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const data = new TextEncoder().encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(digest));
}

export async function initiateWso2Login(config: OidcConfig): Promise<void> {
  if (!config.clientId) {
    throw new Error("VITE_CLIENT_ID is not configured. Add it to frontend/.env or use Demo Mode.");
  }

  const codeVerifier = generateRandomString(48);
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateRandomString(24);

  sessionStorage.setItem(VERIFIER_STORAGE_KEY, codeVerifier);
  sessionStorage.setItem(STATE_STORAGE_KEY, state);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256"
  });

  window.location.assign(`${config.baseUrl}/oauth2/authorize?${params.toString()}`);
}

export async function handleOidcCallback(config: OidcConfig): Promise<TokenSession | null> {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    throw new Error(`WSO2 Authorization Error: ${error}`);
  }

  if (!code) {
    return null;
  }

  const expectedState = sessionStorage.getItem(STATE_STORAGE_KEY);
  const codeVerifier = sessionStorage.getItem(VERIFIER_STORAGE_KEY);

  if (!expectedState || returnedState !== expectedState) {
    throw new Error("OIDC state mismatch detected. Potential CSRF attempt blocked.");
  }

  if (!codeVerifier) {
    throw new Error("PKCE code_verifier missing from session storage.");
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    code_verifier: codeVerifier
  });

  const response = await fetch(`${config.baseUrl}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString()
  });

  if (!response.ok) {
    const details = await response.text();
    throw new Error(`Token exchange failed (${response.status}): ${details}`);
  }

  const tokenData = (await response.json()) as {
    access_token: string;
    id_token?: string;
    token_type?: string;
    expires_in?: number;
  };

  sessionStorage.removeItem(VERIFIER_STORAGE_KEY);
  sessionStorage.removeItem(STATE_STORAGE_KEY);
  window.history.replaceState({}, document.title, "/");

  const session: TokenSession = {
    accessToken: tokenData.access_token,
    idToken: tokenData.id_token,
    tokenType: tokenData.token_type || "Bearer",
    expiresIn: tokenData.expires_in || 3600,
    issuedAt: Date.now(),
    mode: "live"
  };

  saveSession(session);
  return session;
}

export function decodeJwt(token: string): DecodedJwt | null {
  try {
    const parts = token.split(".");
    if (parts.length < 2) {
      return null;
    }
    const decodeSegment = (segment: string): Record<string, unknown> => {
      const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
      const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
      return JSON.parse(atob(padded)) as Record<string, unknown>;
    };
    return {
      header: decodeSegment(parts[0]),
      payload: decodeSegment(parts[1])
    };
  } catch {
    return null;
  }
}

export function createDemoSession(role: "user" | "admin", config: OidcConfig): TokenSession {
  const nowSec = Math.floor(Date.now() / 1000);
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: "wso2is-demo-key-2026"
  };
  const payload = {
    sub: role === "admin" ? "usr_9f82a10c_admin" : "usr_4b21d90e_dev",
    username: role === "admin" ? "admin@lexoratech.io" : "developer@lexoratech.io",
    email: role === "admin" ? "admin@lexoratech.io" : "developer@lexoratech.io",
    iss: `${config.baseUrl}/oauth2/token`,
    aud: "wso2-api-demo",
    groups: role === "admin" ? ["admin", "developer"] : ["developer"],
    scope:
      role === "admin"
        ? "openid profile email groups read:profile write:reports admin:all"
        : "openid profile email groups read:profile",
    iat: nowSec,
    exp: nowSec + 3600
  };

  const token = `${base64UrlEncodeJson(header)}.${base64UrlEncodeJson(payload)}.demo_rs256_signature_placeholder`;

  const session: TokenSession = {
    accessToken: token,
    tokenType: "Bearer",
    expiresIn: 3600,
    issuedAt: Date.now(),
    mode: "demo"
  };
  saveSession(session);
  return session;
}

export function loadSession(): TokenSession | null {
  try {
    const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as TokenSession;
  } catch {
    return null;
  }
}

export function saveSession(session: TokenSession): void {
  sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
}

export function clearSession(): void {
  sessionStorage.removeItem(SESSION_STORAGE_KEY);
}
