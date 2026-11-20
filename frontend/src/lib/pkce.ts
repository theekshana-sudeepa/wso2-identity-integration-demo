export type IdpPreset = "wso2is" | "asgardeo";

export interface IdpPresetMeta {
  readonly id: IdpPreset;
  readonly label: string;
  readonly shortLabel: string;
  readonly deploymentTag: string;
  readonly defaultBaseUrl: string;
  readonly defaultAudience: string;
  readonly demoKid: string;
}

export const IDP_PRESETS: Record<IdpPreset, IdpPresetMeta> = {
  wso2is: {
    id: "wso2is",
    label: "WSO2 Identity Server 7.0",
    shortLabel: "WSO2 IS 7.0",
    deploymentTag: "Local Docker · Self-Hosted CIAM",
    defaultBaseUrl: "https://localhost:9443",
    defaultAudience: "wso2-api-demo",
    demoKid: "wso2is7-rs256-2026-key1"
  },
  asgardeo: {
    id: "asgardeo",
    label: "Asgardeo Cloud",
    shortLabel: "Asgardeo",
    deploymentTag: "Choreo Labs SaaS · Multi-Tenant CIAM",
    defaultBaseUrl: "https://api.asgardeo.io/t/choreo-demo",
    defaultAudience: "choreo-integration-api",
    demoKid: "asgardeo-edge-rs256-2026"
  }
};

export interface OidcConfig {
  readonly preset: IdpPreset;
  readonly baseUrl: string;
  readonly issuer: string;
  readonly jwksUri: string;
  readonly audience: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scope: string;
  readonly backendApiUrl: string;
}

export interface TokenSession {
  readonly accessToken: string;
  readonly idToken?: string;
  readonly tokenType: string;
  readonly expiresIn: number;
  readonly issuedAt: number;
  readonly mode: "live" | "demo";
  readonly demoRole?: "user" | "admin";
  readonly preset: IdpPreset;
}

export interface DecodedJwt {
  readonly header: Record<string, unknown>;
  readonly payload: Record<string, unknown>;
  readonly rawParts: readonly [string, string, string];
}

export interface ParsedJwtClaims {
  readonly alg: string;
  readonly typ: string;
  readonly kid: string;
  readonly sub: string;
  readonly username: string;
  readonly email: string;
  readonly issuer: string;
  readonly audience: string;
  readonly groups: readonly string[];
  readonly scopes: readonly string[];
  readonly issuedAtSec: number | null;
  readonly expiresAtSec: number | null;
  readonly isAdmin: boolean;
  readonly hasWriteReports: boolean;
}

export interface PkceTelemetry {
  readonly codeVerifier: string;
  readonly codeChallenge: string;
  readonly state: string;
  readonly challengeMethod: "S256";
  readonly entropyBits: number;
  readonly generatedAt: string;
}

const VERIFIER_STORAGE_KEY = "wso2_pkce_code_verifier";
const STATE_STORAGE_KEY = "wso2_oidc_state";
const SESSION_STORAGE_KEY = "wso2_oidc_session";

export function getInitialPreset(): IdpPreset {
  return import.meta.env.VITE_IDP_PRESET === "asgardeo" ? "asgardeo" : "wso2is";
}

export function getOidcConfig(preset: IdpPreset = getInitialPreset()): OidcConfig {
  const presetMeta = IDP_PRESETS[preset];
  const envBaseUrl = import.meta.env.VITE_WSO2_BASE_URL?.trim();
  const useEnvBase = Boolean(envBaseUrl) && preset === getInitialPreset();
  const baseUrl = (useEnvBase && envBaseUrl ? envBaseUrl : presetMeta.defaultBaseUrl).replace(
    /\/+$/,
    ""
  );

  return {
    preset,
    baseUrl,
    issuer: `${baseUrl}/oauth2/token`,
    jwksUri: `${baseUrl}/oauth2/jwks`,
    audience: presetMeta.defaultAudience,
    clientId: import.meta.env.VITE_CLIENT_ID || "",
    redirectUri: import.meta.env.VITE_REDIRECT_URI || `${window.location.origin}/callback`,
    scope: import.meta.env.VITE_SCOPE || "openid profile email groups",
    backendApiUrl: (import.meta.env.VITE_BACKEND_API_URL || "http://localhost:5050").replace(
      /\/+$/,
      ""
    )
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

export async function generateLivePkceTelemetry(): Promise<PkceTelemetry> {
  const codeVerifier = generateRandomString(48);
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateRandomString(24);
  return {
    codeVerifier,
    codeChallenge,
    state,
    challengeMethod: "S256",
    entropyBits: 384,
    generatedAt: new Date().toISOString()
  };
}

export async function initiateWso2Login(config: OidcConfig): Promise<void> {
  if (!config.clientId) {
    throw new Error(
      `VITE_CLIENT_ID is not configured for ${IDP_PRESETS[config.preset].label}. Add it to frontend/.env or explore instantly using Demo Tokens.`
    );
  }

  const telemetry = await generateLivePkceTelemetry();
  sessionStorage.setItem(VERIFIER_STORAGE_KEY, telemetry.codeVerifier);
  sessionStorage.setItem(STATE_STORAGE_KEY, telemetry.state);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope,
    state: telemetry.state,
    code_challenge: telemetry.codeChallenge,
    code_challenge_method: telemetry.challengeMethod
  });

  window.location.assign(`${config.baseUrl}/oauth2/authorize?${params.toString()}`);
}

export async function handleOidcCallback(config: OidcConfig): Promise<TokenSession | null> {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    throw new Error(`OIDC Authorization Error: ${error}`);
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
    throw new Error("PKCE code_verifier missing from sessionStorage.");
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
    mode: "live",
    preset: config.preset
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
      payload: decodeSegment(parts[1]),
      rawParts: [parts[0], parts[1], parts[2] ?? ""]
    };
  } catch {
    return null;
  }
}

function asString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim().length > 0 ? value : fallback;
}

function asStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }
  if (typeof value === "string" && value.trim().length > 0) {
    return value
      .split(/[,\s]+/)
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [];
}

export function parseJwtClaims(decoded: DecodedJwt): ParsedJwtClaims {
  const { header, payload } = decoded;
  const groups =
    payload.groups !== undefined ? asStringArray(payload.groups) : asStringArray(payload.roles);
  const scopes =
    typeof payload.scope === "string"
      ? payload.scope.split(" ").map((s) => s.trim()).filter(Boolean)
      : [];

  const sub = asString(payload.sub, "unknown");
  const username = asString(payload.username ?? payload.preferred_username, sub);
  const email = asString(payload.email, "—");

  return {
    alg: asString(header.alg, "RS256"),
    typ: asString(header.typ, "JWT"),
    kid: asString(header.kid, "unresolved"),
    sub,
    username,
    email,
    issuer: asString(payload.iss, "—"),
    audience: Array.isArray(payload.aud)
      ? payload.aud.map(String).join(", ")
      : asString(payload.aud, "—"),
    groups,
    scopes,
    issuedAtSec: typeof payload.iat === "number" ? payload.iat : null,
    expiresAtSec: typeof payload.exp === "number" ? payload.exp : null,
    isAdmin: groups.some((g) => g.toLowerCase() === "admin" || g.toLowerCase() === "administrator"),
    hasWriteReports: scopes.includes("write:reports")
  };
}

export function createDemoSession(role: "user" | "admin", config: OidcConfig): TokenSession {
  const nowSec = Math.floor(Date.now() / 1000);
  const presetMeta = IDP_PRESETS[config.preset];
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: presetMeta.demoKid
  };
  const payload = {
    sub: role === "admin" ? "usr_9f82a10c_admin" : "usr_4b21d90e_dev",
    username: role === "admin" ? "admin@acme-identity.example" : "developer@acme-identity.example",
    email: role === "admin" ? "admin@acme-identity.example" : "developer@acme-identity.example",
    iss: config.issuer,
    aud: config.audience,
    azp: config.clientId || "choreo-spa-public-client",
    groups: role === "admin" ? ["admin", "integration-lead", "developer"] : ["developer"],
    scope:
      role === "admin"
        ? "openid profile email groups read:profile write:reports admin:audit"
        : "openid profile email groups read:profile",
    iat: nowSec,
    exp: nowSec + 3600
  };

  const token = `${base64UrlEncodeJson(header)}.${base64UrlEncodeJson(payload)}.demo_rs256_signature_requires_idp_jwks`;

  const session: TokenSession = {
    accessToken: token,
    tokenType: "Bearer",
    expiresIn: 3600,
    issuedAt: Date.now(),
    mode: "demo",
    demoRole: role,
    preset: config.preset
  };
  saveSession(session);
  return session;
}

export function loadSession(): TokenSession | null {
  try {
    const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<TokenSession>;
    if (typeof parsed.accessToken !== "string") return null;
    return {
      accessToken: parsed.accessToken,
      idToken: typeof parsed.idToken === "string" ? parsed.idToken : undefined,
      tokenType: typeof parsed.tokenType === "string" ? parsed.tokenType : "Bearer",
      expiresIn: typeof parsed.expiresIn === "number" ? parsed.expiresIn : 3600,
      issuedAt: typeof parsed.issuedAt === "number" ? parsed.issuedAt : Date.now(),
      mode: parsed.mode === "live" ? "live" : "demo",
      demoRole: parsed.demoRole === "admin" || parsed.demoRole === "user" ? parsed.demoRole : undefined,
      preset: parsed.preset === "asgardeo" ? "asgardeo" : "wso2is"
    };
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
