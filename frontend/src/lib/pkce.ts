import { AGENT_TOKEN_MAX_TTL_SECONDS } from "./agentPolicy";

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

export const IDP_PRESET_KEYS: readonly IdpPreset[] = ["wso2is", "asgardeo"];

export interface OidcConfig {
  readonly preset: IdpPreset;
  readonly baseUrl: string;
  readonly issuer: string;
  readonly jwksUri: string;
  readonly audience: string;
  readonly mcpAudience: string;
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

export interface ActorClaim {
  readonly sub: string;
  readonly client_id: string;
  readonly delegation_protocol: string;
}

export interface DelegatedAgentSession {
  readonly accessToken: string;
  readonly humanSubject: string;
  readonly humanUsername: string;
  readonly actor: ActorClaim;
  readonly audience: string;
  readonly grantedScopes: readonly string[];
  readonly originalScopes: readonly string[];
  readonly strippedScopes: readonly string[];
  readonly ttlSeconds: number;
  readonly issuedAtSec: number;
  readonly expiresAtSec: number;
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
  readonly actor: ActorClaim | null;
  readonly originalScopes: readonly string[];
  readonly strippedScopes: readonly string[];
  readonly delegationDepth: number | null;
  readonly hasHumanApproval: boolean;
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

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

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
  const origin =
    typeof window !== "undefined" && window.location?.origin
      ? window.location.origin
      : "http://localhost:5173";

  const backendApiUrl = (import.meta.env.VITE_BACKEND_API_URL || "http://localhost:5050").replace(
    /\/+$/,
    ""
  );
  const mcpAudience = (import.meta.env.VITE_MCP_AUDIENCE || `${backendApiUrl}/api/mcp`).replace(
    /\/+$/,
    ""
  );

  return {
    preset,
    baseUrl,
    issuer: `${baseUrl}/oauth2/token`,
    jwksUri: `${baseUrl}/oauth2/jwks`,
    audience: presetMeta.defaultAudience,
    mcpAudience,
    clientId: import.meta.env.VITE_CLIENT_ID || "",
    redirectUri: import.meta.env.VITE_REDIRECT_URI || `${origin}/callback`,
    scope: import.meta.env.VITE_SCOPE || "openid profile email groups",
    backendApiUrl
  };
}

function base64UrlEncode(buffer: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < buffer.byteLength; i += 1) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlEncodeJson(data: Record<string, unknown>): string {
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

  const rawJson: unknown = await response.json();
  if (!isRecord(rawJson) || typeof rawJson.access_token !== "string") {
    throw new Error("Token exchange response missing access_token.");
  }

  sessionStorage.removeItem(VERIFIER_STORAGE_KEY);
  sessionStorage.removeItem(STATE_STORAGE_KEY);
  window.history.replaceState({}, document.title, "/");

  const session: TokenSession = {
    accessToken: rawJson.access_token,
    idToken: typeof rawJson.id_token === "string" ? rawJson.id_token : undefined,
    tokenType: typeof rawJson.token_type === "string" ? rawJson.token_type : "Bearer",
    expiresIn: typeof rawJson.expires_in === "number" ? rawJson.expires_in : 3600,
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
    if (parts.length < 2 || parts.length > 3) {
      return null;
    }
    const decodeSegment = (segment: string): Record<string, unknown> | null => {
      if (!segment) return null;
      const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
      const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
      const binary = atob(padded);
      const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
      const text = new TextDecoder().decode(bytes);
      const parsed: unknown = JSON.parse(text);
      return isRecord(parsed) ? parsed : null;
    };
    const header = decodeSegment(parts[0]);
    const payload = decodeSegment(parts[1]);
    if (!header || !payload) {
      return null;
    }
    return {
      header,
      payload,
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

function parseActorClaim(rawAct: unknown): ActorClaim | null {
  if (!isRecord(rawAct) || typeof rawAct.sub !== "string" || rawAct.sub.trim().length === 0) {
    return null;
  }
  return {
    sub: rawAct.sub.trim(),
    client_id:
      typeof rawAct.client_id === "string" ? rawAct.client_id : "choreo-mcp-agent-v1",
    delegation_protocol:
      typeof rawAct.delegation_protocol === "string"
        ? rawAct.delegation_protocol
        : "urn:ietf:params:oauth:grant-type:token-exchange"
  };
}

export function parseJwtClaims(decoded: DecodedJwt): ParsedJwtClaims {
  const { header, payload } = decoded;
  const groups =
    payload.groups !== undefined ? asStringArray(payload.groups) : asStringArray(payload.roles);
  const scopes =
    typeof payload.scope === "string"
      ? payload.scope
          .split(" ")
          .map((s) => s.trim())
          .filter(Boolean)
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
    actor: parseActorClaim(payload.act),
    originalScopes: asStringArray(payload.original_scopes),
    strippedScopes: asStringArray(payload.stripped_scopes),
    delegationDepth: typeof payload.delegation_depth === "number" ? payload.delegation_depth : null,
    hasHumanApproval:
      typeof payload.human_approval_token === "string" &&
      payload.human_approval_token.trim().length > 0,
    issuedAtSec: typeof payload.iat === "number" ? payload.iat : null,
    expiresAtSec: typeof payload.exp === "number" ? payload.exp : null,
    isAdmin: groups.some(
      (g) => g.toLowerCase() === "admin" || g.toLowerCase() === "administrator"
    ),
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
        ? "openid profile email groups read:profile orders:read write:reports admin:write admin:audit"
        : "openid profile email groups read:profile orders:read",
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

const PRIVILEGED_SCOPES_STRIPPED_FOR_AGENT: readonly string[] = [
  "admin:write",
  "admin:audit",
  "write:reports",
  "refunds:execute",
  "users:export"
];

export function createDelegatedAgentSession(
  humanClaims: ParsedJwtClaims | null,
  config: OidcConfig,
  nowSecOverride?: number
): DelegatedAgentSession {
  const nowSec = nowSecOverride ?? Math.floor(Date.now() / 1000);
  const ttlSeconds = AGENT_TOKEN_MAX_TTL_SECONDS;
  const presetMeta = IDP_PRESETS[config.preset];

  const humanSubject = humanClaims?.sub ?? "usr_4b21d90e_dev";
  const humanUsername = humanClaims?.username ?? "developer@acme-identity.example";
  const originalScopes =
    humanClaims && humanClaims.scopes.length > 0
      ? [...humanClaims.scopes]
      : ["openid", "profile", "email", "orders:read", "admin:write"];

  const grantedScopes: readonly string[] = ["orders:read"];
  const strippedSet = new Set<string>();
  for (const scope of originalScopes) {
    if (!grantedScopes.includes(scope) && scope !== "openid" && scope !== "profile" && scope !== "email" && scope !== "groups") {
      strippedSet.add(scope);
    }
  }
  for (const priv of PRIVILEGED_SCOPES_STRIPPED_FOR_AGENT) {
    if (originalScopes.includes(priv) || priv === "admin:write" || priv === "refunds:execute") {
      strippedSet.add(priv);
    }
  }
  const strippedScopes = Array.from(strippedSet);

  const actor: ActorClaim = {
    sub: "agent:choreo-integrator-bot",
    client_id: "choreo-mcp-agent-v1",
    delegation_protocol: "urn:ietf:params:oauth:grant-type:token-exchange"
  };

  const audience = config.mcpAudience;

  const header: Record<string, unknown> = {
    alg: "RS256",
    typ: "at+jwt",
    kid: presetMeta.demoKid
  };

  const payload: Record<string, unknown> = {
    sub: humanSubject,
    username: humanUsername,
    iss: config.issuer,
    aud: audience,
    azp: actor.client_id,
    act: actor,
    scope: grantedScopes.join(" "),
    groups: ["delegated-agent-readonly"],
    delegation_depth: 1,
    original_scopes: originalScopes,
    stripped_scopes: strippedScopes,
    iat: nowSec,
    exp: nowSec + ttlSeconds
  };

  const accessToken = `${base64UrlEncodeJson(header)}.${base64UrlEncodeJson(payload)}.demo_obo_rfc8693_rs256_signature`;

  return {
    accessToken,
    humanSubject,
    humanUsername,
    actor,
    audience,
    grantedScopes,
    originalScopes,
    strippedScopes,
    ttlSeconds,
    issuedAtSec: nowSec,
    expiresAtSec: nowSec + ttlSeconds,
    preset: config.preset
  };
}

export function loadSession(): TokenSession | null {
  try {
    const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed) || typeof parsed.accessToken !== "string") return null;
    return {
      accessToken: parsed.accessToken,
      idToken: typeof parsed.idToken === "string" ? parsed.idToken : undefined,
      tokenType: typeof parsed.tokenType === "string" ? parsed.tokenType : "Bearer",
      expiresIn: typeof parsed.expiresIn === "number" ? parsed.expiresIn : 3600,
      issuedAt: typeof parsed.issuedAt === "number" ? parsed.issuedAt : Date.now(),
      mode: parsed.mode === "live" ? "live" : "demo",
      demoRole:
        parsed.demoRole === "admin" || parsed.demoRole === "user" ? parsed.demoRole : undefined,
      preset: parsed.preset === "asgardeo" ? "asgardeo" : "wso2is"
    };
  } catch {
    return null;
  }
}

export function saveSession(session: TokenSession): void {
  try {
    sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
  } catch {
    // Ignore restricted storage contexts
  }
}

export function clearSession(): void {
  try {
    sessionStorage.removeItem(SESSION_STORAGE_KEY);
  } catch {
    // Ignore restricted storage contexts
  }
}
