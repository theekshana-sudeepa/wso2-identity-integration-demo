import type { OidcConfig, ParsedJwtClaims, TokenSession } from "./pkce";

export type HttpMethod = "GET" | "POST";
export type ExecutionMode = "live" | "dry-run";
export type PolicyKind = "public" | "jwt" | "role" | "scope";

export interface ApiEndpointSpec {
  readonly id: string;
  readonly method: HttpMethod;
  readonly path: string;
  readonly label: string;
  readonly policyLabel: string;
  readonly policyKind: PolicyKind;
  readonly requiredRole?: string;
  readonly requiredScope?: string;
  readonly description: string;
  readonly defaultBody?: Record<string, unknown>;
}

export const API_ENDPOINTS: readonly ApiEndpointSpec[] = [
  {
    id: "public-info",
    method: "GET",
    path: "/api/v1/public/info",
    label: "Public Info",
    policyLabel: "PUBLIC",
    policyKind: "public",
    description: "Unauthenticated service & OIDC/JWKS metadata"
  },
  {
    id: "user-profile",
    method: "GET",
    path: "/api/v1/user/profile",
    label: "User Profile",
    policyLabel: "JWT RS256",
    policyKind: "jwt",
    description: "Verifies RS256 signature, iss, aud, exp & returns profile"
  },
  {
    id: "user-roles",
    method: "GET",
    path: "/api/v1/user/roles",
    label: "Roles & Scopes",
    policyLabel: "JWT RS256",
    policyKind: "jwt",
    description: "Inspects resolved groups, OAuth 2.0 scopes & admin flag"
  },
  {
    id: "admin-audit",
    method: "GET",
    path: "/api/v1/admin/audit-logs",
    label: "Admin Audit Logs",
    policyLabel: "ROLE: admin",
    policyKind: "role",
    requiredRole: "admin",
    description: "Enforces requireRoles('admin') RBAC middleware guard"
  },
  {
    id: "create-report",
    method: "POST",
    path: "/api/v1/reports",
    label: "Create Report",
    policyLabel: "SCOPE: write:reports",
    policyKind: "scope",
    requiredScope: "write:reports",
    description: "Enforces requireScopes('write:reports') OAuth2 scope guard",
    defaultBody: {
      title: "Quarterly Zero-Trust CIAM Compliance Audit"
    }
  }
];

export interface ApiCallResult {
  readonly endpoint: string;
  readonly method: HttpMethod;
  readonly status: number;
  readonly latencyMs: number;
  readonly data: unknown;
  readonly ok: boolean;
  readonly mode: ExecutionMode;
  readonly timestamp: string;
}

export interface BackendHealthStatus {
  readonly reachable: boolean;
  readonly statusText: string;
  readonly issuer?: string;
  readonly uptimeSeconds?: number;
}

export async function checkBackendHealth(baseUrl: string): Promise<BackendHealthStatus> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 2500);
  try {
    const response = await fetch(`${baseUrl}/health`, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: controller.signal
    });
    if (!response.ok) {
      return { reachable: false, statusText: `HTTP ${response.status}` };
    }
    const body = (await response.json()) as {
      status?: string;
      issuer?: string;
      uptimeSeconds?: number;
    };
    return {
      reachable: body.status === "ok",
      statusText: "Express API Online",
      issuer: body.issuer,
      uptimeSeconds: body.uptimeSeconds
    };
  } catch {
    return { reachable: false, statusText: "Backend Offline" };
  } finally {
    window.clearTimeout(timer);
  }
}

export async function invokeProtectedApi(
  baseUrl: string,
  endpoint: string,
  method: HttpMethod,
  accessToken?: string,
  body?: Record<string, unknown>
): Promise<ApiCallResult> {
  const startedAt = performance.now();
  const headers: Record<string, string> = {
    Accept: "application/json"
  };

  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }
  if (body) {
    headers["Content-Type"] = "application/json";
  }

  try {
    const response = await fetch(`${baseUrl}${endpoint}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });

    const latencyMs = Math.max(1, Math.round(performance.now() - startedAt));
    let data: unknown;
    try {
      data = await response.json();
    } catch {
      data = { raw: await response.text() };
    }

    return {
      endpoint,
      method,
      status: response.status,
      latencyMs,
      data,
      ok: response.ok,
      mode: "live",
      timestamp: new Date().toISOString()
    };
  } catch (err: unknown) {
    return {
      endpoint,
      method,
      status: 0,
      latencyMs: Math.max(1, Math.round(performance.now() - startedAt)),
      data: {
        error: "network_unreachable",
        message:
          err instanceof Error
            ? err.message
            : "Backend resource server could not be reached. Start backend with `npm run dev:backend` or switch to Policy Dry-Run."
      },
      ok: false,
      mode: "live",
      timestamp: new Date().toISOString()
    };
  }
}

export function evaluateEndpointAccess(
  spec: ApiEndpointSpec,
  claims: ParsedJwtClaims | null
): "allowed" | "unauthenticated" | "forbidden" {
  if (spec.policyKind === "public") return "allowed";
  if (!claims) return "unauthenticated";
  if (spec.policyKind === "role" && spec.requiredRole) {
    const allowed = claims.groups.some(
      (g) => g.toLowerCase() === spec.requiredRole?.toLowerCase() || g.toLowerCase() === "administrator"
    );
    return allowed ? "allowed" : "forbidden";
  }
  if (spec.policyKind === "scope" && spec.requiredScope) {
    return claims.scopes.includes(spec.requiredScope) ? "allowed" : "forbidden";
  }
  return "allowed";
}

export function simulateRbacPolicyCall(
  spec: ApiEndpointSpec,
  config: OidcConfig,
  session: TokenSession | null,
  claims: ParsedJwtClaims | null
): ApiCallResult {
  const nowIso = new Date().toISOString();

  if (spec.policyKind === "public") {
    return {
      endpoint: spec.path,
      method: spec.method,
      status: 200,
      latencyMs: 2,
      ok: true,
      mode: "dry-run",
      timestamp: nowIso,
      data: {
        service: "wso2-identity-integration-api",
        providerFamily: "Choreo Labs (formerly WSO2) — WSO2 Identity Server 7.0 & Asgardeo",
        status: "operational",
        authProtocol: "OAuth 2.0 / OpenID Connect (OIDC) with S256 PKCE",
        tokenSigning: "Stateless RS256 via JWKS Cache",
        identityProvider: config.baseUrl,
        jwksUri: config.jwksUri,
        policyEvaluation: "DRY_RUN_SIMULATION"
      }
    };
  }

  if (!session || !claims) {
    return {
      endpoint: spec.path,
      method: spec.method,
      status: 401,
      latencyMs: 1,
      ok: false,
      mode: "dry-run",
      timestamp: nowIso,
      data: {
        error: "unauthorized",
        message: "Missing or malformed Authorization header. Expected Bearer RS256 JWT.",
        policyEvaluation: "DRY_RUN_SIMULATION"
      }
    };
  }

  if (spec.policyKind === "role" && !claims.isAdmin) {
    return {
      endpoint: spec.path,
      method: spec.method,
      status: 403,
      latencyMs: 2,
      ok: false,
      mode: "dry-run",
      timestamp: nowIso,
      data: {
        error: "forbidden",
        message: `Access denied. Required role(s): ${spec.requiredRole ?? "admin"}.`,
        assignedRoles: claims.groups,
        policyEvaluation: "DRY_RUN_SIMULATION"
      }
    };
  }

  if (spec.policyKind === "scope" && spec.requiredScope && !claims.scopes.includes(spec.requiredScope)) {
    return {
      endpoint: spec.path,
      method: spec.method,
      status: 403,
      latencyMs: 2,
      ok: false,
      mode: "dry-run",
      timestamp: nowIso,
      data: {
        error: "insufficient_scope",
        message: `Missing required OAuth2 scope(s): ${spec.requiredScope}.`,
        grantedScopes: claims.scopes,
        policyEvaluation: "DRY_RUN_SIMULATION"
      }
    };
  }

  if (spec.id === "user-profile") {
    return {
      endpoint: spec.path,
      method: spec.method,
      status: 200,
      latencyMs: 3,
      ok: true,
      mode: "dry-run",
      timestamp: nowIso,
      data: {
        message: "Verified identity profile retrieved from RS256 access token.",
        profile: {
          subject: claims.sub,
          username: claims.username,
          email: claims.email,
          groups: claims.groups,
          scopes: claims.scopes
        },
        jwksKeyId: claims.kid,
        policyEvaluation: "DRY_RUN_SIMULATION"
      }
    };
  }

  if (spec.id === "user-roles") {
    return {
      endpoint: spec.path,
      method: spec.method,
      status: 200,
      latencyMs: 2,
      ok: true,
      mode: "dry-run",
      timestamp: nowIso,
      data: {
        subject: claims.sub,
        roles: claims.groups,
        scopes: claims.scopes,
        isAdmin: claims.isAdmin,
        policyEvaluation: "DRY_RUN_SIMULATION"
      }
    };
  }

  if (spec.id === "admin-audit") {
    return {
      endpoint: spec.path,
      method: spec.method,
      status: 200,
      latencyMs: 4,
      ok: true,
      mode: "dry-run",
      timestamp: nowIso,
      data: {
        accessedBy: claims.username,
        policy: "RBAC (Role: admin)",
        entries: [
          {
            id: "evt_01",
            action: "OIDC_PKCE_S256_TOKEN_ISSUED",
            actor: claims.username,
            status: "SUCCESS",
            timestamp: new Date(Date.now() - 120_000).toISOString()
          },
          {
            id: "evt_02",
            action: "JWKS_KEY_ROTATION_SYNC",
            actor: "system-jwks-cache",
            status: "VERIFIED",
            timestamp: new Date(Date.now() - 45_000).toISOString()
          },
          {
            id: "evt_03",
            action: "ADMIN_AUDIT_ACCESS",
            actor: claims.username,
            status: "AUTHORIZED",
            timestamp: nowIso
          }
        ],
        policyEvaluation: "DRY_RUN_SIMULATION"
      }
    };
  }

  return {
    endpoint: spec.path,
    method: spec.method,
    status: 201,
    latencyMs: 4,
    ok: true,
    mode: "dry-run",
    timestamp: nowIso,
    data: {
      id: `rep_${Date.now()}`,
      title:
        typeof spec.defaultBody?.title === "string"
          ? spec.defaultBody.title
          : "Security Compliance Summary",
      createdBy: claims.username,
      status: "CREATED",
      grantedScope: "write:reports",
      timestamp: nowIso,
      policyEvaluation: "DRY_RUN_SIMULATION"
    }
  };
}
