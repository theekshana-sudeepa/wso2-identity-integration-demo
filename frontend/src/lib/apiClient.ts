import { AGENT_TOKEN_MAX_TTL_SECONDS } from "./agentPolicy";
import {
  isRecord,
  type DelegatedAgentSession,
  type OidcConfig,
  type ParsedJwtClaims,
  type TokenSession
} from "./pkce";
import {
  assertNever,
  evaluateFaultScenario,
  type DefenseTrace,
  type FaultState,
  type McpToolSpec
} from "./securityLab";

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
  readonly defenseTrace?: DefenseTrace;
  readonly timestamp: string;
}

export interface BackendHealthStatus {
  readonly reachable: boolean;
  readonly statusText: string;
  readonly simulationOnly?: boolean;
  readonly issuer?: string;
  readonly uptimeSeconds?: number;
}

function isStaticHostedWithoutBackend(baseUrl: string): boolean {
  if (typeof window === "undefined") return false;
  const host = window.location.hostname;
  const isLocalHost = host === "localhost" || host === "127.0.0.1" || host === "";
  const targetsLocalBackend =
    baseUrl.includes("localhost") || baseUrl.includes("127.0.0.1");
  return !isLocalHost && targetsLocalBackend;
}

export async function checkBackendHealth(baseUrl: string): Promise<BackendHealthStatus> {
  if (isStaticHostedWithoutBackend(baseUrl)) {
    return {
      reachable: false,
      simulationOnly: true,
      statusText: "Browser Simulation Mode"
    };
  }

  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 2000);
  try {
    const response = await fetch(`${baseUrl}/health`, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: controller.signal
    });
    if (!response.ok) {
      return {
        reachable: false,
        simulationOnly: true,
        statusText: "Browser Simulation Mode"
      };
    }
    const raw: unknown = await response.json();
    if (!isRecord(raw)) {
      return {
        reachable: false,
        simulationOnly: true,
        statusText: "Browser Simulation Mode"
      };
    }
    return {
      reachable: raw.status === "ok",
      simulationOnly: raw.status !== "ok",
      statusText: raw.status === "ok" ? "Express API Online" : "Browser Simulation Mode",
      issuer: typeof raw.issuer === "string" ? raw.issuer : undefined,
      uptimeSeconds: typeof raw.uptimeSeconds === "number" ? raw.uptimeSeconds : undefined
    };
  } catch {
    return {
      reachable: false,
      simulationOnly: true,
      statusText: "Browser Simulation Mode"
    };
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
            : "Backend resource server could not be reached. Running in Browser Simulation Mode."
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
      (g) =>
        g.toLowerCase() === spec.requiredRole?.toLowerCase() ||
        g.toLowerCase() === "administrator"
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
  claims: ParsedJwtClaims | null,
  activeFault?: FaultState
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
        authProtocol: "OAuth 2.0 / OpenID Connect (OIDC) with S256 PKCE + RFC 8693 AI Agent OBO",
        tokenSigning: "Stateless RS256 via JWKS Cache",
        identityProvider: config.baseUrl,
        jwksUri: config.jwksUri,
        policyEvaluation: "BROWSER_SIMULATION_MODE"
      }
    };
  }

  if (activeFault && activeFault.id !== "none") {
    const faultEval = evaluateFaultScenario(activeFault, {
      config,
      claims,
      pkceTelemetry: null
    });
    if (faultEval.isBlocked) {
      return {
        endpoint: spec.path,
        method: spec.method,
        status: faultEval.httpStatus,
        latencyMs: 3,
        ok: false,
        mode: "dry-run",
        defenseTrace: faultEval.defenseTrace,
        timestamp: nowIso,
        data: {
          error: faultEval.faultId,
          status: faultEval.httpStatus,
          rfc: faultEval.rfc,
          message: faultEval.summary,
          defenseTrace: faultEval.defenseTrace,
          wireArtifact: faultEval.wirePayload,
          policyEvaluation: "BROWSER_SIMULATION_MODE"
        }
      };
    }
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
        policyEvaluation: "BROWSER_SIMULATION_MODE"
      }
    };
  }

  if (spec.policyKind === "role" && !claims.isAdmin) {
    const defenseTrace: DefenseTrace = {
      layer: "RBAC Role Guard",
      middleware: "backend/src/middleware/rbacMiddleware.ts",
      rfc: "NIST RBAC · Least Privilege",
      check: `requireRoles("${spec.requiredRole ?? "admin"}", "administrator")`,
      outcome: "REJECTED",
      details: `Assigned groups [${claims.groups.join(", ")}] do not include "${spec.requiredRole ?? "admin"}".`
    };
    return {
      endpoint: spec.path,
      method: spec.method,
      status: 403,
      latencyMs: 2,
      ok: false,
      mode: "dry-run",
      defenseTrace,
      timestamp: nowIso,
      data: {
        error: "forbidden",
        message: `Access denied. Required role(s): ${spec.requiredRole ?? "admin"}.`,
        assignedRoles: claims.groups,
        defenseTrace,
        policyEvaluation: "BROWSER_SIMULATION_MODE"
      }
    };
  }

  if (
    spec.policyKind === "scope" &&
    spec.requiredScope &&
    !claims.scopes.includes(spec.requiredScope)
  ) {
    const defenseTrace: DefenseTrace = {
      layer: "OAuth 2.0 Scope Guard",
      middleware: "backend/src/middleware/rbacMiddleware.ts",
      rfc: "RFC 6750 §3.1 (insufficient_scope)",
      check: `requireScopes("${spec.requiredScope}")`,
      outcome: "REJECTED",
      details: `Missing required scope "${spec.requiredScope}".`
    };
    return {
      endpoint: spec.path,
      method: spec.method,
      status: 403,
      latencyMs: 2,
      ok: false,
      mode: "dry-run",
      defenseTrace,
      timestamp: nowIso,
      data: {
        error: "insufficient_scope",
        message: `Missing required OAuth2 scope(s): ${spec.requiredScope}.`,
        grantedScopes: claims.scopes,
        defenseTrace,
        policyEvaluation: "BROWSER_SIMULATION_MODE"
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
        policyEvaluation: "BROWSER_SIMULATION_MODE"
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
        policyEvaluation: "BROWSER_SIMULATION_MODE"
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
        policyEvaluation: "BROWSER_SIMULATION_MODE"
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
      policyEvaluation: "BROWSER_SIMULATION_MODE"
    }
  };
}

export function simulateMcpToolCall(
  toolSpec: McpToolSpec,
  delegatedSession: DelegatedAgentSession,
  config: OidcConfig,
  activeFault?: FaultState,
  nowSecOverride?: number
): ApiCallResult {
  const nowSec = nowSecOverride ?? Math.floor(Date.now() / 1000);
  const nowIso = new Date(nowSec * 1000).toISOString();
  const endpoint = "/api/mcp/tools/call";

  if (activeFault && activeFault.id !== "none") {
    const faultEval = evaluateFaultScenario(activeFault, {
      config,
      claims: null,
      pkceTelemetry: null,
      nowSec
    });
    if (faultEval.isBlocked) {
      return {
        endpoint,
        method: "POST",
        status: faultEval.httpStatus,
        latencyMs: 3,
        ok: false,
        mode: "dry-run",
        defenseTrace: faultEval.defenseTrace,
        timestamp: nowIso,
        data: {
          error: faultEval.faultId,
          tool: toolSpec.name,
          message: faultEval.summary,
          defenseTrace: faultEval.defenseTrace,
          policyEvaluation: "BROWSER_SIMULATION_MODE"
        }
      };
    }
  }

  const ttlRemaining = delegatedSession.expiresAtSec - nowSec;
  if (ttlRemaining <= 0) {
    const defenseTrace: DefenseTrace = {
      layer: "Delegated Agent TTL Guard",
      middleware: "backend/src/middleware/authMiddleware.ts + requireAgentDelegation()",
      rfc: `RFC 8693 · Short-Lived ${AGENT_TOKEN_MAX_TTL_SECONDS}s Agent Token`,
      check: `exp (${delegatedSession.expiresAtSec}) > now (${nowSec})`,
      outcome: "REJECTED",
      details: `Delegated ${AGENT_TOKEN_MAX_TTL_SECONDS}s agent token has expired. Click 'Re-Exchange OBO Token' to mint a fresh short-lived token.`
    };
    return {
      endpoint,
      method: "POST",
      status: 401,
      latencyMs: 2,
      ok: false,
      mode: "dry-run",
      defenseTrace,
      timestamp: nowIso,
      data: {
        error: "delegated_token_expired",
        tool: toolSpec.name,
        message: `Short-lived ${AGENT_TOKEN_MAX_TTL_SECONDS}s RFC 8693 agent token expired. Re-exchange required.`,
        defenseTrace,
        policyEvaluation: "BROWSER_SIMULATION_MODE"
      }
    };
  }

  switch (toolSpec.name) {
    case "get_order_status": {
      const defenseTrace: DefenseTrace = {
        layer: "MCP Tool Scope-Subset Guard",
        middleware: "backend/src/routes/mcpRoutes.ts -> requireAgentDelegation()",
        rfc: "RFC 8693 §4.1 (act + Down-Scoped Access)",
        check: `verify(act.sub === "${delegatedSession.actor.sub}" && scopes.includes("orders:read"))`,
        outcome: "ALLOWED",
        details: `Authorized delegated read on behalf of "${delegatedSession.humanSubject}" with ${ttlRemaining}s TTL remaining.`
      };
      return {
        endpoint,
        method: "POST",
        status: 200,
        latencyMs: 4,
        ok: true,
        mode: "dry-run",
        defenseTrace,
        timestamp: nowIso,
        data: {
          protocol: "MCP tools/call · RFC 8693 OBO",
          tool: toolSpec.name,
          status: "ALLOWED",
          delegatedBy: delegatedSession.humanSubject,
          actor: delegatedSession.actor,
          grantedScopes: delegatedSession.grantedScopes,
          ttlRemainingSec: ttlRemaining,
          result: {
            orderId: "ORD-2026-88412",
            fulfillmentState: "SHIPPED",
            carrier: "Choreo Logistics Express",
            estimatedDelivery: "2026-11-26",
            redactedPii: true
          },
          defenseTrace,
          policyEvaluation: "BROWSER_SIMULATION_MODE"
        }
      };
    }

    case "issue_refund": {
      const defenseTrace: DefenseTrace = {
        layer: "MCP Tool Scope-Subset Guard",
        middleware: "backend/src/middleware/rbacMiddleware.ts -> evaluateMcpToolAuthorization()",
        rfc: "RFC 8693 §2.1 (Privilege Attenuation)",
        check: 'scopes.includes("refunds:execute")',
        outcome: "REJECTED",
        details: `Scope escalation blocked: "refunds:execute" was stripped during OBO exchange. Granted scopes: [${delegatedSession.grantedScopes.join(", ")}].`
      };
      return {
        endpoint,
        method: "POST",
        status: 403,
        latencyMs: 2,
        ok: false,
        mode: "dry-run",
        defenseTrace,
        timestamp: nowIso,
        data: {
          error: "scope_escalation_blocked",
          tool: toolSpec.name,
          message:
            '403 Denied: Scope Escalation Blocked — "refunds:execute" was stripped when down-scoping human JWT into AI Agent OBO token.',
          requiredScope: toolSpec.requiredScope,
          grantedScopes: delegatedSession.grantedScopes,
          strippedScopes: delegatedSession.strippedScopes,
          delegatedBy: delegatedSession.humanSubject,
          actor: delegatedSession.actor,
          defenseTrace,
          policyEvaluation: "BROWSER_SIMULATION_MODE"
        }
      };
    }

    case "export_all_users": {
      const defenseTrace: DefenseTrace = {
        layer: "MCP Human-in-the-Loop Step-Up Guard",
        middleware: "backend/src/middleware/rbacMiddleware.ts -> evaluateMcpToolAuthorization()",
        rfc: "RFC 8693 + Step-Up Human Consent",
        check: 'verify(human_approval_token && scopes.includes("users:export"))',
        outcome: "REJECTED",
        details:
          'Bulk PII exfiltration ("export_all_users") cannot execute autonomously; requires interactive human step-up consent.'
      };
      return {
        endpoint,
        method: "POST",
        status: 403,
        latencyMs: 2,
        ok: false,
        mode: "dry-run",
        defenseTrace,
        timestamp: nowIso,
        data: {
          error: "human_approval_required",
          tool: toolSpec.name,
          message:
            "403 Denied: Human Approval Required — High-risk bulk PII export requires explicit human-in-the-loop step-up consent.",
          requiredScope: toolSpec.requiredScope,
          grantedScopes: delegatedSession.grantedScopes,
          delegatedBy: delegatedSession.humanSubject,
          actor: delegatedSession.actor,
          defenseTrace,
          policyEvaluation: "BROWSER_SIMULATION_MODE"
        }
      };
    }

    default:
      return assertNever(toolSpec.name);
  }
}
