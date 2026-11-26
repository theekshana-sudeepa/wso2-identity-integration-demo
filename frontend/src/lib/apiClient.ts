import { AGENT_TOKEN_MAX_TTL_SECONDS } from "./agentPolicy";
import {
  getBrowserDpopKeyPair,
  isSimulatedTokenRevoked,
  revokeSimulatedToken,
  SIM_ACTIVE_KID,
  signBrowserRs256Jwt,
  verifyBrowserRs256Jwt
} from "./browserCrypto";
import {
  decodeJwt,
  generateLivePkceTelemetry,
  isRecord,
  parseJwtClaims,
  saveSession,
  type ActorClaim,
  type DelegatedAgentSession,
  type DemoPersona,
  type OidcConfig,
  type ParsedJwtClaims,
  type PkceTelemetry,
  type TokenSession
} from "./pkce";
import {
  assertNever,
  evaluateFaultScenario,
  mintSimulatedFaultToken,
  type DefenseTrace,
  type FaultState,
  type McpToolSpec
} from "./securityLab";

export type HttpMethod = "GET" | "POST";
export type ExecutionMode = "live" | "dry-run";
export type VerificationMode = "jwks" | "introspect";
export type PolicyKind = "public" | "jwt" | "role" | "scope";

export interface PendingCibaRequest {
  readonly authReqId: string;
  readonly bindingMessage: string;
  readonly tool: "export_all_users";
  readonly actorSub: string;
  readonly sub: string;
  readonly expiresIn: number;
}

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
  readonly devIdpEnabled?: boolean;
  readonly activeKid?: string;
  readonly rotatedKid?: string;
  readonly issuer?: string;
  readonly mcpAudience?: string;
  readonly uptimeSeconds?: number;
}

export interface McpAuditEntry {
  readonly id: string;
  readonly timestamp: string;
  readonly sub: string;
  readonly actorSub: string;
  readonly tool: string;
  readonly riskTier: "read" | "write" | "high_risk_pii";
  readonly decision: "ALLOWED" | "DENIED";
  readonly status: number;
  readonly reason: string;
  readonly jti: string | null;
}

const simulatedMcpAuditRing: McpAuditEntry[] = [];

function recordSimulatedMcpAudit(entry: Omit<McpAuditEntry, "id">): void {
  simulatedMcpAuditRing.unshift({
    id: `sim_aud_${Date.now()}_${simulatedMcpAuditRing.length + 1}`,
    ...entry
  });
  if (simulatedMcpAuditRing.length > 50) {
    simulatedMcpAuditRing.pop();
  }
}

export function getSimulatedMcpAuditLog(): readonly McpAuditEntry[] {
  return [...simulatedMcpAuditRing];
}

export async function fetchMcpAuditLog(baseUrl: string): Promise<readonly McpAuditEntry[]> {
  try {
    const res = await fetch(`${baseUrl}/api/mcp/audit`, {
      method: "GET",
      headers: { Accept: "application/json" }
    });
    if (!res.ok) {
      return getSimulatedMcpAuditLog();
    }
    const raw: unknown = await res.json();
    if (!isRecord(raw) || !Array.isArray(raw.entries)) {
      return getSimulatedMcpAuditLog();
    }
    const entries: McpAuditEntry[] = [];
    for (const item of raw.entries) {
      if (
        isRecord(item) &&
        typeof item.id === "string" &&
        typeof item.timestamp === "string" &&
        typeof item.sub === "string" &&
        typeof item.actorSub === "string" &&
        typeof item.tool === "string" &&
        typeof item.status === "number" &&
        typeof item.reason === "string"
      ) {
        const riskTier =
          item.riskTier === "write" || item.riskTier === "high_risk_pii"
            ? item.riskTier
            : "read";
        const decision = item.decision === "ALLOWED" ? "ALLOWED" : "DENIED";
        entries.push({
          id: item.id,
          timestamp: item.timestamp,
          sub: item.sub,
          actorSub: item.actorSub,
          tool: item.tool,
          riskTier,
          decision,
          status: item.status,
          reason: item.reason,
          jti: typeof item.jti === "string" ? item.jti : null
        });
      }
    }
    return entries;
  } catch {
    return getSimulatedMcpAuditLog();
  }
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
      statusText:
        raw.status === "ok"
          ? raw.devIdpEnabled === true
            ? "Express API + Dev IdP Online"
            : "Express API Online"
          : "Browser Simulation Mode",
      devIdpEnabled: raw.devIdpEnabled === true,
      activeKid: typeof raw.activeKid === "string" ? raw.activeKid : undefined,
      rotatedKid: typeof raw.rotatedKid === "string" ? raw.rotatedKid : undefined,
      issuer: typeof raw.issuer === "string" ? raw.issuer : undefined,
      mcpAudience: typeof raw.mcpAudience === "string" ? raw.mcpAudience : undefined,
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
  body?: Record<string, unknown>,
  extraHeaders?: Readonly<Record<string, string>>
): Promise<ApiCallResult> {
  const startedAt = performance.now();
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(extraHeaders ?? {})
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

    let defenseTrace: DefenseTrace | undefined;
    if (isRecord(data) && isRecord(data.defenseTrace)) {
      const dt = data.defenseTrace;
      if (
        typeof dt.layer === "string" &&
        typeof dt.middleware === "string" &&
        typeof dt.rfc === "string" &&
        typeof dt.check === "string" &&
        typeof dt.details === "string" &&
        (dt.outcome === "ALLOWED" || dt.outcome === "REJECTED" || dt.outcome === "RECOVERED")
      ) {
        defenseTrace = {
          layer: dt.layer,
          middleware: dt.middleware,
          rfc: dt.rfc,
          check: dt.check,
          outcome: dt.outcome,
          details: dt.details
        };
      }
    }

    return {
      endpoint,
      method,
      status: response.status,
      latencyMs,
      data,
      ok: response.ok,
      mode: "live",
      defenseTrace,
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
      recordSimulatedMcpAudit({
        timestamp: nowIso,
        sub: delegatedSession.humanSubject,
        actorSub: delegatedSession.actor.sub,
        tool: toolSpec.name,
        riskTier: "read",
        decision: "ALLOWED",
        status: 200,
        reason: "authorized_downscoped_obo",
        jti: `sim_jti_${nowSec}`
      });
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
      recordSimulatedMcpAudit({
        timestamp: nowIso,
        sub: delegatedSession.humanSubject,
        actorSub: delegatedSession.actor.sub,
        tool: toolSpec.name,
        riskTier: "write",
        decision: "DENIED",
        status: 403,
        reason: "scope_escalation_blocked",
        jti: `sim_jti_${nowSec}`
      });
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
      if (delegatedSession.hasHumanApproval && delegatedSession.grantedScopes.includes("users:export")) {
        recordSimulatedMcpAudit({
          timestamp: nowIso,
          sub: delegatedSession.humanSubject,
          actorSub: delegatedSession.actor.sub,
          tool: toolSpec.name,
          riskTier: "high_risk_pii",
          decision: "ALLOWED",
          status: 200,
          reason: "ciba_step_up_approved",
          jti: `sim_jti_ciba_${nowSec}`
        });
        const defenseTrace: DefenseTrace = {
          layer: "MCP Human-in-the-Loop Step-Up Guard",
          middleware: "backend/src/mcp/toolRegistry.ts -> cibaApprovalStore.verifyAndConsumeApprovalToken()",
          rfc: "RFC 8693 + CIBA Step-Up Human Consent",
          check: 'verify(human_approval_token && scopes.includes("users:export"))',
          outcome: "ALLOWED",
          details: `Verified one-time CIBA human approval token for "${delegatedSession.humanSubject}" with step-up scope "users:export".`
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
            jsonrpc: "2.0",
            id: 1,
            protocol: "MCP JSON-RPC 2.0 · tools/call · CIBA Step-Up",
            tool: toolSpec.name,
            status: "ALLOWED",
            delegatedBy: delegatedSession.humanSubject,
            actor: delegatedSession.actor,
            grantedScopes: delegatedSession.grantedScopes,
            result: {
              exportJobId: "exp_verified_ciba_stepup",
              status: "QUEUED",
              format: "csv"
            },
            defenseTrace,
            policyEvaluation: "SIMULATED_STS_WEB_CRYPTO_RS256"
          }
        };
      }

      const simAuthReqId = `ciba_sim_${nowSec}`;
      recordSimulatedMcpAudit({
        timestamp: nowIso,
        sub: delegatedSession.humanSubject,
        actorSub: delegatedSession.actor.sub,
        tool: toolSpec.name,
        riskTier: "high_risk_pii",
        decision: "DENIED",
        status: 403,
        reason: "human_approval_required",
        jti: `sim_jti_${nowSec}`
      });
      const defenseTrace: DefenseTrace = {
        layer: "MCP Human-in-the-Loop Step-Up Guard",
        middleware: "backend/src/mcp/toolRegistry.ts -> evaluateRegisteredMcpToolPolicy()",
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
          auth_req_id: simAuthReqId,
          binding_message: `Approve high-risk tool "export_all_users" (users:export) requested by ${delegatedSession.actor.sub}`,
          expires_in: 120,
          defenseTrace,
          policyEvaluation: "BROWSER_SIMULATION_MODE"
        }
      };
    }

    default:
      return assertNever(toolSpec.name);
  }
}

export async function exchangeDevIdpPersonaToken(
  baseUrl: string,
  role: DemoPersona,
  config: OidcConfig,
  pkceTelemetry?: PkceTelemetry | null
): Promise<TokenSession> {
  const telemetry = pkceTelemetry ?? (await generateLivePkceTelemetry());
  const persona = role === "user" ? "developer" : role;

  const authzRes = await fetch(`${baseUrl}/dev-idp/oauth2/authorize`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      persona,
      code_challenge: telemetry.codeChallenge,
      code_challenge_method: "S256",
      state: telemetry.state,
      client_id: config.clientId || "choreo-spa-public-client",
      redirect_uri: config.redirectUri
    })
  });
  const authzData: unknown = await authzRes.json();
  if (!authzRes.ok || !isRecord(authzData) || typeof authzData.code !== "string") {
    throw new Error("Dev IdP /oauth2/authorize failed to issue authorization code.");
  }

  const tokenRes = await fetch(`${baseUrl}/dev-idp/oauth2/token`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code: authzData.code,
      code_verifier: telemetry.codeVerifier
    })
  });
  const tokenData: unknown = await tokenRes.json();
  if (!tokenRes.ok || !isRecord(tokenData) || typeof tokenData.access_token !== "string") {
    throw new Error("Dev IdP /oauth2/token failed to exchange PKCE authorization code.");
  }

  const session: TokenSession = {
    accessToken: tokenData.access_token,
    idToken: typeof tokenData.id_token === "string" ? tokenData.id_token : undefined,
    tokenType: typeof tokenData.token_type === "string" ? tokenData.token_type : "Bearer",
    expiresIn: typeof tokenData.expires_in === "number" ? tokenData.expires_in : 3600,
    issuedAt: Date.now(),
    mode: "demo",
    demoRole: role,
    preset: config.preset,
    stsMode: "dev-idp"
  };
  saveSession(session);
  return session;
}

export async function exchangeDevIdpOboToken(
  baseUrl: string,
  subjectToken: string,
  config: OidcConfig,
  humanClaims: ParsedJwtClaims | null
): Promise<DelegatedAgentSession> {
  const dpopKey = await getBrowserDpopKeyPair();
  const res = await fetch(`${baseUrl}/dev-idp/oauth2/token`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: subjectToken,
      actor_token: "agent:choreo-integrator-bot",
      resource: config.mcpAudience,
      scope: "orders:read",
      dpop_jkt: dpopKey.jkt
    })
  });
  const raw: unknown = await res.json();
  if (!res.ok || !isRecord(raw) || typeof raw.access_token !== "string") {
    throw new Error("Dev IdP RFC 8693 token-exchange endpoint rejected subject_token.");
  }

  const decoded = decodeJwt(raw.access_token);
  const parsed = decoded ? parseJwtClaims(decoded) : null;
  const nowSec = Math.floor(Date.now() / 1000);
  const ttlSeconds =
    typeof raw.expires_in === "number" ? raw.expires_in : AGENT_TOKEN_MAX_TTL_SECONDS;
  const issuedAtSec =
    typeof raw.issued_at === "number" ? raw.issued_at : (parsed?.issuedAtSec ?? nowSec);
  const expiresAtSec =
    typeof raw.expires_at === "number"
      ? raw.expires_at
      : (parsed?.expiresAtSec ?? issuedAtSec + ttlSeconds);

  const actor: ActorClaim = parsed?.actor ?? {
    sub: "agent:choreo-integrator-bot",
    client_id: "choreo-mcp-agent-v1",
    delegation_protocol: "urn:ietf:params:oauth:grant-type:token-exchange"
  };

  return {
    accessToken: raw.access_token,
    humanSubject: parsed?.sub ?? humanClaims?.sub ?? "usr_4b21d90e_dev",
    humanUsername:
      parsed?.username ?? humanClaims?.username ?? "developer@acme-identity.example",
    actor,
    audience:
      typeof raw.audience === "string" ? raw.audience : config.mcpAudience,
    grantedScopes: parsed?.scopes.length ? parsed.scopes : ["orders:read"],
    originalScopes: parsed?.originalScopes.length
      ? parsed.originalScopes
      : (humanClaims?.scopes ?? ["openid", "profile", "orders:read"]),
    strippedScopes: parsed?.strippedScopes.length
      ? parsed.strippedScopes
      : ["admin:write", "refunds:execute"],
    ttlSeconds,
    issuedAtSec,
    expiresAtSec,
    preset: config.preset,
    stsMode: "dev-idp",
    dpopJkt: dpopKey.jkt,
    hasHumanApproval: false
  };
}

export async function submitCibaApprovalDecision(params: {
  readonly baseUrl: string;
  readonly authReqId: string;
  readonly decision: "APPROVED" | "DENIED";
  readonly delegatedSession: DelegatedAgentSession;
  readonly config: OidcConfig;
  readonly useLiveDevIdp: boolean;
}): Promise<{
  readonly approved: boolean;
  readonly updatedSession?: DelegatedAgentSession;
}> {
  const { baseUrl, authReqId, decision, delegatedSession, config, useLiveDevIdp } = params;
  if (decision === "DENIED") {
    if (useLiveDevIdp) {
      await fetch(`${baseUrl}/dev-idp/oauth2/ciba/decide`, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          auth_req_id: authReqId,
          decision: "DENIED"
        })
      }).catch(() => undefined);
    }
    return { approved: false };
  }

  const dpopKey = await getBrowserDpopKeyPair();
  if (useLiveDevIdp) {
    const res = await fetch(`${baseUrl}/dev-idp/oauth2/ciba/decide`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        auth_req_id: authReqId,
        decision: "APPROVED",
        dpop_jkt: dpopKey.jkt
      })
    });
    const raw: unknown = await res.json();
    if (res.ok && isRecord(raw) && typeof raw.access_token === "string") {
      const nowSec = Math.floor(Date.now() / 1000);
      return {
        approved: true,
        updatedSession: {
          ...delegatedSession,
          accessToken: raw.access_token,
          grantedScopes: ["orders:read", "users:export"],
          issuedAtSec: nowSec,
          expiresAtSec: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS,
          dpopJkt: dpopKey.jkt,
          hasHumanApproval: true
        }
      };
    }
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const stepUpPayload: Record<string, unknown> = {
    sub: delegatedSession.humanSubject,
    username: delegatedSession.humanUsername,
    iss: config.issuer,
    aud: config.mcpAudience,
    azp: delegatedSession.actor.client_id,
    act: delegatedSession.actor,
    cnf: { jkt: dpopKey.jkt },
    scope: "orders:read users:export",
    groups: ["delegated-agent-stepup"],
    delegation_depth: 1,
    human_approval_token: `hat_sim_${authReqId}`,
    approval: {
      auth_req_id: authReqId,
      tool: "export_all_users",
      approved_by: delegatedSession.humanSubject,
      expires_at: nowSec + 120
    },
    iat: nowSec,
    exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
  };
  const stepUpJwt = await signBrowserRs256Jwt(
    { alg: "RS256", typ: "at+jwt", kid: SIM_ACTIVE_KID },
    stepUpPayload,
    "active"
  );
  return {
    approved: true,
    updatedSession: {
      ...delegatedSession,
      accessToken: stepUpJwt,
      grantedScopes: ["orders:read", "users:export"],
      issuedAtSec: nowSec,
      expiresAtSec: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS,
      dpopJkt: dpopKey.jkt,
      hasHumanApproval: true
    }
  };
}

export async function revokeActiveToken(
  baseUrl: string,
  token: string,
  useLiveDevIdp: boolean
): Promise<void> {
  revokeSimulatedToken(token);
  if (useLiveDevIdp) {
    await fetch(`${baseUrl}/dev-idp/oauth2/revoke`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ token })
    }).catch(() => undefined);
  }
}

export async function probeDevIdpUnauthorizedActor(
  baseUrl: string,
  subjectToken: string,
  mcpAudience: string
): Promise<ApiCallResult> {
  return invokeProtectedApi(
    baseUrl,
    "/dev-idp/oauth2/token",
    "POST",
    undefined,
    {
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: subjectToken,
      actor_token: "agent:unlisted-rogue-bot",
      resource: mcpAudience,
      scope: "orders:read"
    }
  );
}

export async function requestDevIdpFaultToken(
  baseUrl: string,
  fault: FaultState,
  targetAudience: string,
  role?: DemoPersona
): Promise<string | null> {
  if (
    fault.id === "none" ||
    fault.id === "pkce_verifier_mismatch" ||
    fault.id === "csrf_state_mismatch"
  ) {
    return null;
  }
  const res = await fetch(`${baseUrl}/dev-idp/admin/mint-fault-token`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      fault,
      targetAudience,
      persona: role === "user" ? "developer" : (role ?? "admin")
    })
  });
  const data: unknown = await res.json();
  if (!res.ok || !isRecord(data) || typeof data.token !== "string") {
    return null;
  }
  return data.token;
}

export async function probeDevIdpPkceMismatch(
  baseUrl: string,
  pkceTelemetry: PkceTelemetry | null
): Promise<ApiCallResult> {
  const telemetry = pkceTelemetry ?? (await generateLivePkceTelemetry());
  const authzRes = await fetch(`${baseUrl}/dev-idp/oauth2/authorize`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      persona: "developer",
      code_challenge: telemetry.codeChallenge,
      code_challenge_method: "S256"
    })
  });
  const authzData: unknown = await authzRes.json();
  const code =
    isRecord(authzData) && typeof authzData.code === "string"
      ? authzData.code
      : "authz_code_invalid";

  const tamperedVerifier =
    telemetry.tamperedCodeVerifier ?? `${telemetry.codeVerifier.slice(0, -8)}TAMPERED`;
  return invokeProtectedApi(
    baseUrl,
    "/dev-idp/oauth2/token",
    "POST",
    undefined,
    {
      grant_type: "authorization_code",
      code,
      code_verifier: tamperedVerifier
    }
  );
}

/**
 * Cryptographically verifies the token via Web Crypto RSASSA-PKCS1-v1_5 in Browser Simulation Mode
 * before evaluating RBAC endpoint policy.
 */
export async function simulateVerifiedRbacPolicyCall(
  spec: ApiEndpointSpec,
  config: OidcConfig,
  session: TokenSession | null,
  claims: ParsedJwtClaims | null,
  activeFault?: FaultState,
  pkceTelemetry?: PkceTelemetry | null,
  verificationMode: VerificationMode = "jwks"
): Promise<ApiCallResult> {
  const nowSec = Math.floor(Date.now() / 1000);
  const nowIso = new Date(nowSec * 1000).toISOString();

  if (spec.policyKind === "public") {
    return simulateRbacPolicyCall(spec, config, session, claims, activeFault);
  }

  if (
    activeFault &&
    (activeFault.id === "pkce_verifier_mismatch" ||
      activeFault.id === "csrf_state_mismatch" ||
      activeFault.id === "dpop_token_replay" ||
      activeFault.id === "rfc8707_token_passthrough" ||
      activeFault.id === "act_chain_violation" ||
      activeFault.id === "unauthorized_actor_may_act")
  ) {
    return simulateRbacPolicyCall(spec, config, session, claims, activeFault);
  }

  const faultToken =
    activeFault && activeFault.id !== "none"
      ? await mintSimulatedFaultToken(activeFault, {
          config,
          claims,
          pkceTelemetry: pkceTelemetry ?? null,
          nowSec,
          targetAudience: config.audience
        })
      : null;

  const tokenToVerify = faultToken ?? session?.accessToken ?? null;
  if (!tokenToVerify) {
    return simulateRbacPolicyCall(spec, config, null, null);
  }

  const verified = await verifyBrowserRs256Jwt(tokenToVerify, {
    expectedIssuer: config.issuer,
    expectedAudience: config.audience,
    nowSec
  });

  if (!verified.ok) {
    return {
      endpoint: spec.path,
      method: spec.method,
      status: verified.status,
      latencyMs: 3,
      ok: false,
      mode: "dry-run",
      defenseTrace: verified.defenseTrace,
      timestamp: nowIso,
      data: {
        error: verified.errorCode,
        status: verified.status,
        message: verified.message,
        defenseTrace: verified.defenseTrace,
        policyEvaluation: "SIMULATED_STS_WEB_CRYPTO_RS256"
      }
    };
  }

  if (verificationMode === "introspect" && isSimulatedTokenRevoked(tokenToVerify)) {
    const revokeTrace: DefenseTrace = {
      layer: "RFC 7662 Stateful Token Introspection Guard",
      middleware: "frontend/src/lib/apiClient.ts -> introspect(token)",
      rfc: "RFC 7662 §2.2 (Introspection Response active: false)",
      check: "introspect(token).active === true",
      outcome: "REJECTED",
      details:
        "Stateful introspection (+1 IdP hop) detected real-time revocation before exp, whereas stateless JWKS verification continues accepting the token until exp."
    };
    return {
      endpoint: spec.path,
      method: spec.method,
      status: 401,
      latencyMs: 14,
      ok: false,
      mode: "dry-run",
      defenseTrace: revokeTrace,
      timestamp: nowIso,
      data: {
        error: "token_revoked",
        status: 401,
        verificationMode: "introspect",
        message:
          "Token was revoked via RFC 7009 and detected as active=false by RFC 7662 Token Introspection.",
        defenseTrace: revokeTrace,
        policyEvaluation: "SIMULATED_STS_WEB_CRYPTO_RS256"
      }
    };
  }

  const verifiedDecoded = decodeJwt(tokenToVerify);
  const verifiedClaims = verifiedDecoded ? parseJwtClaims(verifiedDecoded) : claims;
  const rbacResult = simulateRbacPolicyCall(spec, config, session, verifiedClaims);

  if (verified.recoveredRotatedKey && rbacResult.ok) {
    return {
      ...rbacResult,
      defenseTrace: verified.defenseTrace
    };
  }
  return rbacResult;
}

/**
 * Cryptographically verifies the delegated agent token via Web Crypto RSASSA-PKCS1-v1_5
 * in Browser Simulation Mode before evaluating MCP tool policies.
 */
export async function simulateVerifiedMcpToolCall(
  toolSpec: McpToolSpec,
  delegatedSession: DelegatedAgentSession,
  config: OidcConfig,
  activeFault?: FaultState,
  pkceTelemetry?: PkceTelemetry | null,
  nowSecOverride?: number
): Promise<ApiCallResult> {
  const nowSec = nowSecOverride ?? Math.floor(Date.now() / 1000);
  const nowIso = new Date(nowSec * 1000).toISOString();
  const endpoint = "/api/mcp/tools/call";

  if (
    activeFault &&
    (activeFault.id === "pkce_verifier_mismatch" ||
      activeFault.id === "csrf_state_mismatch" ||
      activeFault.id === "dpop_token_replay" ||
      activeFault.id === "act_chain_violation" ||
      activeFault.id === "unauthorized_actor_may_act")
  ) {
    return simulateMcpToolCall(toolSpec, delegatedSession, config, activeFault, nowSec);
  }

  const faultToken =
    activeFault && activeFault.id !== "none"
      ? await mintSimulatedFaultToken(activeFault, {
          config,
          claims: null,
          pkceTelemetry: pkceTelemetry ?? null,
          nowSec,
          targetAudience: config.mcpAudience
        })
      : null;

  const tokenToVerify = faultToken ?? delegatedSession.accessToken;
  const verified = await verifyBrowserRs256Jwt(tokenToVerify, {
    expectedIssuer: config.issuer,
    expectedAudience: config.mcpAudience,
    nowSec
  });

  if (!verified.ok) {
    return {
      endpoint,
      method: "POST",
      status: verified.status,
      latencyMs: 3,
      ok: false,
      mode: "dry-run",
      defenseTrace: verified.defenseTrace,
      timestamp: nowIso,
      data: {
        error: verified.errorCode,
        tool: toolSpec.name,
        message: verified.message,
        defenseTrace: verified.defenseTrace,
        policyEvaluation: "SIMULATED_STS_WEB_CRYPTO_RS256"
      }
    };
  }

  return simulateMcpToolCall(toolSpec, delegatedSession, config, undefined, nowSec);
}
