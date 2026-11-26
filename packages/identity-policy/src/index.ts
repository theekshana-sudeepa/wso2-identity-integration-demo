/**
 * Shared pure-TypeScript Identity & Delegation Policy Engine
 * (Zero DOM or Node.js runtime dependencies; shared across frontend & backend)
 */

export const AGENT_TOKEN_MAX_TTL_SECONDS = 60;
export const MAX_DELEGATION_DEPTH = 2;
export const AGENT_ACTOR_PREFIX = "agent:";

export type McpToolName = "get_order_status" | "issue_refund" | "export_all_users";
export type McpRiskTier = "read" | "write" | "high_risk_pii";
export type PolicyKind = "public" | "jwt" | "role" | "scope";

export interface SharedDefenseTrace {
  readonly layer: string;
  readonly middleware: string;
  readonly rfc: string;
  readonly check: string;
  readonly outcome: "ALLOWED" | "REJECTED" | "RECOVERED";
  readonly details: string;
}

export interface SharedActorClaim {
  readonly sub: string;
  readonly client_id?: string;
  readonly delegation_protocol?: string;
  readonly act?: SharedActorClaim;
}

export interface SharedEndpointPolicySpec {
  readonly id: string;
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly policyKind: PolicyKind;
  readonly requiredRole?: string;
  readonly requiredScope?: string;
}

export const SHARED_ENDPOINT_POLICIES: readonly SharedEndpointPolicySpec[] = [
  {
    id: "public-info",
    method: "GET",
    path: "/api/v1/public/info",
    policyKind: "public"
  },
  {
    id: "user-profile",
    method: "GET",
    path: "/api/v1/user/profile",
    policyKind: "jwt"
  },
  {
    id: "user-roles",
    method: "GET",
    path: "/api/v1/user/roles",
    policyKind: "jwt"
  },
  {
    id: "admin-audit",
    method: "GET",
    path: "/api/v1/admin/audit-logs",
    policyKind: "role",
    requiredRole: "admin"
  },
  {
    id: "create-report",
    method: "POST",
    path: "/api/v1/reports",
    policyKind: "scope",
    requiredScope: "write:reports"
  }
];

export function evaluateSharedEndpointStatus(
  spec: SharedEndpointPolicySpec,
  principal: {
    readonly authenticated: boolean;
    readonly groups: readonly string[];
    readonly scopes: readonly string[];
  }
): 200 | 201 | 401 | 403 {
  const successCode = spec.method === "POST" ? 201 : 200;
  if (spec.policyKind === "public") {
    return successCode;
  }
  if (!principal.authenticated) {
    return 401;
  }
  if (spec.policyKind === "role" && spec.requiredRole) {
    const reqRole = spec.requiredRole.toLowerCase();
    const hasRole = principal.groups.some(
      (g) => g.toLowerCase() === reqRole || g.toLowerCase() === "administrator"
    );
    return hasRole ? successCode : 403;
  }
  if (spec.policyKind === "scope" && spec.requiredScope) {
    return principal.scopes.includes(spec.requiredScope) ? successCode : 403;
  }
  return successCode;
}
