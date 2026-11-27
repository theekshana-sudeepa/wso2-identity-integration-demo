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

export type SharedApimSubscriptionTier = "Bronze" | "Silver" | "Gold" | "AI-Agent-MCP";
export type SharedIntegrationFaultMode =
  | "nominal"
  | "throttle_spike"
  | "upstream_timeout_cb"
  | "dag_cycle_fault";
export type SharedDsaAlgorithmId =
  | "radix_trie"
  | "doubly_linked_lru"
  | "token_bucket"
  | "circuit_breaker_min_heap"
  | "dag_topological_sort";

export interface SharedDsaAlgorithmCatalogEntry {
  readonly id: SharedDsaAlgorithmId;
  readonly name: string;
  readonly timeComplexity: string;
  readonly spaceComplexity: string;
  readonly wso2ProductComponent: string;
}

export const SHARED_DSA_CATALOG: readonly SharedDsaAlgorithmCatalogEntry[] = [
  {
    id: "radix_trie",
    name: "Radix Prefix Segment Trie",
    timeComplexity: "O(k) where k = URL path segments",
    spaceComplexity: "O(N * k)",
    wso2ProductComponent: "WSO2 API Manager Gateway / Synapse URI-Template Matcher"
  },
  {
    id: "doubly_linked_lru",
    name: "Doubly-Linked List + HashMap LRU Cache (with TTL)",
    timeComplexity: "O(1) strict get / put / evict",
    spaceComplexity: "O(C) capacity",
    wso2ProductComponent: "WSO2 APIM Response Cache Mediator & JWKS kid Cache"
  },
  {
    id: "token_bucket",
    name: "Token Bucket Continuous Refill Throttler",
    timeComplexity: "O(1) arithmetic refill & consume",
    spaceComplexity: "O(S) active subscribers",
    wso2ProductComponent: "WSO2 APIM Traffic Manager Subscription Tiers (Bronze/Silver/Gold)"
  },
  {
    id: "circuit_breaker_min_heap",
    name: "FSM Circuit Breaker + Binary Min-Heap Priority Queue",
    timeComplexity: "O(1) FSM transition · O(log n) Min-Heap enqueue/poll",
    spaceComplexity: "O(n) queued DLQ retry messages",
    wso2ProductComponent: "WSO2 Micro Integrator Endpoint SuspendOnFailure & Message Processor DLQ"
  },
  {
    id: "dag_topological_sort",
    name: "DAG Kahn's BFS Topological Sort & Cycle Detector",
    timeComplexity: "O(V + E) vertices + dependency edges",
    spaceComplexity: "O(V + E)",
    wso2ProductComponent: "WSO2 Micro Integrator Mediation Sequence & Clone/Aggregate Planner"
  }
];
