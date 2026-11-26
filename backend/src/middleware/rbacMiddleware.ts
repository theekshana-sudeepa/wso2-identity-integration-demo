import type { RequestHandler } from "express";
import { AGENT_TOKEN_MAX_TTL_SECONDS, MAX_DELEGATION_DEPTH } from "../config/agentPolicy.js";
import {
  assertNever,
  type AuthenticatedUser,
  type DefenseTrace,
  type McpPolicyDecision,
  type McpToolName
} from "../types/auth.js";
import { sendBearerError } from "./bearerChallenge.js";
import { evaluateActChain } from "./delegationPolicy.js";

export function requireRoles(...allowedRoles: string[]): RequestHandler {
  const normalizedAllowed = allowedRoles.map((role) => role.toLowerCase());

  return (req, res, next) => {
    if (!req.user) {
      sendBearerError(res, 401, null, {
        error: "unauthorized",
        message: "Authentication context missing."
      });
      return;
    }

    const userGroups = req.user.groups.map((group) => group.toLowerCase());
    const hasMatch = normalizedAllowed.some((role) => userGroups.includes(role));

    if (!hasMatch) {
      const description = `Required role(s): ${allowedRoles.join(", ")}`;
      const defenseTrace: DefenseTrace = {
        layer: "RBAC Role Guard",
        middleware: "backend/src/middleware/rbacMiddleware.ts",
        rfc: "NIST RBAC · Least Privilege",
        check: `requireRoles(${allowedRoles.map((r) => `"${r}"`).join(", ")})`,
        outcome: "REJECTED",
        details: `Principal groups [${req.user.groups.join(", ")}] do not satisfy required roles [${allowedRoles.join(", ")}].`
      };
      sendBearerError(
        res,
        403,
        { error: "insufficient_scope", description },
        {
          error: "forbidden",
          message: `Access denied. Required role(s): ${allowedRoles.join(", ")}.`,
          assignedRoles: req.user.groups,
          defenseTrace
        }
      );
      return;
    }

    next();
  };
}

export function requireScopes(...requiredScopes: string[]): RequestHandler {
  return (req, res, next) => {
    if (!req.user) {
      sendBearerError(res, 401, null, {
        error: "unauthorized",
        message: "Authentication context missing."
      });
      return;
    }

    const userScopes = req.user.scopes;
    const missingScopes = requiredScopes.filter((scope) => !userScopes.includes(scope));

    if (missingScopes.length > 0) {
      const description = `Missing required OAuth2 scope(s): ${missingScopes.join(", ")}`;
      const defenseTrace: DefenseTrace = {
        layer: "OAuth 2.0 Scope Guard",
        middleware: "backend/src/middleware/rbacMiddleware.ts",
        rfc: "RFC 6750 §3.1 (insufficient_scope)",
        check: `requireScopes(${requiredScopes.map((s) => `"${s}"`).join(", ")})`,
        outcome: "REJECTED",
        details: `Missing required scope(s): ${missingScopes.join(", ")}.`
      };
      sendBearerError(
        res,
        403,
        { error: "insufficient_scope", description, scope: requiredScopes },
        {
          error: "insufficient_scope",
          message: `Missing required OAuth2 scope(s): ${missingScopes.join(", ")}.`,
          grantedScopes: userScopes,
          defenseTrace
        }
      );
      return;
    }

    next();
  };
}

export interface AgentDelegationOptions {
  readonly maxTtlSeconds?: number;
  readonly maxDepth?: number;
}

export function requireAgentDelegation(options?: AgentDelegationOptions): RequestHandler {
  const maxTtlSeconds = options?.maxTtlSeconds ?? AGENT_TOKEN_MAX_TTL_SECONDS;
  const maxDepth = options?.maxDepth ?? MAX_DELEGATION_DEPTH;

  return (req, res, next) => {
    if (!req.user) {
      sendBearerError(res, 401, null, {
        error: "unauthorized",
        message: "Authentication context missing."
      });
      return;
    }

    const { sub, actorChain, actorChainTruncated, issuedAtSec, expiresAtSec } = req.user;
    const chainVerdict = evaluateActChain(sub, actorChain, actorChainTruncated, maxDepth);
    if (!chainVerdict.ok) {
      let message: string;
      let defenseTrace: DefenseTrace;

      switch (chainVerdict.reason) {
        case "delegation_required":
          message =
            "MCP tool invocation requires an RFC 8693 On-Behalf-Of (OBO) delegated token with an act.sub agent claim.";
          defenseTrace = {
            layer: "RFC 8693 Agent Delegation Guard",
            middleware: "backend/src/middleware/rbacMiddleware.ts",
            rfc: "RFC 8693 §4.1 (act Actor Claim)",
            check: 'requireAgentDelegation() -> verify(act.sub.startsWith("agent:"))',
            outcome: "REJECTED",
            details: chainVerdict.details
          };
          break;
        case "delegation_chain_too_deep":
          message = chainVerdict.details;
          defenseTrace = {
            layer: "RFC 8693 Delegation Chain Guard",
            middleware: "backend/src/middleware/rbacMiddleware.ts",
            rfc: "RFC 8693 §4.1 (Nested act Claim)",
            check: `evaluateActChain(depth <= ${maxDepth})`,
            outcome: "REJECTED",
            details: chainVerdict.details
          };
          break;
        case "delegation_cycle_detected":
          message = chainVerdict.details;
          defenseTrace = {
            layer: "RFC 8693 Delegation Chain Guard",
            middleware: "backend/src/middleware/rbacMiddleware.ts",
            rfc: "RFC 8693 §4.1 (Nested act Claim)",
            check: "evaluateActChain(acyclic actor chain)",
            outcome: "REJECTED",
            details: chainVerdict.details
          };
          break;
        default:
          return assertNever(chainVerdict.reason);
      }

      sendBearerError(
        res,
        403,
        { error: "insufficient_scope", description: message },
        {
          error: chainVerdict.reason,
          message,
          defenseTrace
        }
      );
      return;
    }

    if (issuedAtSec === null || expiresAtSec === null || expiresAtSec - issuedAtSec > maxTtlSeconds) {
      const ttl =
        issuedAtSec !== null && expiresAtSec !== null ? expiresAtSec - issuedAtSec : -1;
      const message = `Delegated AI agent token TTL must not exceed ${maxTtlSeconds} seconds.`;
      const defenseTrace: DefenseTrace = {
        layer: "Delegated Token Short-TTL Guard",
        middleware: "backend/src/middleware/rbacMiddleware.ts",
        rfc: "RFC 8693 · Short-Lived Delegation Bound",
        check: `verify((exp - iat) <= ${maxTtlSeconds}s)`,
        outcome: "REJECTED",
        details: `Delegated agent token TTL (${ttl}s) exceeds maximum allowed window (${maxTtlSeconds}s).`
      };
      sendBearerError(
        res,
        403,
        { error: "insufficient_scope", description: message },
        {
          error: "delegation_ttl_exceeded",
          message,
          defenseTrace
        }
      );
      return;
    }

    next();
  };
}

export function evaluateMcpToolAuthorization(
  user: AuthenticatedUser,
  tool: McpToolName
): McpPolicyDecision {
  switch (tool) {
    case "get_order_status": {
      const requiredScope = "orders:read";
      if (!user.scopes.includes(requiredScope)) {
        return {
          allowed: false,
          status: 403,
          error: "scope_escalation_blocked",
          message: `Scope escalation blocked: delegated agent lacks "${requiredScope}" for ${tool}.`,
          tool,
          requiredScope,
          defenseTrace: {
            layer: "MCP Tool Scope-Subset Guard",
            middleware: "backend/src/middleware/rbacMiddleware.ts",
            rfc: "RFC 8693 §2.1 (Down-Scoped Token Exchange)",
            check: `evaluateMcpToolAuthorization("${tool}") -> scopes.includes("${requiredScope}")`,
            outcome: "REJECTED",
            details: `Granted agent scopes [${user.scopes.join(", ")}] do not include "${requiredScope}".`
          }
        };
      }
      return {
        allowed: true,
        tool,
        requiredScope,
        defenseTrace: {
          layer: "MCP Tool Scope-Subset Guard",
          middleware: "backend/src/middleware/rbacMiddleware.ts",
          rfc: "RFC 8693 §4.1 (act + Down-Scoped Access)",
          check: `evaluateMcpToolAuthorization("${tool}") -> act.sub + scopes.includes("${requiredScope}")`,
          outcome: "ALLOWED",
          details: `Delegated agent "${user.actor?.sub ?? "unknown"}" authorized on behalf of "${user.sub}" with narrowed scope "${requiredScope}".`
        }
      };
    }

    case "issue_refund": {
      const requiredScope = "refunds:execute";
      if (!user.scopes.includes(requiredScope)) {
        return {
          allowed: false,
          status: 403,
          error: "scope_escalation_blocked",
          message:
            'Scope escalation blocked: "refunds:execute" was intentionally stripped during RFC 8693 OBO token down-scoping.',
          tool,
          requiredScope,
          defenseTrace: {
            layer: "MCP Tool Scope-Subset Guard",
            middleware: "backend/src/middleware/rbacMiddleware.ts",
            rfc: "RFC 8693 §2.1 (Privilege Attenuation)",
            check: `evaluateMcpToolAuthorization("${tool}") -> scopes.includes("${requiredScope}")`,
            outcome: "REJECTED",
            details: `Autonomous agent attempted privileged financial mutation "${tool}" without "${requiredScope}". Granted scopes: [${user.scopes.join(", ")}].`
          }
        };
      }
      return {
        allowed: true,
        tool,
        requiredScope,
        defenseTrace: {
          layer: "MCP Tool Scope-Subset Guard",
          middleware: "backend/src/middleware/rbacMiddleware.ts",
          rfc: "RFC 8693 §2.1",
          check: `evaluateMcpToolAuthorization("${tool}") -> scopes.includes("${requiredScope}")`,
          outcome: "ALLOWED",
          details: `Explicitly scoped refund tool executed by "${user.actor?.sub ?? "unknown"}".`
        }
      };
    }

    case "export_all_users": {
      const requiredScope = "users:export";
      const hasHumanApproval = Boolean(user.rawClaims.human_approval_token);
      if (!hasHumanApproval || !user.scopes.includes(requiredScope)) {
        return {
          allowed: false,
          status: 403,
          error: "human_approval_required",
          message:
            "Human approval required: bulk PII export cannot be executed autonomously by a delegated AI agent without step-up human consent.",
          tool,
          requiredScope,
          defenseTrace: {
            layer: "MCP Human-in-the-Loop Step-Up Guard",
            middleware: "backend/src/middleware/rbacMiddleware.ts",
            rfc: "RFC 8693 + CIBA / Step-Up Human Consent",
            check: `evaluateMcpToolAuthorization("${tool}") -> verify(human_approval_token && "${requiredScope}")`,
            outcome: "REJECTED",
            details:
              'High-risk PII exfiltration tool "export_all_users" requires interactive human step-up approval (missing human_approval_token).'
          }
        };
      }
      return {
        allowed: true,
        tool,
        requiredScope,
        defenseTrace: {
          layer: "MCP Human-in-the-Loop Step-Up Guard",
          middleware: "backend/src/middleware/rbacMiddleware.ts",
          rfc: "RFC 8693 + Step-Up Consent",
          check: `evaluateMcpToolAuthorization("${tool}") -> verified step-up token`,
          outcome: "ALLOWED",
          details: "Step-up human approval token verified."
        }
      };
    }

    default:
      return assertNever(tool);
  }
}
