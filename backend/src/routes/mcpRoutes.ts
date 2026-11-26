import express, { type RequestHandler, type Router } from "express";
import identityConfig from "../config/identityConfig.js";
import { createAuthMiddleware } from "../middleware/authMiddleware.js";
import { sendBearerError } from "../middleware/bearerChallenge.js";
import {
  evaluateMcpToolAuthorization,
  requireAgentDelegation
} from "../middleware/rbacMiddleware.js";
import { assertNever, type McpToolName } from "../types/auth.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseMcpToolName(raw: unknown): McpToolName | null {
  if (raw === "get_order_status" || raw === "issue_refund" || raw === "export_all_users") {
    return raw;
  }
  return null;
}

export const authenticateMcpToken: RequestHandler = createAuthMiddleware({
  audience: identityConfig.mcpAudience
});

export function createMcpRouter(authMiddleware: RequestHandler = authenticateMcpToken): Router {
  const router = express.Router();

  router.post(
    "/tools/call",
    authMiddleware,
    requireAgentDelegation(),
    (req, res) => {
      const user = req.user;
      if (!user || !user.actor) {
        sendBearerError(res, 401, null, {
          error: "unauthorized",
          message: "Missing delegated agent authentication context."
        });
        return;
      }

      if (!isRecord(req.body)) {
        res.status(400).json({
          error: "invalid_request",
          message: 'Request body must be a JSON object containing a valid "tool" identifier.'
        });
        return;
      }

      const tool = parseMcpToolName(req.body.tool);
      if (!tool) {
        res.status(400).json({
          error: "unknown_mcp_tool",
          message:
            'Unsupported MCP tool. Expected one of: "get_order_status", "issue_refund", "export_all_users".'
        });
        return;
      }

      const decision = evaluateMcpToolAuthorization(user, tool);
      if (!decision.allowed) {
        sendBearerError(
          res,
          decision.status,
          {
            error: "insufficient_scope",
            description: decision.message,
            scope: [decision.requiredScope]
          },
          {
            error: decision.error,
            message: decision.message,
            tool: decision.tool,
            requiredScope: decision.requiredScope,
            grantedScopes: user.scopes,
            delegatedBy: user.sub,
            actor: user.actor,
            defenseTrace: decision.defenseTrace
          }
        );
        return;
      }

      const rawArgs = isRecord(req.body.arguments) ? req.body.arguments : {};
      const orderId =
        typeof rawArgs.orderId === "string" && rawArgs.orderId.trim().length > 0
          ? rawArgs.orderId.trim().slice(0, 64)
          : "ORD-2026-88412";

      let toolOutput: Record<string, unknown>;
      switch (tool) {
        case "get_order_status":
          toolOutput = {
            orderId,
            fulfillmentState: "SHIPPED",
            carrier: "Choreo Logistics Express",
            estimatedDelivery: "2026-11-26",
            redactedPii: true
          };
          break;
        case "issue_refund":
          toolOutput = {
            orderId,
            refundStatus: "PROCESSED"
          };
          break;
        case "export_all_users":
          toolOutput = {
            exportJobId: "exp_verified_stepup",
            status: "QUEUED"
          };
          break;
        default:
          assertNever(tool);
      }

      res.status(200).json({
        protocol: "MCP tools/call · RFC 8693 OBO",
        tool,
        status: "ALLOWED",
        delegatedBy: user.sub,
        actor: user.actor,
        grantedScopes: user.scopes,
        ttlRemainingSec:
          user.expiresAtSec !== null
            ? Math.max(0, user.expiresAtSec - Math.floor(Date.now() / 1000))
            : null,
        result: toolOutput,
        defenseTrace: decision.defenseTrace,
        timestamp: new Date().toISOString()
      });
    }
  );

  return router;
}

export default createMcpRouter();
