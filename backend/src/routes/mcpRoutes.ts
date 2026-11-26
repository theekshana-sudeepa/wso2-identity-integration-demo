import express, { type RequestHandler, type Router } from "express";
import identityConfig from "../config/identityConfig.js";
import { mcpAuditLog } from "../mcp/auditLog.js";
import {
  isMcpToolName,
  MCP_TOOL_LIST,
  MCP_TOOL_REGISTRY
} from "../mcp/toolRegistry.js";
import { createAuthMiddleware } from "../middleware/authMiddleware.js";
import { sendBearerError } from "../middleware/bearerChallenge.js";
import {
  evaluateMcpToolAuthorization,
  requireAgentDelegation
} from "../middleware/rbacMiddleware.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export const PROTECTED_RESOURCE_METADATA_URL = `http://localhost:${identityConfig.port}/.well-known/oauth-protected-resource`;

export const authenticateMcpToken: RequestHandler = createAuthMiddleware({
  audience: identityConfig.mcpAudience,
  resourceMetadataUrl: PROTECTED_RESOURCE_METADATA_URL
});

export function createMcpRouter(authMiddleware: RequestHandler = authenticateMcpToken): Router {
  const router = express.Router();

  router.get("/audit", (_req, res) => {
    res.status(200).json({
      entries: mcpAuditLog.list(),
      totalRecorded: mcpAuditLog.totalRecorded()
    });
  });

  const handleMcpRequest: RequestHandler = (req, res) => {
    const user = req.user;
    if (!user || !user.actor) {
      sendBearerError(
        res,
        401,
        { resourceMetadataUrl: PROTECTED_RESOURCE_METADATA_URL },
        {
          error: "unauthorized",
          message: "Missing delegated agent authentication context."
        }
      );
      return;
    }

    if (!isRecord(req.body)) {
      res.status(400).json({
        jsonrpc: "2.0",
        id: null,
        error: "invalid_request",
        message: "Request body must be a JSON object."
      });
      return;
    }

    const isJsonRpc = req.body.jsonrpc === "2.0" || typeof req.body.method === "string";
    const rpcId: string | number | null =
      typeof req.body.id === "number" || typeof req.body.id === "string"
        ? req.body.id
        : 1;
    const rpcMethod =
      typeof req.body.method === "string" ? req.body.method : "tools/call";

    if (isJsonRpc && rpcMethod === "tools/list") {
      const tools = MCP_TOOL_LIST.map((descriptor) => ({
        name: descriptor.name,
        description: descriptor.description,
        inputSchema: descriptor.inputSchema,
        annotations: {
          requiredScopes: descriptor.requiredScopes,
          riskTier: descriptor.riskTier,
          requiresHumanApproval: descriptor.requiresHumanApproval
        }
      }));

      res.status(200).json({
        jsonrpc: "2.0",
        id: rpcId,
        result: {
          tools
        }
      });
      return;
    }

    if (isJsonRpc && rpcMethod !== "tools/call") {
      res.status(400).json({
        jsonrpc: "2.0",
        id: rpcId,
        error: {
          code: -32601,
          message: `Method not found: "${rpcMethod}". Supported methods: "tools/list", "tools/call".`
        }
      });
      return;
    }

    const params = isRecord(req.body.params) ? req.body.params : req.body;
    const rawToolName = params.name ?? req.body.tool;

    if (!isMcpToolName(rawToolName)) {
      res.status(400).json({
        jsonrpc: "2.0",
        id: rpcId,
        error: "unknown_mcp_tool",
        message:
          'Unsupported MCP tool. Expected one of: "get_order_status", "issue_refund", "export_all_users".',
        rpcError: {
          code: -32602,
          message: `Unknown MCP tool "${String(rawToolName ?? "")}".`
        }
      });
      return;
    }

    const descriptor = MCP_TOOL_REGISTRY[rawToolName];
    const rawArgs = params.arguments ?? req.body.arguments;
    const argValidation = descriptor.validateArguments(rawArgs);
    if (!argValidation.ok) {
      res.status(400).json({
        jsonrpc: "2.0",
        id: rpcId,
        error: "invalid_tool_arguments",
        message: argValidation.errors.join(" "),
        validationErrors: argValidation.errors,
        rpcError: {
          code: -32602,
          message: "Invalid params: tool arguments failed inputSchema validation.",
          data: { errors: argValidation.errors }
        }
      });
      return;
    }

    const jti =
      typeof user.rawClaims.jti === "string" ? user.rawClaims.jti : null;
    const decision = evaluateMcpToolAuthorization(user, rawToolName);

    if (!decision.allowed) {
      mcpAuditLog.record({
        sub: user.sub,
        actorSub: user.actor.sub,
        tool: rawToolName,
        riskTier: descriptor.riskTier,
        decision: "DENIED",
        status: decision.status,
        reason: decision.error,
        jti
      });

      sendBearerError(
        res,
        decision.status,
        {
          error: "insufficient_scope",
          description: decision.message,
          scope: [decision.requiredScope],
          resourceMetadataUrl: PROTECTED_RESOURCE_METADATA_URL
        },
        {
          jsonrpc: "2.0",
          id: rpcId,
          error: decision.error,
          message: decision.message,
          tool: decision.tool,
          riskTier: descriptor.riskTier,
          requiredScope: decision.requiredScope,
          grantedScopes: user.scopes,
          delegatedBy: user.sub,
          actor: user.actor,
          defenseTrace: decision.defenseTrace,
          rpcError: {
            code: -32001,
            message: decision.message,
            data: {
              error: decision.error,
              requiredScope: decision.requiredScope,
              defenseTrace: decision.defenseTrace
            }
          }
        }
      );
      return;
    }

    const toolOutput = descriptor.execute(argValidation.value);
    mcpAuditLog.record({
      sub: user.sub,
      actorSub: user.actor.sub,
      tool: rawToolName,
      riskTier: descriptor.riskTier,
      decision: "ALLOWED",
      status: 200,
      reason: "authorized_downscoped_obo",
      jti
    });

    res.status(200).json({
      jsonrpc: "2.0",
      id: rpcId,
      protocol: "MCP JSON-RPC 2.0 · tools/call · RFC 8693 OBO",
      tool: rawToolName,
      riskTier: descriptor.riskTier,
      status: "ALLOWED",
      delegatedBy: user.sub,
      actor: user.actor,
      grantedScopes: user.scopes,
      ttlRemainingSec:
        user.expiresAtSec !== null
          ? Math.max(0, user.expiresAtSec - Math.floor(Date.now() / 1000))
          : null,
      result: {
        ...toolOutput,
        content: [
          {
            type: "text",
            text: JSON.stringify(toolOutput)
          }
        ]
      },
      defenseTrace: decision.defenseTrace,
      timestamp: new Date().toISOString()
    });
  };

  router.post("/", authMiddleware, requireAgentDelegation(), handleMcpRequest);
  router.post("/tools/call", authMiddleware, requireAgentDelegation(), handleMcpRequest);

  return router;
}

export default createMcpRouter();
