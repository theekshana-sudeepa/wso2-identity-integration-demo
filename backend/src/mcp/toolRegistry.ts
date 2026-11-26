import type {
  AuthenticatedUser,
  McpPolicyDecision,
  McpToolName
} from "../types/auth.js";
import { cibaApprovalStore } from "./cibaStore.js";

export type McpRiskTier = "read" | "write" | "high_risk_pii";

export interface JsonSchemaProperty {
  readonly type: "string" | "number" | "boolean";
  readonly description: string;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly minimum?: number;
  readonly enum?: readonly string[];
}

export interface ToolInputJsonSchema {
  readonly type: "object";
  readonly properties: Readonly<Record<string, JsonSchemaProperty>>;
  readonly required: readonly string[];
  readonly additionalProperties: boolean;
}

export type ToolArgumentValidationResult =
  | { readonly ok: true; readonly value: Record<string, unknown> }
  | { readonly ok: false; readonly errors: readonly string[] };

export interface McpToolDescriptor {
  readonly name: McpToolName;
  readonly description: string;
  readonly inputSchema: ToolInputJsonSchema;
  readonly requiredScopes: readonly string[];
  readonly riskTier: McpRiskTier;
  readonly requiresHumanApproval: boolean;
  readonly validateArguments: (raw: unknown) => ToolArgumentValidationResult;
  readonly execute: (validatedArgs: Record<string, unknown>) => Record<string, unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateAgainstJsonSchema(
  schema: ToolInputJsonSchema,
  raw: unknown,
  defaults: Record<string, unknown>
): ToolArgumentValidationResult {
  if (raw === undefined || raw === null) {
    return { ok: true, value: { ...defaults } };
  }
  if (!isRecord(raw)) {
    return {
      ok: false,
      errors: ["Tool arguments must be a JSON object."]
    };
  }

  const errors: string[] = [];
  const merged: Record<string, unknown> = { ...defaults, ...raw };

  for (const reqKey of schema.required) {
    if (merged[reqKey] === undefined || merged[reqKey] === null) {
      errors.push(`Missing required parameter "${reqKey}".`);
    }
  }

  for (const [key, val] of Object.entries(merged)) {
    const propSchema = schema.properties[key];
    if (!propSchema) {
      if (!schema.additionalProperties) {
        errors.push(`Unknown argument "${key}" is not permitted by inputSchema.`);
      }
      continue;
    }

    if (propSchema.type === "string") {
      if (typeof val !== "string") {
        errors.push(`Parameter "${key}" must be a string.`);
        continue;
      }
      if (propSchema.minLength !== undefined && val.trim().length < propSchema.minLength) {
        errors.push(`Parameter "${key}" must be at least ${propSchema.minLength} character(s).`);
      }
      if (propSchema.maxLength !== undefined && val.length > propSchema.maxLength) {
        errors.push(`Parameter "${key}" must not exceed ${propSchema.maxLength} characters.`);
      }
      if (propSchema.enum && !propSchema.enum.includes(val)) {
        errors.push(`Parameter "${key}" must be one of: ${propSchema.enum.join(", ")}.`);
      }
    } else if (propSchema.type === "number") {
      if (typeof val !== "number" || !Number.isFinite(val)) {
        errors.push(`Parameter "${key}" must be a finite number.`);
        continue;
      }
      if (propSchema.minimum !== undefined && val < propSchema.minimum) {
        errors.push(`Parameter "${key}" must be >= ${propSchema.minimum}.`);
      }
    } else if (propSchema.type === "boolean") {
      if (typeof val !== "boolean") {
        errors.push(`Parameter "${key}" must be a boolean.`);
      }
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }
  return { ok: true, value: merged };
}

const getOrderStatusSchema: ToolInputJsonSchema = {
  type: "object",
  properties: {
    orderId: {
      type: "string",
      description: "Unique Choreo order identifier to inspect",
      minLength: 3,
      maxLength: 64
    }
  },
  required: ["orderId"],
  additionalProperties: false
};

const issueRefundSchema: ToolInputJsonSchema = {
  type: "object",
  properties: {
    orderId: {
      type: "string",
      description: "Order identifier for financial refund settlement",
      minLength: 3,
      maxLength: 64
    },
    amountUsd: {
      type: "number",
      description: "Refund amount in USD",
      minimum: 0.01
    }
  },
  required: ["orderId"],
  additionalProperties: false
};

const exportAllUsersSchema: ToolInputJsonSchema = {
  type: "object",
  properties: {
    format: {
      type: "string",
      description: "Export serialization format",
      enum: ["csv", "jsonl"]
    },
    includePii: {
      type: "boolean",
      description: "Whether to include unredacted user PII fields"
    }
  },
  required: [],
  additionalProperties: false
};

export const MCP_TOOL_REGISTRY: Readonly<Record<McpToolName, McpToolDescriptor>> = {
  get_order_status: {
    name: "get_order_status",
    description: "Read-only order fulfillment lookup within delegated agent orders:read scope",
    inputSchema: getOrderStatusSchema,
    requiredScopes: ["orders:read"],
    riskTier: "read",
    requiresHumanApproval: false,
    validateArguments: (raw) =>
      validateAgainstJsonSchema(getOrderStatusSchema, raw, {
        orderId: "ORD-2026-88412"
      }),
    execute: (args) => ({
      orderId:
        typeof args.orderId === "string" && args.orderId.trim().length > 0
          ? args.orderId.trim().slice(0, 64)
          : "ORD-2026-88412",
      fulfillmentState: "SHIPPED",
      carrier: "Choreo Logistics Express",
      estimatedDelivery: "2026-11-26",
      redactedPii: true
    })
  },
  issue_refund: {
    name: "issue_refund",
    description:
      "Privileged financial mutation requiring refunds:execute scope (stripped during default OBO down-scoping)",
    inputSchema: issueRefundSchema,
    requiredScopes: ["refunds:execute"],
    riskTier: "write",
    requiresHumanApproval: false,
    validateArguments: (raw) =>
      validateAgainstJsonSchema(issueRefundSchema, raw, {
        orderId: "ORD-2026-88412",
        amountUsd: 420.0
      }),
    execute: (args) => ({
      orderId:
        typeof args.orderId === "string" && args.orderId.trim().length > 0
          ? args.orderId.trim().slice(0, 64)
          : "ORD-2026-88412",
      refundStatus: "PROCESSED",
      amountUsd: typeof args.amountUsd === "number" ? args.amountUsd : 420.0
    })
  },
  export_all_users: {
    name: "export_all_users",
    description:
      "High-risk bulk tenant PII export requiring interactive CIBA / step-up human approval",
    inputSchema: exportAllUsersSchema,
    requiredScopes: ["users:export"],
    riskTier: "high_risk_pii",
    requiresHumanApproval: true,
    validateArguments: (raw) =>
      validateAgainstJsonSchema(exportAllUsersSchema, raw, {
        format: "csv",
        includePii: true
      }),
    execute: (args) => ({
      exportJobId: "exp_verified_stepup",
      status: "QUEUED",
      format: typeof args.format === "string" ? args.format : "csv"
    })
  }
};

export const MCP_TOOL_LIST: readonly McpToolDescriptor[] = [
  MCP_TOOL_REGISTRY.get_order_status,
  MCP_TOOL_REGISTRY.issue_refund,
  MCP_TOOL_REGISTRY.export_all_users
];

export function isMcpToolName(raw: unknown): raw is McpToolName {
  return (
    raw === "get_order_status" ||
    raw === "issue_refund" ||
    raw === "export_all_users"
  );
}

/**
 * Policy engine evaluating an authenticated delegated agent against the
 * declarative MCP tool registry.
 */
export function evaluateRegisteredMcpToolPolicy(
  user: AuthenticatedUser,
  tool: McpToolName
): McpPolicyDecision {
  const descriptor = MCP_TOOL_REGISTRY[tool];
  const primaryScope = descriptor.requiredScopes[0] ?? "orders:read";

  if (descriptor.requiresHumanApproval) {
    const rawApprovalToken =
      typeof user.rawClaims.human_approval_token === "string"
        ? user.rawClaims.human_approval_token
        : "";
    const hasHumanApproval =
      rawApprovalToken.length > 0 &&
      cibaApprovalStore.verifyAndConsumeApprovalToken(rawApprovalToken, user.sub, tool);
    const hasAllScopes = descriptor.requiredScopes.every((s) => user.scopes.includes(s));
    if (!hasHumanApproval || !hasAllScopes) {
      return {
        allowed: false,
        status: 403,
        error: "human_approval_required",
        message:
          "Human approval required: bulk PII export cannot be executed autonomously by a delegated AI agent without step-up human consent.",
        tool,
        requiredScope: primaryScope,
        defenseTrace: {
          layer: "MCP Human-in-the-Loop Step-Up Guard",
          middleware: "backend/src/mcp/toolRegistry.ts",
          rfc: "RFC 8693 + CIBA / Step-Up Human Consent",
          check: `evaluateRegisteredMcpToolPolicy("${tool}") -> verify(human_approval_token && "${primaryScope}")`,
          outcome: "REJECTED",
          details: `High-risk PII exfiltration tool "${tool}" (riskTier: ${descriptor.riskTier}) requires interactive human step-up approval (missing human_approval_token).`
        }
      };
    }

    return {
      allowed: true,
      tool,
      requiredScope: primaryScope,
      defenseTrace: {
        layer: "MCP Human-in-the-Loop Step-Up Guard",
        middleware: "backend/src/mcp/toolRegistry.ts",
        rfc: "RFC 8693 + Step-Up Consent",
        check: `evaluateRegisteredMcpToolPolicy("${tool}") -> verified step-up token`,
        outcome: "ALLOWED",
        details: "Step-up human approval token verified."
      }
    };
  }

  const missingScopes = descriptor.requiredScopes.filter((s) => !user.scopes.includes(s));
  if (missingScopes.length > 0) {
    const message =
      tool === "issue_refund"
        ? 'Scope escalation blocked: "refunds:execute" was intentionally stripped during RFC 8693 OBO token down-scoping.'
        : `Scope escalation blocked: delegated agent lacks "${primaryScope}" for ${tool}.`;

    return {
      allowed: false,
      status: 403,
      error: "scope_escalation_blocked",
      message,
      tool,
      requiredScope: primaryScope,
      defenseTrace: {
        layer: "MCP Tool Scope-Subset Guard",
        middleware: "backend/src/mcp/toolRegistry.ts",
        rfc:
          tool === "issue_refund"
            ? "RFC 8693 §2.1 (Privilege Attenuation)"
            : "RFC 8693 §2.1 (Down-Scoped Token Exchange)",
        check: `evaluateRegisteredMcpToolPolicy("${tool}") -> scopes.includes("${primaryScope}")`,
        outcome: "REJECTED",
        details:
          tool === "issue_refund"
            ? `Autonomous agent attempted privileged financial mutation "${tool}" without "${primaryScope}". Granted scopes: [${user.scopes.join(", ")}].`
            : `Granted agent scopes [${user.scopes.join(", ")}] do not include "${primaryScope}".`
      }
    };
  }

  return {
    allowed: true,
    tool,
    requiredScope: primaryScope,
    defenseTrace: {
      layer: "MCP Tool Scope-Subset Guard",
      middleware: "backend/src/mcp/toolRegistry.ts",
      rfc: "RFC 8693 §4.1 (act + Down-Scoped Access)",
      check: `evaluateRegisteredMcpToolPolicy("${tool}") -> act.sub + scopes.includes("${primaryScope}")`,
      outcome: "ALLOWED",
      details: `Delegated agent "${user.actor?.sub ?? "unknown"}" authorized on behalf of "${user.sub}" with narrowed scope "${primaryScope}".`
    }
  };
}
