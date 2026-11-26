import type { JwtPayload } from "jsonwebtoken";

export interface IdentityConfig {
  readonly port: number;
  readonly nodeEnv: string;
  readonly corsOrigins: readonly string[];
  readonly wso2BaseUrl: string;
  readonly issuer: string;
  readonly audience: string;
  readonly mcpAudience: string;
  readonly jwksUri: string;
  readonly allowSelfSignedCerts: boolean;
  readonly jwksCacheMaxAgeMs: number;
  readonly jwksRequestsPerMinute: number;
}

export interface ActorClaim {
  readonly sub: string;
  readonly client_id?: string;
  readonly delegation_protocol?: string;
  readonly act?: ActorClaim;
}

export interface VerifiedJwtClaims extends JwtPayload {
  sub?: string;
  username?: string;
  preferred_username?: string;
  email?: string;
  groups?: string[] | string;
  roles?: string[] | string;
  scope?: string;
  act?: ActorClaim;
  delegation_depth?: number;
  original_scopes?: string[];
  human_approval_token?: string;
}

export interface AuthenticatedUser {
  readonly sub: string;
  readonly username: string;
  readonly email: string | null;
  readonly groups: readonly string[];
  readonly scopes: readonly string[];
  readonly actor: ActorClaim | null;
  readonly actorChain: readonly ActorClaim[];
  readonly actorChainTruncated: boolean;
  readonly issuedAtSec: number | null;
  readonly expiresAtSec: number | null;
  readonly kid: string | null;
  readonly alg: string;
  readonly rawClaims: VerifiedJwtClaims;
}

export interface DefenseTrace {
  readonly layer: string;
  readonly middleware: string;
  readonly rfc: string;
  readonly check: string;
  readonly outcome: "ALLOWED" | "REJECTED";
  readonly details: string;
}

export type McpToolName = "get_order_status" | "issue_refund" | "export_all_users";

export type McpPolicyDecision =
  | {
      readonly allowed: true;
      readonly tool: McpToolName;
      readonly requiredScope: string;
      readonly defenseTrace: DefenseTrace;
    }
  | {
      readonly allowed: false;
      readonly status: 403;
      readonly error: "scope_escalation_blocked" | "human_approval_required";
      readonly message: string;
      readonly tool: McpToolName;
      readonly requiredScope: string;
      readonly defenseTrace: DefenseTrace;
    };

export function assertNever(value: never): never {
  throw new Error(`Unhandled discriminated union member: ${String(value)}`);
}

declare module "express-serve-static-core" {
  interface Request {
    user?: AuthenticatedUser;
  }
}
