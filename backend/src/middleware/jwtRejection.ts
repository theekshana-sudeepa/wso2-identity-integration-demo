import jwt from "jsonwebtoken";
import jwksRsa from "jwks-rsa";
import { assertNever, type DefenseTrace } from "../types/auth.js";

export type JwtRejectionReason =
  | "invalid_algorithm"
  | "token_expired"
  | "token_not_yet_valid"
  | "invalid_audience"
  | "invalid_issuer"
  | "unknown_signing_key"
  | "jwks_rate_limited"
  | "invalid_signature"
  | "malformed_token";

/**
 * Classifies verification failures from jsonwebtoken and jwks-rsa using typed
 * instanceof checks (subclasses tested before parent JsonWebTokenError).
 */
export function classifyJwtVerifyError(
  err: unknown,
  resolverError: Error | null
): JwtRejectionReason {
  if (resolverError instanceof jwksRsa.SigningKeyNotFoundError) {
    return "unknown_signing_key";
  }
  if (resolverError instanceof jwksRsa.JwksRateLimitError) {
    return "jwks_rate_limited";
  }
  if (resolverError !== null) {
    return "unknown_signing_key";
  }
  if (err instanceof jwt.TokenExpiredError) {
    return "token_expired";
  }
  if (err instanceof jwt.NotBeforeError) {
    return "token_not_yet_valid";
  }
  if (err instanceof jwt.JsonWebTokenError) {
    return "invalid_signature";
  }
  return "malformed_token";
}

/**
 * Builds a structured DefenseTrace entry for a typed JWT rejection reason.
 */
export function buildJwtRejectionTrace(
  reason: JwtRejectionReason,
  details: string
): DefenseTrace {
  switch (reason) {
    case "invalid_algorithm":
      return {
        layer: "JWT Signature & Algorithm Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 8725 §3.1 (Algorithm Pinning)",
        check: 'jwt.verify(token, getSigningKey, { algorithms: ["RS256"] })',
        outcome: "REJECTED",
        details
      };
    case "token_expired":
      return {
        layer: "JWT Temporal Validity Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 7519 §4.1.4 (exp Claim)",
        check: "exp + clockTolerance(5s) >= now",
        outcome: "REJECTED",
        details
      };
    case "token_not_yet_valid":
      return {
        layer: "JWT Temporal Validity Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 7519 §4.1.5 (nbf)",
        check: "nbf - clockTolerance(5s) <= now",
        outcome: "REJECTED",
        details
      };
    case "invalid_audience":
      return {
        layer: "JWT Tenant & Audience Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 7519 §4.1.3 (aud)",
        check: "verify(aud includes expectedAudience)",
        outcome: "REJECTED",
        details
      };
    case "invalid_issuer":
      return {
        layer: "JWT Tenant & Audience Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 7519 §4.1.1 (iss)",
        check: "verify(iss === expectedIssuer)",
        outcome: "REJECTED",
        details
      };
    case "unknown_signing_key":
      return {
        layer: "JWKS Key Resolution Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 7517 §4.5 (JWKS kid Rotation)",
        check: "jwksClient.getSigningKey(header.kid) [LRU cache + 10 req/min limit]",
        outcome: "REJECTED",
        details
      };
    case "jwks_rate_limited":
      return {
        layer: "JWKS Key Resolution Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 7517 · JWKS fetch rate limit",
        check: "jwksClient rate limiter (10 req/min)",
        outcome: "REJECTED",
        details
      };
    case "invalid_signature":
      return {
        layer: "Stateless RS256 Verification Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 7519 · JWS Verification",
        check: 'jwt.verify(token, getSigningKey, { algorithms: ["RS256"] })',
        outcome: "REJECTED",
        details
      };
    case "malformed_token":
      return {
        layer: "Bearer Token Structure Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 7519 §7.2 (JWT structure)",
        check: "3-segment Base64URL JWT with JSON object header & payload",
        outcome: "REJECTED",
        details
      };
    default:
      return assertNever(reason);
  }
}
