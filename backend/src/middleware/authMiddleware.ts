import https from "node:https";
import type { RequestHandler } from "express";
import jwt, {
  type GetPublicKeyOrSecret,
  type JwtHeader,
  type JwtPayload,
  type SigningKeyCallback
} from "jsonwebtoken";
import jwksRsa from "jwks-rsa";
import identityConfig from "../config/identityConfig.js";
import type { ActorClaim, DefenseTrace, VerifiedJwtClaims } from "../types/auth.js";

export interface AuthMiddlewareOptions {
  readonly issuer: string;
  readonly audience: string;
  readonly clockToleranceSec: number;
  readonly keyResolver: GetPublicKeyOrSecret;
}

const requestAgent = identityConfig.allowSelfSignedCerts
  ? new https.Agent({ rejectUnauthorized: false })
  : undefined;

const defaultJwksClient = jwksRsa({
  jwksUri: identityConfig.jwksUri,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: identityConfig.jwksCacheMaxAgeMs,
  rateLimit: true,
  jwksRequestsPerMinute: identityConfig.jwksRequestsPerMinute,
  requestAgent
});

function defaultGetSigningKey(header: JwtHeader, callback: SigningKeyCallback): void {
  if (!header.kid) {
    callback(new Error("Missing Key ID (kid) in JWT header"));
    return;
  }

  defaultJwksClient.getSigningKey(header.kid, (err, key) => {
    if (err || !key) {
      callback(err ?? new Error("Unable to resolve signing key from JWKS endpoint"));
      return;
    }

    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeClaimList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((entry) => String(entry).trim()).filter(Boolean);
  }
  if (typeof value === "string" && value.trim().length > 0) {
    return value
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  return [];
}

function extractActorClaim(rawAct: unknown): ActorClaim | null {
  if (!isRecord(rawAct) || typeof rawAct.sub !== "string" || rawAct.sub.trim().length === 0) {
    return null;
  }
  return {
    sub: rawAct.sub.trim(),
    client_id: typeof rawAct.client_id === "string" ? rawAct.client_id : undefined,
    delegation_protocol:
      typeof rawAct.delegation_protocol === "string" ? rawAct.delegation_protocol : undefined
  };
}

interface ParsedUnverifiedHeader {
  readonly alg: string | null;
  readonly kid: string | null;
}

function parseUnverifiedHeader(token: string): ParsedUnverifiedHeader {
  const firstSegment = token.split(".")[0];
  if (!firstSegment) {
    return { alg: null, kid: null };
  }
  try {
    const normalized = firstSegment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const parsed: unknown = JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
    if (!isRecord(parsed)) {
      return { alg: null, kid: null };
    }
    return {
      alg: typeof parsed.alg === "string" ? parsed.alg : null,
      kid: typeof parsed.kid === "string" ? parsed.kid : null
    };
  } catch {
    return { alg: null, kid: null };
  }
}

function buildJwtRejectionTrace(
  err: Error,
  header: ParsedUnverifiedHeader
): { readonly errorCode: string; readonly defenseTrace: DefenseTrace } {
  const msg = err.message;
  const lower = msg.toLowerCase();

  if (
    (header.alg !== null && header.alg !== "RS256") ||
    lower.includes("invalid algorithm") ||
    lower.includes("signature is required")
  ) {
    return {
      errorCode: "invalid_algorithm",
      defenseTrace: {
        layer: "JWT Signature & Algorithm Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 8725 §3.1 (Algorithm Pinning)",
        check: 'jwt.verify(token, getSigningKey, { algorithms: ["RS256"] })',
        outcome: "REJECTED",
        details: `Algorithm "${header.alg}" rejected by strict RS256 pinning policy.`
      }
    };
  }

  if (err.name === "TokenExpiredError" || lower.includes("jwt expired")) {
    return {
      errorCode: "token_expired",
      defenseTrace: {
        layer: "JWT Temporal Validity Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 7519 §4.1.4 (exp Claim)",
        check: "exp + clockTolerance(5s) >= now",
        outcome: "REJECTED",
        details: msg
      }
    };
  }

  if (lower.includes("audience") || lower.includes("issuer")) {
    return {
      errorCode: "invalid_claims",
      defenseTrace: {
        layer: "JWT Tenant & Audience Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 7519 §4.1.1 & §4.1.3 (iss / aud)",
        check: "verify(iss === expectedIssuer && aud === expectedAudience)",
        outcome: "REJECTED",
        details: msg
      }
    };
  }

  if (lower.includes("kid") || lower.includes("signing key") || lower.includes("jwks")) {
    return {
      errorCode: "unknown_signing_key",
      defenseTrace: {
        layer: "JWKS Key Resolution Guard",
        middleware: "backend/src/middleware/authMiddleware.ts",
        rfc: "RFC 7517 §4.5 (JWKS kid Rotation)",
        check: "jwksClient.getSigningKey(header.kid) [LRU cache + 10 req/min limit]",
        outcome: "REJECTED",
        details: msg
      }
    };
  }

  return {
    errorCode: "invalid_token",
    defenseTrace: {
      layer: "Stateless RS256 Verification Guard",
      middleware: "backend/src/middleware/authMiddleware.ts",
      rfc: "RFC 7519 · JWS Verification",
      check: 'jwt.verify(token, getSigningKey, { algorithms: ["RS256"] })',
      outcome: "REJECTED",
      details: msg
    }
  };
}

function toVerifiedClaims(decoded: JwtPayload): VerifiedJwtClaims {
  const actor = extractActorClaim(decoded.act);
  const claims: VerifiedJwtClaims = {
    ...decoded,
    sub: typeof decoded.sub === "string" ? decoded.sub : undefined,
    username: typeof decoded.username === "string" ? decoded.username : undefined,
    preferred_username:
      typeof decoded.preferred_username === "string" ? decoded.preferred_username : undefined,
    email: typeof decoded.email === "string" ? decoded.email : undefined,
    scope: typeof decoded.scope === "string" ? decoded.scope : undefined,
    act: actor ?? undefined,
    delegation_depth:
      typeof decoded.delegation_depth === "number" ? decoded.delegation_depth : undefined,
    human_approval_token:
      typeof decoded.human_approval_token === "string" ? decoded.human_approval_token : undefined
  };
  return claims;
}

export function createAuthMiddleware(
  overrides?: Partial<AuthMiddlewareOptions>
): RequestHandler {
  const options: AuthMiddlewareOptions = {
    issuer: overrides?.issuer ?? identityConfig.issuer,
    audience: overrides?.audience ?? identityConfig.audience,
    clockToleranceSec: overrides?.clockToleranceSec ?? 5,
    keyResolver: overrides?.keyResolver ?? defaultGetSigningKey
  };

  return (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({
        error: "unauthorized",
        message: "Missing or malformed Authorization header. Expected Bearer token.",
        defenseTrace: {
          layer: "Bearer Token Extraction Guard",
          middleware: "backend/src/middleware/authMiddleware.ts",
          rfc: "RFC 6750 §2.1",
          check: 'req.headers.authorization.startsWith("Bearer ")',
          outcome: "REJECTED",
          details: "Request lacked an Authorization: Bearer <JWT> header."
        } satisfies DefenseTrace
      });
      return;
    }

    const token = authHeader.slice(7).trim();
    if (!token) {
      res.status(401).json({
        error: "unauthorized",
        message: "Bearer token cannot be empty."
      });
      return;
    }

    const header = parseUnverifiedHeader(token);

    if (header.alg !== null && header.alg !== "RS256") {
      const rejection = buildJwtRejectionTrace(
        new Error(`Invalid JWT algorithm "${header.alg}". Only RS256 is permitted.`),
        header
      );
      res.status(401).json({
        error: rejection.errorCode,
        message: `Invalid JWT algorithm "${header.alg}". Strict algorithms: ["RS256"] pinning enforced.`,
        defenseTrace: rejection.defenseTrace
      });
      return;
    }

    jwt.verify(
      token,
      options.keyResolver,
      {
        algorithms: ["RS256"],
        issuer: options.issuer,
        audience: options.audience,
        clockTolerance: options.clockToleranceSec
      },
      (err, decoded) => {
        if (err || !decoded || typeof decoded === "string") {
          const errorObj = err ?? new Error("Decoded JWT payload is malformed.");
          const rejection = buildJwtRejectionTrace(errorObj, header);
          res.status(401).json({
            error: rejection.errorCode,
            message: errorObj.message,
            defenseTrace: rejection.defenseTrace
          });
          return;
        }

        const claims = toVerifiedClaims(decoded);
        const subject =
          typeof claims.sub === "string" && claims.sub.length > 0 ? claims.sub : "unknown";
        const groups =
          claims.groups !== undefined
            ? normalizeClaimList(claims.groups)
            : normalizeClaimList(claims.roles);
        const scopes =
          typeof claims.scope === "string"
            ? claims.scope
                .split(" ")
                .map((s) => s.trim())
                .filter(Boolean)
            : [];

        req.user = {
          sub: subject,
          username: claims.username || claims.preferred_username || subject,
          email: typeof claims.email === "string" ? claims.email : null,
          groups,
          scopes,
          actor: claims.act ?? null,
          issuedAtSec: typeof claims.iat === "number" ? claims.iat : null,
          expiresAtSec: typeof claims.exp === "number" ? claims.exp : null,
          kid: header.kid,
          alg: header.alg ?? "RS256",
          rawClaims: claims
        };

        next();
      }
    );
  };
}

export const authenticateToken: RequestHandler = createAuthMiddleware();
