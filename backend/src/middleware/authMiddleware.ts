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
import { devIdpKeyStore } from "../devIdp/keyStore.js";
import type { DefenseTrace, VerifiedJwtClaims } from "../types/auth.js";
import { sendBearerError } from "./bearerChallenge.js";
import { parseActorChain } from "./delegationPolicy.js";
import { buildJwtRejectionTrace, classifyJwtVerifyError } from "./jwtRejection.js";

export interface AuthMiddlewareOptions {
  readonly issuer: string;
  readonly audience: string;
  readonly clockToleranceSec: number;
  readonly keyResolver: GetPublicKeyOrSecret;
  readonly resourceMetadataUrl?: string;
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
    callback(new jwksRsa.SigningKeyNotFoundError("Missing Key ID (kid) in JWT header"));
    return;
  }

  defaultJwksClient.getSigningKey(header.kid, (err, key) => {
    if (!err && key) {
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
      return;
    }

    if (identityConfig.devIdpEnabled) {
      const localPem = devIdpKeyStore.resolvePublicKeyPem(header.kid);
      if (localPem) {
        callback(null, localPem);
        return;
      }
      callback(
        new jwksRsa.SigningKeyNotFoundError(
          `Unable to find a signing key in Dev IdP JWKS that matches '${header.kid}'`
        )
      );
      return;
    }

    callback(
      err ?? new jwksRsa.SigningKeyNotFoundError("Unable to resolve signing key from JWKS endpoint")
    );
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

interface ParsedUnverifiedJwt {
  readonly alg: string | null;
  readonly kid: string | null;
}

function decodeBase64UrlJsonObject(segment: string): Record<string, unknown> | null {
  if (!segment) {
    return null;
  }
  try {
    const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const parsed: unknown = JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function parseUnverifiedJwtStructure(token: string): ParsedUnverifiedJwt | null {
  const segments = token.split(".");
  if (segments.length !== 3) {
    return null;
  }
  const header = decodeBase64UrlJsonObject(segments[0]);
  const payload = decodeBase64UrlJsonObject(segments[1]);
  if (!header || !payload) {
    return null;
  }
  return {
    alg: typeof header.alg === "string" ? header.alg : null,
    kid: typeof header.kid === "string" ? header.kid : null
  };
}

function hasMatchingAudience(aud: unknown, expectedAudience: string): boolean {
  if (typeof aud === "string") {
    return aud === expectedAudience;
  }
  if (Array.isArray(aud)) {
    return aud.some((entry) => entry === expectedAudience);
  }
  return false;
}

function toVerifiedClaims(decoded: JwtPayload): VerifiedJwtClaims {
  const { chain } = parseActorChain(decoded.act);
  const claims: VerifiedJwtClaims = {
    ...decoded,
    sub: typeof decoded.sub === "string" ? decoded.sub : undefined,
    username: typeof decoded.username === "string" ? decoded.username : undefined,
    preferred_username:
      typeof decoded.preferred_username === "string" ? decoded.preferred_username : undefined,
    email: typeof decoded.email === "string" ? decoded.email : undefined,
    scope: typeof decoded.scope === "string" ? decoded.scope : undefined,
    act: chain[0],
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
    keyResolver: overrides?.keyResolver ?? defaultGetSigningKey,
    resourceMetadataUrl: overrides?.resourceMetadataUrl
  };

  const withResourceMeta = (
    params?: {
      readonly error?: "invalid_request" | "invalid_token" | "insufficient_scope";
      readonly description?: string;
    } | null
  ) => {
    if (!options.resourceMetadataUrl) {
      return params ?? null;
    }
    return {
      ...(params ?? {}),
      resourceMetadataUrl: options.resourceMetadataUrl
    };
  };

  return (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      sendBearerError(res, 401, withResourceMeta(null), {
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
      sendBearerError(
        res,
        401,
        withResourceMeta({ error: "invalid_token", description: "Bearer token cannot be empty" }),
        {
          error: "unauthorized",
          message: "Bearer token cannot be empty."
        }
      );
      return;
    }

    const structure = parseUnverifiedJwtStructure(token);
    if (!structure) {
      const msg = "Bearer token is not a valid 3-segment JSON Web Token.";
      sendBearerError(
        res,
        401,
        withResourceMeta({ error: "invalid_token", description: msg }),
        {
          error: "malformed_token",
          message: msg,
          defenseTrace: buildJwtRejectionTrace("malformed_token", msg)
        }
      );
      return;
    }

    if (structure.alg !== "RS256") {
      const msg = `Invalid JWT algorithm "${structure.alg}". Strict algorithms: ["RS256"] pinning enforced.`;
      sendBearerError(
        res,
        401,
        withResourceMeta({ error: "invalid_token", description: msg }),
        {
          error: "invalid_algorithm",
          message: msg,
          defenseTrace: buildJwtRejectionTrace(
            "invalid_algorithm",
            `Algorithm "${structure.alg}" rejected by strict RS256 pinning policy.`
          )
        }
      );
      return;
    }

    let resolverError: Error | null = null;
    const trackingKeyResolver: GetPublicKeyOrSecret = (jwtHeader, callback) => {
      options.keyResolver(jwtHeader, (err, key) => {
        if (err) {
          resolverError = err instanceof Error ? err : new Error(String(err));
          callback(err);
          return;
        }
        callback(null, key);
      });
    };

    jwt.verify(
      token,
      trackingKeyResolver,
      {
        algorithms: ["RS256"],
        clockTolerance: options.clockToleranceSec
      },
      (err, decoded) => {
        if (err || !decoded || typeof decoded === "string" || !isRecord(decoded)) {
          const errorObj = err ?? new Error("Decoded JWT payload is malformed.");
          const reason = classifyJwtVerifyError(err, resolverError);
          sendBearerError(
            res,
            401,
            withResourceMeta({ error: "invalid_token", description: errorObj.message }),
            {
              error: reason,
              message: errorObj.message,
              defenseTrace: buildJwtRejectionTrace(reason, errorObj.message)
            }
          );
          return;
        }

        if (decoded.iss !== options.issuer) {
          const issMsg = `Invalid JWT issuer. Expected "${options.issuer}", received "${typeof decoded.iss === "string" ? decoded.iss : "missing"}".`;
          sendBearerError(
            res,
            401,
            withResourceMeta({ error: "invalid_token", description: issMsg }),
            {
              error: "invalid_issuer",
              message: issMsg,
              defenseTrace: buildJwtRejectionTrace("invalid_issuer", issMsg)
            }
          );
          return;
        }

        if (!hasMatchingAudience(decoded.aud, options.audience)) {
          const audMsg = `Invalid JWT audience. Expected "${options.audience}".`;
          sendBearerError(
            res,
            401,
            withResourceMeta({ error: "invalid_token", description: audMsg }),
            {
              error: "invalid_audience",
              message: audMsg,
              defenseTrace: buildJwtRejectionTrace("invalid_audience", audMsg)
            }
          );
          return;
        }

        const verificationMode = req.headers["x-verification-mode"];
        const tokenJti = typeof decoded.jti === "string" ? decoded.jti : undefined;
        if (
          verificationMode === "introspect" &&
          identityConfig.devIdpEnabled &&
          devIdpKeyStore.isTokenRevoked(token, tokenJti)
        ) {
          const revokeMsg =
            "Token was revoked via RFC 7009 and detected as active=false by RFC 7662 Token Introspection.";
          sendBearerError(
            res,
            401,
            withResourceMeta({ error: "invalid_token", description: revokeMsg }),
            {
              error: "token_revoked",
              message: revokeMsg,
              verificationMode: "introspect",
              defenseTrace: {
                layer: "RFC 7662 Stateful Token Introspection Guard",
                middleware: "backend/src/middleware/authMiddleware.ts -> POST /dev-idp/oauth2/introspect",
                rfc: "RFC 7662 §2.2 (Introspection Response active: false)",
                check: "introspect(token).active === true",
                outcome: "REJECTED",
                details:
                  "Stateful introspection (+1 IdP hop) detected real-time revocation before exp, whereas stateless JWKS verification would continue accepting the token until exp."
              } satisfies DefenseTrace
            }
          );
          return;
        }

        const { chain: actorChain, truncated: actorChainTruncated } = parseActorChain(decoded.act);
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
          actor: actorChain[0] ?? null,
          actorChain,
          actorChainTruncated,
          issuedAtSec: typeof claims.iat === "number" ? claims.iat : null,
          expiresAtSec: typeof claims.exp === "number" ? claims.exp : null,
          kid: structure.kid,
          alg: structure.alg ?? "RS256",
          rawClaims: claims
        };

        next();
      }
    );
  };
}

export const authenticateToken: RequestHandler = createAuthMiddleware();
