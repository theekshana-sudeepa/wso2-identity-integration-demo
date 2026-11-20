import https from "node:https";
import type { RequestHandler } from "express";
import jwt, { type JwtHeader, type SigningKeyCallback } from "jsonwebtoken";
import jwksRsa from "jwks-rsa";
import identityConfig from "../config/identityConfig.js";
import type { VerifiedJwtClaims } from "../types/auth.js";

const requestAgent = identityConfig.allowSelfSignedCerts
  ? new https.Agent({ rejectUnauthorized: false })
  : undefined;

const jwksClient = jwksRsa({
  jwksUri: identityConfig.jwksUri,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: identityConfig.jwksCacheMaxAgeMs,
  rateLimit: true,
  jwksRequestsPerMinute: identityConfig.jwksRequestsPerMinute,
  requestAgent
});

function getSigningKey(header: JwtHeader, callback: SigningKeyCallback): void {
  if (!header.kid) {
    callback(new Error("Missing Key ID (kid) in JWT header"));
    return;
  }

  jwksClient.getSigningKey(header.kid, (err, key) => {
    if (err || !key) {
      callback(err ?? new Error("Unable to resolve signing key from JWKS endpoint"));
      return;
    }

    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

function normalizeClaimList(value: string[] | string | undefined): string[] {
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

export const authenticateToken: RequestHandler = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({
      error: "unauthorized",
      message: "Missing or malformed Authorization header. Expected Bearer token."
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

  jwt.verify(
    token,
    getSigningKey,
    {
      algorithms: ["RS256"],
      issuer: identityConfig.issuer,
      audience: identityConfig.audience,
      clockTolerance: 5
    },
    (err, decoded) => {
      if (err || !decoded || typeof decoded === "string") {
        res.status(401).json({
          error: "invalid_token",
          message: err ? err.message : "Decoded JWT payload is malformed."
        });
        return;
      }

      const claims = decoded as VerifiedJwtClaims;
      const subject = typeof claims.sub === "string" && claims.sub.length > 0 ? claims.sub : "unknown";
      const groups =
        claims.groups !== undefined
          ? normalizeClaimList(claims.groups)
          : normalizeClaimList(claims.roles);
      const scopes =
        typeof claims.scope === "string"
          ? claims.scope.split(" ").map((s) => s.trim()).filter(Boolean)
          : [];

      req.user = {
        sub: subject,
        username: claims.username || claims.preferred_username || subject,
        email: typeof claims.email === "string" ? claims.email : null,
        groups,
        scopes,
        rawClaims: claims
      };

      next();
    }
  );
};
