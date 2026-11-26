import crypto from "node:crypto";
import type { RequestHandler } from "express";
import * as jose from "jose";
import type { DefenseTrace } from "../types/auth.js";
import { sendBearerError } from "./bearerChallenge.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Computes the RFC 7638 canonical JWK SHA-256 thumbprint (`jkt`) for an EC P-256 public key.
 */
export function computeEcJwkThumbprint(jwk: Record<string, unknown>): string | null {
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string"
  ) {
    return null;
  }
  const canonicalJson = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y
  });
  return crypto.createHash("sha256").update(canonicalJson, "utf8").digest("base64url");
}

export function computeAccessTokenHash(accessToken: string): string {
  return crypto.createHash("sha256").update(accessToken, "ascii").digest("base64url");
}

class DpopJtiReplayCache {
  private readonly seen = new Map<string, number>();
  private readonly maxEntries: number;

  constructor(maxEntries = 500) {
    this.maxEntries = maxEntries;
  }

  public checkAndRecord(jti: string, nowSec: number): boolean {
    const existingExp = this.seen.get(jti);
    if (existingExp !== undefined && existingExp >= nowSec) {
      return false;
    }
    if (this.seen.size >= this.maxEntries) {
      const oldestKey = this.seen.keys().next().value;
      if (oldestKey) {
        this.seen.delete(oldestKey);
      }
    }
    this.seen.set(jti, nowSec + 300);
    return true;
  }

  public clear(): void {
    this.seen.clear();
  }
}

export const dpopReplayCache = new DpopJtiReplayCache(500);

export interface DpopVerificationInput {
  readonly dpopProof: string | undefined;
  readonly expectedJkt: string;
  readonly accessToken: string;
  readonly httpMethod: string;
  readonly nowSec?: number;
}

export type DpopVerificationOutcome =
  | { readonly ok: true; readonly jkt: string; readonly jti: string }
  | {
      readonly ok: false;
      readonly error: "invalid_dpop_proof";
      readonly message: string;
      readonly defenseTrace: DefenseTrace;
    };

/**
 * Verifies an RFC 9449 DPoP proof JWT against a sender-constrained token's `cnf.jkt` binding:
 * - Header `typ === "dpop+jwt"`, `alg === "ES256"`, embedded public EC `jwk`
 * - Cryptographic ES256 signature verification
 * - RFC 7638 thumbprint (`jkt`) match against access token `cnf.jkt`
 * - `htm`, `ath` (SHA-256 of access token), `iat` freshness, and `jti` replay protection
 */
export async function verifyDpopProof(
  input: DpopVerificationInput
): Promise<DpopVerificationOutcome> {
  const { dpopProof, expectedJkt, accessToken, httpMethod } = input;
  const nowSec = input.nowSec ?? Math.floor(Date.now() / 1000);

  if (!dpopProof || dpopProof.trim().length === 0) {
    return {
      ok: false,
      error: "invalid_dpop_proof",
      message:
        "Sender-constrained agent token (cnf.jkt) requires an RFC 9449 DPoP proof header, but none was provided (stolen token replay blocked).",
      defenseTrace: {
        layer: "RFC 9449 DPoP Sender-Constrained Proof Guard",
        middleware: "backend/src/middleware/dpopMiddleware.ts -> verifyDpopProof()",
        rfc: "RFC 9449 §4.3 (Checking DPoP Proofs)",
        check: `req.headers.dpop present && thumbprint(dpop.header.jwk) === cnf.jkt ("${expectedJkt}")`,
        outcome: "REJECTED",
        details:
          "Stolen bearer token replay blocked: token is bound to DPoP thumbprint cnf.jkt, and attacker lacks the agent's private ES256 key to sign a DPoP proof."
      }
    };
  }

  let protectedHeader: jose.ProtectedHeaderParameters;
  try {
    protectedHeader = jose.decodeProtectedHeader(dpopProof);
  } catch {
    return {
      ok: false,
      error: "invalid_dpop_proof",
      message: "Malformed DPoP proof JWT header.",
      defenseTrace: {
        layer: "RFC 9449 DPoP Sender-Constrained Proof Guard",
        middleware: "backend/src/middleware/dpopMiddleware.ts",
        rfc: "RFC 9449 §4.2",
        check: "decodeProtectedHeader(dpopProof)",
        outcome: "REJECTED",
        details: "DPoP proof header is not valid Base64URL JSON."
      }
    };
  }

  if (protectedHeader.typ !== "dpop+jwt" || protectedHeader.alg !== "ES256") {
    return {
      ok: false,
      error: "invalid_dpop_proof",
      message: `DPoP proof must use typ="dpop+jwt" and alg="ES256" (received typ="${String(protectedHeader.typ ?? "")}", alg="${String(protectedHeader.alg ?? "")}").`,
      defenseTrace: {
        layer: "RFC 9449 DPoP Sender-Constrained Proof Guard",
        middleware: "backend/src/middleware/dpopMiddleware.ts",
        rfc: "RFC 9449 §4.2",
        check: 'header.typ === "dpop+jwt" && header.alg === "ES256"',
        outcome: "REJECTED",
        details: "DPoP proof header failed typ/alg validation."
      }
    };
  }

  const rawJwk: unknown = protectedHeader.jwk;
  if (
    !isRecord(rawJwk) ||
    typeof rawJwk.d === "string" ||
    rawJwk.kty !== "EC" ||
    rawJwk.crv !== "P-256" ||
    typeof rawJwk.x !== "string" ||
    typeof rawJwk.y !== "string"
  ) {
    return {
      ok: false,
      error: "invalid_dpop_proof",
      message: "DPoP proof header must embed a public EC JWK (without private key material).",
      defenseTrace: {
        layer: "RFC 9449 DPoP Sender-Constrained Proof Guard",
        middleware: "backend/src/middleware/dpopMiddleware.ts",
        rfc: "RFC 9449 §4.2",
        check: "header.jwk is public EC P-256 JWK",
        outcome: "REJECTED",
        details: "DPoP proof lacked a valid public EC JWK."
      }
    };
  }

  const computedJkt = computeEcJwkThumbprint(rawJwk);
  if (!computedJkt || computedJkt !== expectedJkt) {
    return {
      ok: false,
      error: "invalid_dpop_proof",
      message: `DPoP JWK thumbprint mismatch: proof key jkt "${computedJkt ?? "invalid"}" does not match token cnf.jkt "${expectedJkt}".`,
      defenseTrace: {
        layer: "RFC 9449 DPoP Key Binding Guard",
        middleware: "backend/src/middleware/dpopMiddleware.ts -> computeEcJwkThumbprint()",
        rfc: "RFC 9449 §6.1 (JWK Thumbprint Confirmation Method)",
        check: `SHA256_Thumbprint(dpop.jwk) [${computedJkt ?? "invalid"}] === token.cnf.jkt [${expectedJkt}]`,
        outcome: "REJECTED",
        details: `DPoP proof was signed with an unauthorized key whose RFC 7638 thumbprint ("${computedJkt ?? "invalid"}") does not match the token's sender-constrained cnf.jkt ("${expectedJkt}").`
      }
    };
  }

  let payload: jose.JWTPayload;
  try {
    const publicJwk: jose.JWK = {
      kty: "EC",
      crv: "P-256",
      x: rawJwk.x,
      y: rawJwk.y
    };
    const publicKey = await jose.importJWK(publicJwk, "ES256");
    const verified = await jose.jwtVerify(dpopProof, publicKey, {
      algorithms: ["ES256"],
      typ: "dpop+jwt"
    });
    payload = verified.payload;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "ES256 signature verification failed";
    return {
      ok: false,
      error: "invalid_dpop_proof",
      message: `DPoP proof cryptographic verification failed: ${msg}`,
      defenseTrace: {
        layer: "RFC 9449 DPoP Signature Guard",
        middleware: "backend/src/middleware/dpopMiddleware.ts",
        rfc: "RFC 9449 §4.3",
        check: 'jose.jwtVerify(dpopProof, header.jwk, { algorithms: ["ES256"] })',
        outcome: "REJECTED",
        details: msg
      }
    };
  }

  const htm = typeof payload.htm === "string" ? payload.htm.toUpperCase() : "";
  if (htm !== httpMethod.toUpperCase()) {
    return {
      ok: false,
      error: "invalid_dpop_proof",
      message: `DPoP htm claim "${htm}" does not match HTTP method "${httpMethod.toUpperCase()}".`,
      defenseTrace: {
        layer: "RFC 9449 DPoP HTTP Binding Guard",
        middleware: "backend/src/middleware/dpopMiddleware.ts",
        rfc: "RFC 9449 §4.3",
        check: `dpop.htm === "${httpMethod.toUpperCase()}"`,
        outcome: "REJECTED",
        details: `DPoP proof htm "${htm}" did not match request method "${httpMethod.toUpperCase()}".`
      }
    };
  }

  const expectedAth = computeAccessTokenHash(accessToken);
  if (payload.ath !== expectedAth) {
    return {
      ok: false,
      error: "invalid_dpop_proof",
      message: "DPoP ath (access token hash) does not match presented Bearer/DPoP access token.",
      defenseTrace: {
        layer: "RFC 9449 DPoP Access Token Hash Guard",
        middleware: "backend/src/middleware/dpopMiddleware.ts",
        rfc: "RFC 9449 §4.2 (ath Claim)",
        check: "dpop.ath === BASE64URL(SHA256(access_token))",
        outcome: "REJECTED",
        details: "DPoP proof ath digest did not match the SHA-256 hash of the access token."
      }
    };
  }

  if (typeof payload.iat !== "number" || Math.abs(nowSec - payload.iat) > 120) {
    return {
      ok: false,
      error: "invalid_dpop_proof",
      message: "DPoP proof iat timestamp is missing or outside the ±120s freshness window.",
      defenseTrace: {
        layer: "RFC 9449 DPoP Temporal Freshness Guard",
        middleware: "backend/src/middleware/dpopMiddleware.ts",
        rfc: "RFC 9449 §4.3",
        check: "|now - dpop.iat| <= 120s",
        outcome: "REJECTED",
        details: "DPoP proof timestamp is stale or in the future."
      }
    };
  }

  const jti = typeof payload.jti === "string" ? payload.jti.trim() : "";
  if (!jti || !dpopReplayCache.checkAndRecord(jti, nowSec)) {
    return {
      ok: false,
      error: "invalid_dpop_proof",
      message: "DPoP proof jti is missing or has already been consumed (replay detected).",
      defenseTrace: {
        layer: "RFC 9449 DPoP Nonce Replay Guard",
        middleware: "backend/src/middleware/dpopMiddleware.ts -> dpopReplayCache",
        rfc: "RFC 9449 §11.1 (DPoP Proof Replay)",
        check: `dpopReplayCache.checkAndRecord("${jti}")`,
        outcome: "REJECTED",
        details: `DPoP proof jti "${jti || "missing"}" was replayed; rejected via LRU replay cache.`
      }
    };
  }

  return {
    ok: true,
    jkt: computedJkt,
    jti
  };
}

/**
 * Express middleware that enforces RFC 9449 DPoP proof verification whenever an
 * access token carries a `cnf.jkt` confirmation claim (or when a `DPoP` header is sent).
 */
export function enforceSenderConstrainedDpop(resourceMetadataUrl?: string): RequestHandler {
  return async (req, res, next) => {
    const user = req.user;
    if (!user) {
      next();
      return;
    }

    const rawCnf = user.rawClaims.cnf;
    const expectedJkt =
      isRecord(rawCnf) && typeof rawCnf.jkt === "string" && rawCnf.jkt.trim().length > 0
        ? rawCnf.jkt.trim()
        : null;

    if (!expectedJkt) {
      next();
      return;
    }

    const authHeader = req.headers.authorization ?? "";
    const accessToken = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : authHeader.startsWith("DPoP ")
        ? authHeader.slice(5).trim()
        : "";
    const dpopHeader =
      typeof req.headers.dpop === "string" ? req.headers.dpop.trim() : undefined;

    const outcome = await verifyDpopProof({
      dpopProof: dpopHeader,
      expectedJkt,
      accessToken,
      httpMethod: req.method
    });

    if (!outcome.ok) {
      sendBearerError(
        res,
        401,
        {
          error: "invalid_token",
          description: outcome.message,
          resourceMetadataUrl
        },
        {
          error: outcome.error,
          message: outcome.message,
          expectedJkt,
          defenseTrace: outcome.defenseTrace
        }
      );
      return;
    }

    next();
  };
}
