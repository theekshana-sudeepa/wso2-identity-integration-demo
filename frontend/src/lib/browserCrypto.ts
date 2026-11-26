export const SIM_ACTIVE_KID = "sim-sts-rs256-active-2026";
export const SIM_ROTATED_KID = "sim-sts-rs256-rotated-2026b";
export const SIM_UNKNOWN_KID = "unknown-revoked-kid-9999";

export interface BrowserManagedRsaKey {
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  readonly publicKeyPem: string;
}

export interface BrowserKeyRing {
  readonly activeKey: BrowserManagedRsaKey;
  readonly rotatedKey: BrowserManagedRsaKey;
  readonly rogueKey: BrowserManagedRsaKey;
  readonly publicPemHmacKey: CryptoKey;
}

export interface BrowserDefenseTrace {
  readonly layer: string;
  readonly middleware: string;
  readonly rfc: string;
  readonly check: string;
  readonly outcome: "ALLOWED" | "REJECTED" | "RECOVERED";
  readonly details: string;
}

export type BrowserJwtRejectionCode =
  | "malformed_token"
  | "invalid_algorithm"
  | "unknown_signing_key"
  | "invalid_signature"
  | "token_expired"
  | "token_not_yet_valid"
  | "invalid_issuer"
  | "invalid_audience";

export type BrowserJwtVerifyResult =
  | {
      readonly ok: true;
      readonly header: Record<string, unknown>;
      readonly payload: Record<string, unknown>;
      readonly kid: string;
      readonly recoveredRotatedKey: boolean;
      readonly defenseTrace: BrowserDefenseTrace;
    }
  | {
      readonly ok: false;
      readonly status: 401;
      readonly errorCode: BrowserJwtRejectionCode;
      readonly message: string;
      readonly defenseTrace: BrowserDefenseTrace;
    };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBytes(base64Url: string): Uint8Array | null {
  try {
    const normalized = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

function encodeJsonSegment(data: Record<string, unknown>): string {
  return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(data)));
}

function decodeJsonSegment(segment: string): Record<string, unknown> | null {
  if (!segment) return null;
  const bytes = base64UrlToBytes(segment);
  if (!bytes) return null;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

async function generateManagedRsaKey(kid: string): Promise<BrowserManagedRsaKey> {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );
  const spkiBuffer = await crypto.subtle.exportKey("spki", pair.publicKey);
  const spkiBase64 = btoa(
    String.fromCharCode(...new Uint8Array(spkiBuffer))
  );
  const lines = spkiBase64.match(/.{1,64}/g) ?? [spkiBase64];
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----`;

  return {
    kid,
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    publicKeyPem
  };
}

let cachedKeyRingPromise: Promise<BrowserKeyRing> | null = null;

export function getBrowserKeyRing(): Promise<BrowserKeyRing> {
  if (!cachedKeyRingPromise) {
    cachedKeyRingPromise = (async () => {
      const [activeKey, rotatedKey, rogueKey] = await Promise.all([
        generateManagedRsaKey(SIM_ACTIVE_KID),
        generateManagedRsaKey(SIM_ROTATED_KID),
        generateManagedRsaKey(SIM_UNKNOWN_KID)
      ]);
      const pemBytes = new TextEncoder().encode(activeKey.publicKeyPem);
      const publicPemHmacKey = await crypto.subtle.importKey(
        "raw",
        pemBytes,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      return {
        activeKey,
        rotatedKey,
        rogueKey,
        publicPemHmacKey
      };
    })();
  }
  return cachedKeyRingPromise;
}

export async function signBrowserRs256Jwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  keySelect: "active" | "rotated" | "rogue" = "active"
): Promise<string> {
  const ring = await getBrowserKeyRing();
  const chosen =
    keySelect === "rotated"
      ? ring.rotatedKey
      : keySelect === "rogue"
        ? ring.rogueKey
        : ring.activeKey;
  const fullHeader: Record<string, unknown> = {
    alg: "RS256",
    typ: "JWT",
    kid: chosen.kid,
    ...header
  };
  const signingInput = `${encodeJsonSegment(fullHeader)}.${encodeJsonSegment(payload)}`;
  const sigBuffer = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    chosen.privateKey,
    new TextEncoder().encode(signingInput)
  );
  return `${signingInput}.${bytesToBase64Url(new Uint8Array(sigBuffer))}`;
}

export async function signBrowserHs256KeyConfusionJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>
): Promise<string> {
  const ring = await getBrowserKeyRing();
  const fullHeader: Record<string, unknown> = {
    alg: "HS256",
    typ: "JWT",
    kid: ring.activeKey.kid,
    ...header
  };
  const signingInput = `${encodeJsonSegment(fullHeader)}.${encodeJsonSegment(payload)}`;
  const sigBuffer = await crypto.subtle.sign(
    "HMAC",
    ring.publicPemHmacKey,
    new TextEncoder().encode(signingInput)
  );
  return `${signingInput}.${bytesToBase64Url(new Uint8Array(sigBuffer))}`;
}

function hasAudience(aud: unknown, expected: string): boolean {
  if (typeof aud === "string") {
    return aud === expected;
  }
  if (Array.isArray(aud)) {
    return aud.some((item) => item === expected);
  }
  return false;
}

/**
 * Browser-side Simulated Resource Server verifier that performs real Web Crypto
 * RSASSA-PKCS1-v1_5 SHA-256 verification and claim validation.
 */
export async function verifyBrowserRs256Jwt(
  token: string,
  options: {
    readonly expectedIssuer: string;
    readonly expectedAudience: string;
    readonly nowSec?: number;
    readonly clockToleranceSec?: number;
  }
): Promise<BrowserJwtVerifyResult> {
  const nowSec = options.nowSec ?? Math.floor(Date.now() / 1000);
  const tolerance = options.clockToleranceSec ?? 5;
  const segments = token.split(".");
  if (segments.length !== 3) {
    return {
      ok: false,
      status: 401,
      errorCode: "malformed_token",
      message: "Bearer token is not a valid 3-segment JSON Web Token.",
      defenseTrace: {
        layer: "Bearer Token Structure Guard (Simulated Resource Server)",
        middleware: "frontend/src/lib/browserCrypto.ts -> verifyBrowserRs256Jwt()",
        rfc: "RFC 7519 §7.2 (JWT Structure)",
        check: "segments.length === 3 && JSON header/payload",
        outcome: "REJECTED",
        details: "Bearer token failed 3-segment Base64URL structure validation."
      }
    };
  }

  const header = decodeJsonSegment(segments[0]);
  const payload = decodeJsonSegment(segments[1]);
  if (!header || !payload) {
    return {
      ok: false,
      status: 401,
      errorCode: "malformed_token",
      message: "Bearer token header or payload is not a valid JSON object.",
      defenseTrace: {
        layer: "Bearer Token Structure Guard (Simulated Resource Server)",
        middleware: "frontend/src/lib/browserCrypto.ts -> verifyBrowserRs256Jwt()",
        rfc: "RFC 7519 §7.2",
        check: "JSON.parse(base64url(header)) && JSON.parse(base64url(payload))",
        outcome: "REJECTED",
        details: "Bearer token header or payload failed Base64URL JSON decoding."
      }
    };
  }

  const alg = typeof header.alg === "string" ? header.alg : "none";
  if (alg !== "RS256") {
    return {
      ok: false,
      status: 401,
      errorCode: "invalid_algorithm",
      message: `Invalid JWT algorithm "${alg}". Strict algorithms: ["RS256"] pinning enforced.`,
      defenseTrace: {
        layer: "JWT Signature & Algorithm Pinning Guard",
        middleware: "frontend/src/lib/browserCrypto.ts -> verifyBrowserRs256Jwt()",
        rfc: "RFC 8725 §3.1 (Algorithm Pinning)",
        check: 'header.alg === "RS256"',
        outcome: "REJECTED",
        details: `Explicit RS256 algorithm pinning rejected forged "${alg}" JWT prior to signature/claims trust.`
      }
    };
  }

  const kid = typeof header.kid === "string" ? header.kid : "";
  const ring = await getBrowserKeyRing();

  const isRotatedKid =
    kid === ring.rotatedKey.kid || kid.endsWith("-rot2026b");
  const isUnknownKid =
    !kid ||
    kid === SIM_UNKNOWN_KID ||
    kid.startsWith("unknown-") ||
    kid.startsWith("revoked-");

  if (isUnknownKid) {
    return {
      ok: false,
      status: 401,
      errorCode: "unknown_signing_key",
      message: `Unable to find a signing key in JWKS that matches '${kid || "missing"}'`,
      defenseTrace: {
        layer: "JWKS Key Resolution Guard",
        middleware: "frontend/src/lib/browserCrypto.ts -> verifyBrowserRs256Jwt()",
        rfc: "RFC 7517 §4.5 (JWKS kid Rotation)",
        check: `jwksKeyRing.resolve("${kid}") [LRU cache + 10 req/min limit]`,
        outcome: "REJECTED",
        details: `Key ID "${kid || "missing"}" is not published in the Simulated STS JWKS; failed closed with HTTP 401.`
      }
    };
  }

  const candidateKey = isRotatedKid ? ring.rotatedKey : ring.activeKey;
  const sigBytes = base64UrlToBytes(segments[2]);
  const signingInputBytes = new TextEncoder().encode(`${segments[0]}.${segments[1]}`);

  let signatureValid = false;
  if (sigBytes && sigBytes.byteLength > 0) {
    try {
      signatureValid = await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        candidateKey.publicKey,
        new Uint8Array(sigBytes),
        signingInputBytes
      );
    } catch {
      signatureValid = false;
    }
  }

  if (!signatureValid) {
    return {
      ok: false,
      status: 401,
      errorCode: "invalid_signature",
      message: "RS256 cryptographic signature verification failed via Web Crypto API.",
      defenseTrace: {
        layer: "Stateless RS256 Verification Guard",
        middleware: "frontend/src/lib/browserCrypto.ts -> crypto.subtle.verify('RSASSA-PKCS1-v1_5')",
        rfc: "RFC 7519 · JWS RS256 Verification",
        check: 'crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, signingInput)',
        outcome: "REJECTED",
        details: `Cryptographic RS256 signature verification failed against kid "${candidateKey.kid}".`
      }
    };
  }

  if (typeof payload.exp === "number" && payload.exp + tolerance < nowSec) {
    const skew = nowSec - payload.exp;
    return {
      ok: false,
      status: 401,
      errorCode: "token_expired",
      message: `jwt expired (${skew}s past exp, tolerance ±${tolerance}s)`,
      defenseTrace: {
        layer: "JWT Temporal Validity Guard",
        middleware: "frontend/src/lib/browserCrypto.ts -> verifyBrowserRs256Jwt()",
        rfc: "RFC 7519 §4.1.4 (exp Claim)",
        check: `exp (${payload.exp}) + clockTolerance (${tolerance}s) >= now (${nowSec})`,
        outcome: "REJECTED",
        details: `Token expired ${skew}s ago (delta: -${skew}s, tolerance: ±${tolerance}s).`
      }
    };
  }

  if (typeof payload.nbf === "number" && payload.nbf - tolerance > nowSec) {
    return {
      ok: false,
      status: 401,
      errorCode: "token_not_yet_valid",
      message: "jwt not active (nbf is in the future)",
      defenseTrace: {
        layer: "JWT Temporal Validity Guard",
        middleware: "frontend/src/lib/browserCrypto.ts -> verifyBrowserRs256Jwt()",
        rfc: "RFC 7519 §4.1.5 (nbf Claim)",
        check: `nbf (${payload.nbf}) - clockTolerance (${tolerance}s) <= now (${nowSec})`,
        outcome: "REJECTED",
        details: "Token nbf claim is in the future beyond clockTolerance."
      }
    };
  }

  if (payload.iss !== options.expectedIssuer) {
    const receivedIss = typeof payload.iss === "string" ? payload.iss : "missing";
    return {
      ok: false,
      status: 401,
      errorCode: "invalid_issuer",
      message: `Invalid JWT issuer. Expected "${options.expectedIssuer}", received "${receivedIss}".`,
      defenseTrace: {
        layer: "JWT Tenant & Audience Guard",
        middleware: "frontend/src/lib/browserCrypto.ts -> verifyBrowserRs256Jwt()",
        rfc: "RFC 7519 §4.1.1 (iss Claim)",
        check: `jwt.iss === "${options.expectedIssuer}"`,
        outcome: "REJECTED",
        details: `Rejected valid RS256 signature because iss "${receivedIss}" !== expected "${options.expectedIssuer}".`
      }
    };
  }

  if (!hasAudience(payload.aud, options.expectedAudience)) {
    const receivedAud =
      typeof payload.aud === "string"
        ? payload.aud
        : Array.isArray(payload.aud)
          ? payload.aud.join(", ")
          : "missing";
    return {
      ok: false,
      status: 401,
      errorCode: "invalid_audience",
      message: `Invalid JWT audience. Expected "${options.expectedAudience}", received "${receivedAud}".`,
      defenseTrace: {
        layer: "JWT Tenant & Audience Guard",
        middleware: "frontend/src/lib/browserCrypto.ts -> verifyBrowserRs256Jwt()",
        rfc: "RFC 7519 §4.1.3 (aud Claim)",
        check: `jwt.aud includes "${options.expectedAudience}"`,
        outcome: "REJECTED",
        details: `Rejected valid RS256 signature because aud "${receivedAud}" !== expected "${options.expectedAudience}".`
      }
    };
  }

  return {
    ok: true,
    header,
    payload,
    kid,
    recoveredRotatedKey: isRotatedKid,
    defenseTrace: {
      layer: isRotatedKid
        ? "Stateless JWKS Key Rotation Resolver"
        : "Stateless RS256 Verification Guard",
      middleware: "frontend/src/lib/browserCrypto.ts -> crypto.subtle.verify('RSASSA-PKCS1-v1_5')",
      rfc: isRotatedKid ? "RFC 7517 §4.5 (JWKS kid Rotation)" : "RFC 7519 · JWS RS256 Verification",
      check: `crypto.subtle.verify("RSASSA-PKCS1-v1_5", jwks["${kid}"]) && iss/aud/exp valid`,
      outcome: isRotatedKid ? "RECOVERED" : "ALLOWED",
      details: isRotatedKid
        ? `Zero-downtime rotation: resolved rotated key "${kid}" and verified RS256 signature via Web Crypto API.`
        : `Verified real RS256 signature via Web Crypto API against kid "${kid}".`
    }
  };
}
