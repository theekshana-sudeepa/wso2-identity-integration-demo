import type { Response } from "express";

export const AUTH_REALM = "choreo-demo";

export type BearerErrorCode = "invalid_request" | "invalid_token" | "insufficient_scope";

export interface BearerChallengeParams {
  readonly error?: BearerErrorCode;
  readonly description?: string;
  readonly scope?: readonly string[];
  readonly resourceMetadataUrl?: string;
}

/**
 * Strips characters outside RFC 6750 Appendix B / HTTP quoted-string safe range
 * (%x20-21 / %x23-5B / %x5D-7E) and caps length at 200 characters.
 */
function sanitizeChallengeValue(raw: string): string {
  let out = "";
  for (let i = 0; i < raw.length; i += 1) {
    const code = raw.charCodeAt(i);
    if (
      (code >= 0x20 && code <= 0x21) ||
      (code >= 0x23 && code <= 0x5b) ||
      (code >= 0x5d && code <= 0x7e)
    ) {
      out += raw[i];
    }
  }
  return out.trim().slice(0, 200);
}

/**
 * Formats an RFC 6750 §3 WWW-Authenticate Bearer challenge header.
 */
export function buildBearerChallenge(params: BearerChallengeParams): string {
  const parts: string[] = [`Bearer realm="${AUTH_REALM}"`];

  if (params.resourceMetadataUrl) {
    const sanitizedMeta = sanitizeChallengeValue(params.resourceMetadataUrl);
    if (sanitizedMeta.length > 0) {
      parts.push(`resource_metadata="${sanitizedMeta}"`);
    }
  }

  if (params.error) {
    parts.push(`error="${params.error}"`);
  }

  if (params.description) {
    const sanitizedDescription = sanitizeChallengeValue(params.description);
    if (sanitizedDescription.length > 0) {
      parts.push(`error_description="${sanitizedDescription}"`);
    }
  }

  if (params.scope && params.scope.length > 0) {
    const sanitizedScope = sanitizeChallengeValue(params.scope.join(" "));
    if (sanitizedScope.length > 0) {
      parts.push(`scope="${sanitizedScope}"`);
    }
  }

  return parts.join(", ");
}

/**
 * Sets the RFC 6750 WWW-Authenticate header and sends the JSON error payload.
 */
export function sendBearerError(
  res: Response,
  status: 401 | 403,
  challenge: BearerChallengeParams | null,
  body: Record<string, unknown>
): void {
  res.setHeader("WWW-Authenticate", buildBearerChallenge(challenge ?? {}));
  res.status(status).json(body);
}
