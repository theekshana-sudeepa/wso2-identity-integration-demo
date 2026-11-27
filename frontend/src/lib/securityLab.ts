import { AGENT_TOKEN_MAX_TTL_SECONDS } from "./agentPolicy";
import {
  SIM_ACTIVE_KID,
  SIM_ROTATED_KID,
  SIM_UNKNOWN_KID,
  signBrowserHs256KeyConfusionJwt,
  signBrowserRs256Jwt
} from "./browserCrypto";
import {
  base64UrlEncodeJson,
  IDP_PRESETS,
  type DelegatedAgentSession,
  type OidcConfig,
  type ParsedJwtClaims,
  type PkceTelemetry
} from "./pkce";

export type FlowMode = "human" | "agent";

export type FlowStageId = "spa" | "pkce" | "idp" | "jwks" | "rbac" | "agent_mcp";

export type FaultId =
  | "none"
  | "pkce_verifier_mismatch"
  | "csrf_state_mismatch"
  | "jwt_alg_downgrade"
  | "jwks_kid_miss"
  | "aud_iss_spoof"
  | "expired_token_skew"
  | "dpop_token_replay"
  | "rfc8707_token_passthrough"
  | "act_chain_violation"
  | "unauthorized_actor_may_act";

export type FaultState =
  | { readonly id: "none" }
  | { readonly id: "pkce_verifier_mismatch" }
  | { readonly id: "csrf_state_mismatch" }
  | { readonly id: "jwt_alg_downgrade"; readonly algorithm: "none" | "HS256" }
  | {
      readonly id: "jwks_kid_miss";
      readonly resolution: "reject_unknown_kid" | "recover_rotated_key";
    }
  | { readonly id: "aud_iss_spoof"; readonly spoofTarget: "aud" | "iss" }
  | { readonly id: "expired_token_skew"; readonly skewSeconds: number }
  | { readonly id: "dpop_token_replay" }
  | { readonly id: "rfc8707_token_passthrough" }
  | {
      readonly id: "act_chain_violation";
      readonly variant: "depth_exceeded" | "cycle_detected";
    }
  | { readonly id: "unauthorized_actor_may_act" };

export interface DefenseTrace {
  readonly layer: string;
  readonly middleware: string;
  readonly rfc: string;
  readonly check: string;
  readonly outcome: "ALLOWED" | "REJECTED" | "RECOVERED";
  readonly details: string;
}

export interface FaultEvaluation {
  readonly faultId: FaultId;
  readonly active: boolean;
  readonly title: string;
  readonly shortLabel: string;
  readonly rfc: string;
  readonly failingStage: FlowStageId | null;
  readonly httpStatus: 200 | 400 | 401 | 403;
  readonly statusBadge: string;
  readonly isBlocked: boolean;
  readonly summary: string;
  readonly wirePayload: Record<string, unknown>;
  readonly mutatedToken: string | null;
  readonly defenseTrace: DefenseTrace;
}

export interface FaultPresetOption {
  readonly id: FaultId;
  readonly label: string;
  readonly rfc: string;
  readonly stageHint: string;
  readonly createDefaultState: () => FaultState;
}

export type McpToolName = "get_order_status" | "issue_refund" | "export_all_users";

export interface McpToolSpec {
  readonly name: McpToolName;
  readonly commandLabel: string;
  readonly requiredScope: string;
  readonly requiresHumanApproval: boolean;
  readonly expectedVerdict: "200 Allowed" | "403 Scope Escalation" | "403 Human Approval";
  readonly description: string;
  readonly sampleArguments: Record<string, unknown>;
}

export const MCP_TOOLS: readonly McpToolSpec[] = [
  {
    name: "get_order_status",
    commandLabel: "tools/call: get_order_status",
    requiredScope: "orders:read",
    requiresHumanApproval: false,
    expectedVerdict: "200 Allowed",
    description: "Read-only order lookup within delegated agent orders:read scope",
    sampleArguments: { orderId: "ORD-2026-88412" }
  },
  {
    name: "issue_refund",
    commandLabel: "tools/call: issue_refund",
    requiredScope: "refunds:execute",
    requiresHumanApproval: false,
    expectedVerdict: "403 Scope Escalation",
    description: "Financial mutation blocked — refunds:execute stripped during OBO exchange",
    sampleArguments: { orderId: "ORD-2026-88412", amountUsd: 420.0 }
  },
  {
    name: "export_all_users",
    commandLabel: "tools/call: export_all_users",
    requiredScope: "users:export",
    requiresHumanApproval: true,
    expectedVerdict: "403 Human Approval",
    description: "Bulk PII export blocked — requires interactive step-up human approval",
    sampleArguments: { format: "csv", includePii: true }
  }
];

export const FAULT_PRESETS: readonly FaultPresetOption[] = [
  {
    id: "none",
    label: "Nominal Baseline",
    rfc: "Zero-Trust OK",
    stageHint: "All Stages",
    createDefaultState: () => ({ id: "none" })
  },
  {
    id: "pkce_verifier_mismatch",
    label: "PKCE Verifier Mismatch",
    rfc: "RFC 7636 §4.6",
    stageHint: "Stage 03 · Token",
    createDefaultState: () => ({ id: "pkce_verifier_mismatch" })
  },
  {
    id: "csrf_state_mismatch",
    label: "CSRF State Replay",
    rfc: "RFC 6749 §10.12",
    stageHint: "Stage 02 · Callback",
    createDefaultState: () => ({ id: "csrf_state_mismatch" })
  },
  {
    id: "jwt_alg_downgrade",
    label: "JWT Alg Downgrade",
    rfc: "RFC 8725 §3.1",
    stageHint: "Stage 04 · RS256",
    createDefaultState: () => ({ id: "jwt_alg_downgrade", algorithm: "none" })
  },
  {
    id: "jwks_kid_miss",
    label: "JWKS kid Rotation Miss",
    rfc: "RFC 7517 §4.5",
    stageHint: "Stage 04 · JWKS",
    createDefaultState: () => ({ id: "jwks_kid_miss", resolution: "reject_unknown_kid" })
  },
  {
    id: "aud_iss_spoof",
    label: "Audience / Issuer Spoof",
    rfc: "RFC 7519 §4.1",
    stageHint: "Stage 04 · Claims",
    createDefaultState: () => ({ id: "aud_iss_spoof", spoofTarget: "aud" })
  },
  {
    id: "expired_token_skew",
    label: "Expired Token / Skew",
    rfc: "RFC 7519 §4.1.4",
    stageHint: "Stage 04 · exp",
    createDefaultState: () => ({ id: "expired_token_skew", skewSeconds: 185 })
  },
  {
    id: "dpop_token_replay",
    label: "Stolen Agent Token Replay (no DPoP key)",
    rfc: "RFC 9449 §4.3",
    stageHint: "Stage 06 · DPoP",
    createDefaultState: () => ({ id: "dpop_token_replay" })
  },
  {
    id: "rfc8707_token_passthrough",
    label: "Token Passthrough to Wrong Resource",
    rfc: "RFC 8707 §2",
    stageHint: "Stage 06 · aud",
    createDefaultState: () => ({ id: "rfc8707_token_passthrough" })
  },
  {
    id: "act_chain_violation",
    label: "Delegation Chain Too Deep / act Cycle",
    rfc: "RFC 8693 §4.1",
    stageHint: "Stage 06 · act",
    createDefaultState: () => ({ id: "act_chain_violation", variant: "depth_exceeded" })
  },
  {
    id: "unauthorized_actor_may_act",
    label: "Unauthorized Actor (may_act violation)",
    rfc: "RFC 8693 §4.4",
    stageHint: "Stage 06 · STS",
    createDefaultState: () => ({ id: "unauthorized_actor_may_act" })
  }
];

export function assertNever(value: never): never {
  throw new Error(`Unhandled discriminated union variant: ${String(value)}`);
}

export interface FaultEvaluationContext {
  readonly config: OidcConfig;
  readonly claims: ParsedJwtClaims | null;
  readonly pkceTelemetry: PkceTelemetry | null;
  readonly nowSec?: number;
}

export function evaluateFaultScenario(
  fault: FaultState,
  context: FaultEvaluationContext
): FaultEvaluation {
  const { config, claims, pkceTelemetry } = context;
  const nowSec = context.nowSec ?? Math.floor(Date.now() / 1000);
  const presetMeta = IDP_PRESETS[config.preset];
  const baseSub = claims?.sub ?? "usr_4b21d90e_dev";
  const baseUsername = claims?.username ?? "developer@acme-identity.example";
  const baseGroups = claims?.groups ?? ["developer"];
  const baseScope = claims?.scopes.join(" ") || "openid profile email groups read:profile";

  switch (fault.id) {
    case "none":
      return {
        faultId: "none",
        active: false,
        title: "Nominal Zero-Trust Baseline",
        shortLabel: "Healthy",
        rfc: "RFC 7636 · RFC 7519 · RFC 8725",
        failingStage: null,
        httpStatus: 200,
        statusBadge: "200 OK",
        isBlocked: false,
        summary:
          "All protocol invariants are intact: S256 PKCE binding, CSRF state nonce, strict RS256 pinning, and JWKS LRU cache.",
        wirePayload: {
          status: "NOMINAL",
          pkceMethod: "S256",
          pinnedAlgorithm: "RS256",
          clockToleranceSec: 5
        },
        mutatedToken: null,
        defenseTrace: {
          layer: "End-to-End CIAM Pipeline",
          middleware: "pkce.ts -> authMiddleware.ts -> rbacMiddleware.ts",
          rfc: "RFC 7636 + RFC 7519 + RFC 8725",
          check: "All cryptographic and authorization invariants satisfied",
          outcome: "ALLOWED",
          details: "No fault injected. Select an attack scenario to inspect failure modes."
        }
      };

    case "pkce_verifier_mismatch": {
      const expectedChallenge =
        pkceTelemetry?.codeChallenge ?? "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
      const originalVerifier =
        pkceTelemetry?.codeVerifier ?? "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      const tamperedVerifier =
        pkceTelemetry?.tamperedCodeVerifier ?? `${originalVerifier.slice(0, -8)}TAMPERED`;
      const computedTamperedChallenge =
        pkceTelemetry?.tamperedCodeChallenge ?? "7xK9pQ2mR5vT8wY1zB4nC7fH0jL3dG6sA9eU2iO5pM8";
      return {
        faultId: "pkce_verifier_mismatch",
        active: true,
        title: "PKCE Verifier Mismatch (Auth Code Interception)",
        shortLabel: "PKCE Mismatch",
        rfc: "RFC 7636 §4.6",
        failingStage: "idp",
        httpStatus: 400,
        statusBadge: "400 invalid_grant",
        isBlocked: true,
        summary:
          "An attacker intercepted the authorization code and sent a forged code_verifier to /oauth2/token. SHA-256 verification fails at the IdP.",
        wirePayload: {
          endpoint: `POST ${config.issuer}`,
          grant_type: "authorization_code",
          code: "authz_code_88c1e904_intercepted",
          stored_code_challenge: expectedChallenge,
          submitted_code_verifier: tamperedVerifier,
          computed_tampered_challenge: computedTamperedChallenge,
          recomputed_digest_match: expectedChallenge === computedTamperedChallenge,
          idp_response: {
            error: "invalid_grant",
            error_description: "PKCE code_verifier does not match stored S256 code_challenge."
          }
        },
        mutatedToken: null,
        defenseTrace: {
          layer: "IdP Token Endpoint PKCE Verification",
          middleware: `${presetMeta.shortLabel} /oauth2/token (RFC 7636 Engine)`,
          rfc: "RFC 7636 §4.6 (Server Verifies code_verifier)",
          check: `BASE64URL(SHA256(submitted_verifier)) [${computedTamperedChallenge}] === stored_code_challenge [${expectedChallenge}]`,
          outcome: "REJECTED",
          details: `SHA-256 digest mismatch: stored challenge "${expectedChallenge}" !== computed tampered digest "${computedTamperedChallenge}".`
        }
      };
    }

    case "csrf_state_mismatch": {
      const expectedState = pkceTelemetry?.state ?? "st_90a4f1b2c8e7d6a5";
      const attackerState = "st_FORGED_REPLAY_ATTACKER_771";
      return {
        faultId: "csrf_state_mismatch",
        active: true,
        title: "CSRF state Parameter Replay / Mismatch",
        shortLabel: "CSRF Replay",
        rfc: "RFC 6749 §10.12",
        failingStage: "pkce",
        httpStatus: 403,
        statusBadge: "403 Blocked",
        isBlocked: true,
        summary:
          "Callback received an unexpected or replayed OAuth state nonce. Browser SPA aborts immediately before issuing any /oauth2/token request.",
        wirePayload: {
          callbackUrl: `${config.redirectUri}?code=attacker_session_code&state=${attackerState}`,
          expectedSessionStorageState: expectedState,
          returnedCallbackState: attackerState,
          constantTimeMatch: false,
          tokenExchangeAborted: true
        },
        mutatedToken: null,
        defenseTrace: {
          layer: "SPA Callback CSRF Nonce Guard",
          middleware: "frontend/src/lib/pkce.ts -> handleOidcCallback()",
          rfc: "RFC 6749 §10.12 (Cross-Site Request Forgery)",
          check: "returnedState !== null && returnedState === sessionStorage.getItem('wso2_oidc_state')",
          outcome: "REJECTED",
          details:
            "Blocked login-CSRF / session fixation before authorization code redemption; nonce invalidated."
        }
      };
    }

    case "jwt_alg_downgrade": {
      const alg = fault.algorithm;
      const forgedHeader: Record<string, unknown> =
        alg === "none"
          ? { alg: "none", typ: "JWT" }
          : { alg: "HS256", typ: "JWT", kid: presetMeta.demoKid };
      const forgedPayload: Record<string, unknown> = {
        sub: baseSub,
        username: "attacker-escalated@acme.example",
        iss: config.issuer,
        aud: config.audience,
        groups: ["admin", "superadmin"],
        scope: "openid admin:audit write:reports",
        iat: nowSec,
        exp: nowSec + 3600
      };
      const forgedSig =
        alg === "none" ? "" : "forged_hmac_signed_with_public_rsa_pem_key_confusion";
      const mutatedToken = `${base64UrlEncodeJson(forgedHeader)}.${base64UrlEncodeJson(forgedPayload)}.${forgedSig}`;

      return {
        faultId: "jwt_alg_downgrade",
        active: true,
        title: `JWT Algorithm Downgrade (alg: "${alg}")`,
        shortLabel: `alg:${alg}`,
        rfc: "RFC 8725 §3.1",
        failingStage: "jwks",
        httpStatus: 401,
        statusBadge: "401 Unauthorized",
        isBlocked: true,
        summary:
          alg === "none"
            ? 'Forged unsigned JWT with header alg: "none" attempting to bypass signature verification and escalate to admin.'
            : 'Key-confusion attack switching header alg from RS256 to symmetric HS256 signed using the public RSA key.',
        wirePayload: {
          injectedHeader: forgedHeader,
          injectedEscalationClaims: {
            groups: ["admin", "superadmin"],
            scope: "openid admin:audit write:reports"
          },
          backendPinnedAlgorithms: ["RS256"],
          signatureSegmentPresent: forgedSig.length > 0,
          httpResponse: {
            status: 401,
            error: "invalid_algorithm"
          }
        },
        mutatedToken,
        defenseTrace: {
          layer: "JWT Signature & Algorithm Pinning Guard",
          middleware: "backend/src/middleware/authMiddleware.ts -> createAuthMiddleware()",
          rfc: "RFC 8725 §3.1 (Use Explicit Algorithm Allow-List)",
          check: 'header.alg === "RS256" && jwt.verify(token, getSigningKey, { algorithms: ["RS256"] })',
          outcome: "REJECTED",
          details: `Explicit RS256 algorithm pinning rejected forged "${alg}" JWT prior to claims trust.`
        }
      };
    }

    case "jwks_kid_miss": {
      const recovered = fault.resolution === "recover_rotated_key";
      const rotatedKid = recovered
        ? `${presetMeta.demoKid}-rot2026b`
        : "unknown-revoked-kid-9999";
      const header: Record<string, unknown> = {
        alg: "RS256",
        typ: "JWT",
        kid: rotatedKid
      };
      const payload: Record<string, unknown> = {
        sub: baseSub,
        username: baseUsername,
        iss: config.issuer,
        aud: config.audience,
        groups: [...baseGroups],
        scope: baseScope,
        iat: nowSec,
        exp: nowSec + 3600
      };
      const mutatedToken = `${base64UrlEncodeJson(header)}.${base64UrlEncodeJson(payload)}.rotated_key_rs256_sig`;

      return {
        faultId: "jwks_kid_miss",
        active: true,
        title: recovered
          ? "JWKS kid Key Rotation Miss -> Clean Recovery"
          : "JWKS kid Key Rotation Miss -> Unknown kid (401)",
        shortLabel: recovered ? "kid Recovered" : "kid Miss 401",
        rfc: "RFC 7517 §4.5",
        failingStage: "jwks",
        httpStatus: recovered ? 200 : 401,
        statusBadge: recovered ? "200 Recovered" : "401 Unauthorized",
        isBlocked: !recovered,
        summary: recovered
          ? "Incoming JWT carries a newly rotated kid not yet in the 10-min LRU cache. Backend performs a rate-limited JWKS refetch (10 req/min), caches the new public key, and verifies cleanly."
          : "Incoming JWT carries an unknown/revoked kid. After a rate-limited JWKS cache-miss refetch, no matching public key exists in the tenant key set -> fail-closed 401.",
        wirePayload: {
          jwtHeaderKid: rotatedKid,
          lruCacheLookup: "MISS (cached kids: [" + presetMeta.demoKid + "])",
          rateLimitGuard: "ALLOWED (1/10 req/min budget)",
          jwksRefetchUri: config.jwksUri,
          refetchedKeysCount: 2,
          matchedPublicKey: recovered ? rotatedKid : null,
          outcome: recovered ? "CACHE_UPDATED_AND_VERIFIED" : "FAIL_CLOSED_401"
        },
        mutatedToken,
        defenseTrace: {
          layer: "Stateless JWKS Key Rotation Resolver",
          middleware: "backend/src/middleware/authMiddleware.ts -> jwksRsa({ cache: true, rateLimit: true })",
          rfc: "RFC 7517 §4.5 (JWK Set kid Resolution)",
          check: `jwksClient.getSigningKey("${rotatedKid}") [maxEntries: 5, rateLimit: 10 rpm]`,
          outcome: recovered ? "RECOVERED" : "REJECTED",
          details: recovered
            ? `Zero-downtime rotation: fetched "${rotatedKid}" from ${config.jwksUri} and verified RS256 signature.`
            : `Key ID "${rotatedKid}" not published at ${config.jwksUri}; failed closed with HTTP 401 while rate-limiting prevents JWKS DoS.`
        }
      };
    }

    case "aud_iss_spoof": {
      const isAud = fault.spoofTarget === "aud";
      const spoofedAud = isAud ? "wrong-tenant-billing-api" : config.audience;
      const spoofedIss = isAud ? config.issuer : "https://evil-idp.attacker.example/oauth2/token";
      const header: Record<string, unknown> = {
        alg: "RS256",
        typ: "JWT",
        kid: presetMeta.demoKid
      };
      const payload: Record<string, unknown> = {
        sub: baseSub,
        username: baseUsername,
        iss: spoofedIss,
        aud: spoofedAud,
        groups: [...baseGroups],
        scope: baseScope,
        iat: nowSec,
        exp: nowSec + 3600
      };
      const mutatedToken = `${base64UrlEncodeJson(header)}.${base64UrlEncodeJson(payload)}.valid_sig_wrong_tenant_claim`;

      return {
        faultId: "aud_iss_spoof",
        active: true,
        title: isAud ? "Audience (aud) Confusion / Token Replay" : "Issuer (iss) Cross-Tenant Spoof",
        shortLabel: isAud ? "aud Spoof" : "iss Spoof",
        rfc: "RFC 7519 §4.1.1 & §4.1.3",
        failingStage: "jwks",
        httpStatus: 401,
        statusBadge: "401 Unauthorized",
        isBlocked: true,
        summary: isAud
          ? "Token has a valid RS256 signature from the IdP, but was minted for a different downstream API audience. Strict aud pinning prevents cross-API replay."
          : "Token claims an untrusted issuer domain from another tenant/IdP. Strict iss comparison rejects cross-tenant token substitution.",
        wirePayload: {
          expectedIssuer: config.issuer,
          receivedIssuer: spoofedIss,
          expectedAudience: config.audience,
          receivedAudience: spoofedAud,
          signatureValid: true,
          claimValidationPassed: false
        },
        mutatedToken,
        defenseTrace: {
          layer: "JWT Tenant & Audience Claim Guard",
          middleware: "backend/src/middleware/authMiddleware.ts -> jwt.verify({ issuer, audience })",
          rfc: isAud ? "RFC 7519 §4.1.3 (aud Claim)" : "RFC 7519 §4.1.1 (iss Claim)",
          check: isAud
            ? `jwt.aud === "${config.audience}"`
            : `jwt.iss === "${config.issuer}"`,
          outcome: "REJECTED",
          details: isAud
            ? `Rejected valid signature because aud "${spoofedAud}" !== expected "${config.audience}".`
            : `Rejected token because iss "${spoofedIss}" !== expected "${config.issuer}".`
        }
      };
    }

    case "expired_token_skew": {
      const skew = Math.max(10, fault.skewSeconds);
      const expSec = nowSec - skew;
      const iatSec = expSec - 3600;
      const header: Record<string, unknown> = {
        alg: "RS256",
        typ: "JWT",
        kid: presetMeta.demoKid
      };
      const payload: Record<string, unknown> = {
        sub: baseSub,
        username: baseUsername,
        iss: config.issuer,
        aud: config.audience,
        groups: [...baseGroups],
        scope: baseScope,
        iat: iatSec,
        exp: expSec
      };
      const mutatedToken = `${base64UrlEncodeJson(header)}.${base64UrlEncodeJson(payload)}.expired_rs256_token_sig`;

      return {
        faultId: "expired_token_skew",
        active: true,
        title: `Expired Token (exp) / Clock Skew (-${skew}s)`,
        shortLabel: `exp -${skew}s`,
        rfc: "RFC 7519 §4.1.4",
        failingStage: "jwks",
        httpStatus: 401,
        statusBadge: "401 Unauthorized",
        isBlocked: true,
        summary: `Token expired ${skew} seconds ago, exceeding the backend's ±5s clockTolerance window. Stateless middleware rejects immediately.`,
        wirePayload: {
          serverNowEpochSec: nowSec,
          tokenExpEpochSec: expSec,
          deltaSeconds: -skew,
          clockToleranceSeconds: 5,
          exceededBySeconds: skew - 5,
          expiredAtIso: new Date(expSec * 1000).toISOString()
        },
        mutatedToken,
        defenseTrace: {
          layer: "JWT Temporal Validity Guard",
          middleware: "backend/src/middleware/authMiddleware.ts -> jwt.verify({ clockTolerance: 5 })",
          rfc: "RFC 7519 §4.1.4 (Expiration Time Claim)",
          check: `exp (${expSec}) + clockTolerance (5) >= now (${nowSec})`,
          outcome: "REJECTED",
          details: `Token expired ${skew}s ago (delta: -${skew}s, tolerance: ±5s).`
        }
      };
    }

    case "dpop_token_replay": {
      const header: Record<string, unknown> = {
        alg: "RS256",
        typ: "at+jwt",
        kid: presetMeta.demoKid
      };
      const payload: Record<string, unknown> = {
        sub: baseSub,
        username: baseUsername,
        iss: config.issuer,
        aud: config.mcpAudience,
        act: {
          sub: "agent:choreo-integrator-bot",
          client_id: "choreo-mcp-agent-v1"
        },
        cnf: {
          jkt: "dpop_bound_jkt_expected_2026"
        },
        scope: "orders:read",
        iat: nowSec,
        exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
      };
      const mutatedToken = `${base64UrlEncodeJson(header)}.${base64UrlEncodeJson(payload)}.dpop_bound_obo_sig`;
      return {
        faultId: "dpop_token_replay",
        active: true,
        title: "Stolen Agent Token Replay (Missing RFC 9449 DPoP Proof)",
        shortLabel: "DPoP Replay 401",
        rfc: "RFC 9449 §4.3",
        failingStage: "agent_mcp",
        httpStatus: 401,
        statusBadge: "401 invalid_dpop_proof",
        isBlocked: true,
        summary:
          "Attacker exfiltrated a sender-constrained agent OBO token (bound to cnf.jkt) and replayed it without the agent's non-exportable ES256 private key.",
        wirePayload: {
          tokenConfirmationClaim: { cnf: { jkt: "dpop_bound_jkt_expected_2026" } },
          dpopProofHeaderSent: null,
          expectedDpopAlg: "ES256 (P-256)",
          httpResponse: {
            status: 401,
            error: "invalid_dpop_proof"
          }
        },
        mutatedToken,
        defenseTrace: {
          layer: "RFC 9449 DPoP Sender-Constrained Proof Guard",
          middleware: "backend/src/middleware/dpopMiddleware.ts -> verifyDpopProof()",
          rfc: "RFC 9449 §4.3 & §6.1 (cnf.jkt Proof-of-Possession)",
          check: 'req.headers.dpop present && thumbprint(dpop.jwk) === token.cnf.jkt',
          outcome: "REJECTED",
          details:
            "Stolen bearer token replay blocked: token carries cnf.jkt sender constraint, and attacker cannot forge an ES256 DPoP proof."
        }
      };
    }

    case "rfc8707_token_passthrough": {
      const header: Record<string, unknown> = {
        alg: "RS256",
        typ: "JWT",
        kid: presetMeta.demoKid
      };
      const payload: Record<string, unknown> = {
        sub: baseSub,
        username: baseUsername,
        iss: config.issuer,
        aud: config.audience,
        act: {
          sub: "agent:choreo-integrator-bot",
          client_id: "choreo-mcp-agent-v1"
        },
        scope: "orders:read",
        iat: nowSec,
        exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
      };
      const mutatedToken = `${base64UrlEncodeJson(header)}.${base64UrlEncodeJson(payload)}.passthrough_wrong_aud_sig`;
      return {
        faultId: "rfc8707_token_passthrough",
        active: true,
        title: "Token Passthrough to Wrong Resource (RFC 8707 Violation)",
        shortLabel: "Passthrough 401",
        rfc: "RFC 8707 §2",
        failingStage: "agent_mcp",
        httpStatus: 401,
        statusBadge: "401 invalid_audience",
        isBlocked: true,
        summary:
          "Client or upstream service passed a human-API-audience token directly to the MCP Gateway instead of performing an RFC 8693 + RFC 8707 resource-scoped exchange.",
        wirePayload: {
          presentedTokenAudience: config.audience,
          requiredMcpGatewayResourceUri: config.mcpAudience,
          tokenPassthroughPrevented: true,
          httpResponse: {
            status: 401,
            error: "invalid_audience"
          }
        },
        mutatedToken,
        defenseTrace: {
          layer: "MCP Gateway Canonical Resource Audience Guard",
          middleware: "backend/src/routes/mcpRoutes.ts -> createAuthMiddleware({ audience: MCP_AUDIENCE })",
          rfc: "RFC 8707 §2 + MCP Auth Spec (No Token Passthrough)",
          check: `jwt.aud ("${config.audience}") === mcpCanonicalUri ("${config.mcpAudience}")`,
          outcome: "REJECTED",
          details: `Rejected token passthrough: token was minted for "${config.audience}", not the MCP Gateway resource "${config.mcpAudience}".`
        }
      };
    }

    case "act_chain_violation": {
      const isCycle = fault.variant === "cycle_detected";
      const badAct = isCycle
        ? {
            sub: "agent:a",
            client_id: "choreo-mcp-agent-v1",
            act: { sub: "agent:a", client_id: "choreo-mcp-agent-v1" }
          }
        : {
            sub: "agent:leaf",
            act: {
              sub: "agent:mid",
              act: { sub: "agent:root" }
            }
          };
      const header: Record<string, unknown> = {
        alg: "RS256",
        typ: "at+jwt",
        kid: presetMeta.demoKid
      };
      const payload: Record<string, unknown> = {
        sub: baseSub,
        username: baseUsername,
        iss: config.issuer,
        aud: config.mcpAudience,
        act: badAct,
        scope: "orders:read",
        iat: nowSec,
        exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
      };
      const mutatedToken = `${base64UrlEncodeJson(header)}.${base64UrlEncodeJson(payload)}.act_chain_violation_sig`;
      return {
        faultId: "act_chain_violation",
        active: true,
        title: isCycle
          ? "Delegation Actor Cycle Detected (agent:a -> agent:a)"
          : "Delegation Chain Depth Exceeded (Depth 3 > Max 2)",
        shortLabel: isCycle ? "act Cycle 403" : "act Depth 403",
        rfc: "RFC 8693 §4.1",
        failingStage: "agent_mcp",
        httpStatus: 403,
        statusBadge: isCycle ? "403 cycle_detected" : "403 chain_too_deep",
        isBlocked: true,
        summary: isCycle
          ? "Nested act claim contains a circular delegation hop where an actor delegates back to itself."
          : "Multi-agent orchestration exceeded MAX_DELEGATION_DEPTH (2 hops), blocking unbounded sub-agent chaining.",
        wirePayload: {
          maxDelegationDepth: 2,
          injectedActChain: badAct,
          httpResponse: {
            status: 403,
            error: isCycle ? "delegation_cycle_detected" : "delegation_chain_too_deep"
          }
        },
        mutatedToken,
        defenseTrace: {
          layer: "RFC 8693 Delegation Chain Guard",
          middleware: "backend/src/middleware/delegationPolicy.ts -> evaluateActChain()",
          rfc: "RFC 8693 §4.1 (Nested act Claim)",
          check: isCycle ? "evaluateActChain(acyclic actor chain)" : "evaluateActChain(depth <= 2)",
          outcome: "REJECTED",
          details: isCycle
            ? 'Delegation cycle detected involving actor "agent:a".'
            : "Delegation chain depth (3) exceeds maximum allowed depth (2)."
        }
      };
    }

    case "unauthorized_actor_may_act": {
      return {
        faultId: "unauthorized_actor_may_act",
        active: true,
        title: "Unauthorized Actor (RFC 8693 §4.4 may_act Violation)",
        shortLabel: "may_act 400",
        rfc: "RFC 8693 §4.4",
        failingStage: "idp",
        httpStatus: 400,
        statusBadge: "400 unauthorized_client",
        isBlocked: true,
        summary:
          "An unapproved third-party AI agent attempted an OBO token exchange using the human's subject_token, but is not listed in the token's may_act policy claim.",
        wirePayload: {
          endpoint: `POST ${config.backendApiUrl}/dev-idp/oauth2/token`,
          grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
          subjectTokenMayAct: { sub: "agent:choreo-integrator-bot" },
          requestingActorToken: "agent:unlisted-rogue-bot",
          stsResponse: {
            status: 400,
            error: "unauthorized_client"
          }
        },
        mutatedToken: null,
        defenseTrace: {
          layer: "STS RFC 8693 §4.4 may_act Guard",
          middleware: "backend/src/devIdp/devIdpRouter.ts -> evaluateMayAct()",
          rfc: "RFC 8693 §4.4 (may_act Authorized Actor Claim)",
          check: 'verify(subject_token.may_act allows "agent:unlisted-rogue-bot")',
          outcome: "REJECTED",
          details:
            'Actor "agent:unlisted-rogue-bot" is not authorized by subject_token may_act claim (actor_not_listed).'
        }
      };
    }

    default:
      return assertNever(fault);
  }
}

/**
 * Mints a cryptographically real forged JWT in the browser using Web Crypto API
 * (`RSASSA-PKCS1-v1_5` active/rotated/rogue keys or `HMAC-SHA256` with the exported public PEM).
 */
export async function mintSimulatedFaultToken(
  fault: FaultState,
  context: FaultEvaluationContext & { readonly targetAudience?: string }
): Promise<string | null> {
  const { config, claims } = context;
  const nowSec = context.nowSec ?? Math.floor(Date.now() / 1000);
  const targetAudience = context.targetAudience ?? config.audience;
  const baseSub = claims?.sub ?? "usr_4b21d90e_dev";
  const baseUsername = claims?.username ?? "developer@acme-identity.example";
  const baseGroups = claims?.groups ?? ["developer"];
  const baseScope = claims?.scopes.join(" ") || "openid profile email groups read:profile orders:read";

  const basePayload: Record<string, unknown> = {
    sub: baseSub,
    username: baseUsername,
    iss: config.issuer,
    aud: targetAudience,
    groups: [...baseGroups],
    scope: baseScope,
    iat: nowSec,
    exp: nowSec + 3600
  };

  switch (fault.id) {
    case "none":
    case "pkce_verifier_mismatch":
    case "csrf_state_mismatch":
      return null;

    case "jwt_alg_downgrade": {
      const escalatedPayload: Record<string, unknown> = {
        ...basePayload,
        username: "attacker-escalated@acme.example",
        groups: ["admin", "superadmin"],
        scope: "openid admin:audit write:reports orders:read"
      };
      if (fault.algorithm === "none") {
        return `${base64UrlEncodeJson({ alg: "none", typ: "JWT" })}.${base64UrlEncodeJson(escalatedPayload)}.`;
      }
      return signBrowserHs256KeyConfusionJwt(
        { alg: "HS256", typ: "JWT", kid: SIM_ACTIVE_KID },
        escalatedPayload
      );
    }

    case "jwks_kid_miss": {
      const recovered = fault.resolution === "recover_rotated_key";
      return signBrowserRs256Jwt(
        {
          alg: "RS256",
          typ: "JWT",
          kid: recovered ? SIM_ROTATED_KID : SIM_UNKNOWN_KID
        },
        basePayload,
        recovered ? "rotated" : "rogue"
      );
    }

    case "aud_iss_spoof": {
      const isAud = fault.spoofTarget === "aud";
      return signBrowserRs256Jwt(
        { alg: "RS256", typ: "JWT", kid: SIM_ACTIVE_KID },
        {
          ...basePayload,
          iss: isAud ? config.issuer : "https://evil-idp.attacker.example/oauth2/token",
          aud: isAud ? "wrong-tenant-billing-api" : targetAudience
        },
        "active"
      );
    }

    case "expired_token_skew": {
      const skew = Math.max(10, fault.skewSeconds);
      const expSec = nowSec - skew;
      return signBrowserRs256Jwt(
        { alg: "RS256", typ: "JWT", kid: SIM_ACTIVE_KID },
        {
          ...basePayload,
          iat: expSec - 3600,
          exp: expSec
        },
        "active"
      );
    }

    case "dpop_token_replay": {
      return signBrowserRs256Jwt(
        { alg: "RS256", typ: "at+jwt", kid: SIM_ACTIVE_KID },
        {
          ...basePayload,
          aud: config.mcpAudience,
          act: {
            sub: "agent:choreo-integrator-bot",
            client_id: "choreo-mcp-agent-v1"
          },
          cnf: {
            jkt: "dpop_bound_jkt_expected_2026"
          },
          scope: "orders:read",
          iat: nowSec,
          exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
        },
        "active"
      );
    }

    case "rfc8707_token_passthrough": {
      return signBrowserRs256Jwt(
        { alg: "RS256", typ: "JWT", kid: SIM_ACTIVE_KID },
        {
          ...basePayload,
          aud: config.audience,
          act: {
            sub: "agent:choreo-integrator-bot",
            client_id: "choreo-mcp-agent-v1"
          },
          scope: "orders:read",
          iat: nowSec,
          exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
        },
        "active"
      );
    }

    case "act_chain_violation": {
      const isCycle = fault.variant === "cycle_detected";
      return signBrowserRs256Jwt(
        { alg: "RS256", typ: "at+jwt", kid: SIM_ACTIVE_KID },
        {
          ...basePayload,
          aud: config.mcpAudience,
          act: isCycle
            ? {
                sub: "agent:a",
                act: { sub: "agent:a" }
              }
            : {
                sub: "agent:leaf",
                act: { sub: "agent:mid", act: { sub: "agent:root" } }
              },
          scope: "orders:read",
          iat: nowSec,
          exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
        },
        "active"
      );
    }

    case "unauthorized_actor_may_act":
      return null;

    default:
      return assertNever(fault);
  }
}

export interface CodeExporterInput {
  readonly config: OidcConfig;
  readonly flowMode: FlowMode;
  readonly selectedStage: FlowStageId;
  readonly activeToken: string | null;
  readonly faultEval: FaultEvaluation;
  readonly delegatedSession: DelegatedAgentSession | null;
  readonly redactToken: boolean;
}

export interface GeneratedCodeSnippets {
  readonly curl: string;
  readonly typescript: string;
  readonly oidcConfigJson: string;
  readonly synapseXml: string;
  readonly ballerinaBal: string;
  readonly targetEndpoint: string;
}

export function generateCodeSnippets(input: CodeExporterInput): GeneratedCodeSnippets {
  const {
    config,
    flowMode,
    selectedStage,
    activeToken,
    faultEval,
    delegatedSession,
    redactToken
  } = input;

  const effectiveToken =
    faultEval.mutatedToken ??
    (flowMode === "agent" && delegatedSession ? delegatedSession.accessToken : activeToken) ??
    "<RS256_ACCESS_TOKEN>";

  const displayToken =
    redactToken && effectiveToken !== "<RS256_ACCESS_TOKEN>"
      ? `${effectiveToken.slice(0, 18)}...[REDACTED_${effectiveToken.length}_CHARS]...${effectiveToken.slice(-10)}`
      : effectiveToken;

  const isMcpTarget = flowMode === "agent" || selectedStage === "agent_mcp";
  const targetEndpoint = isMcpTarget
    ? `${config.backendApiUrl}/api/mcp`
    : selectedStage === "rbac"
      ? `${config.backendApiUrl}/api/v1/admin/audit-logs`
      : `${config.backendApiUrl}/api/v1/user/profile`;

  const method = isMcpTarget ? "POST" : "GET";
  const mcpRpcPayload = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "get_order_status",
      arguments: { orderId: "ORD-2026-88412" }
    }
  };
  const mcpBody = JSON.stringify(mcpRpcPayload, null, 2);

  const curl = isMcpTarget
    ? [
        `# Choreo Labs · RFC 8693 OBO Delegated AI Agent -> MCP JSON-RPC 2.0 Call`,
        `# Active Fault: ${faultEval.title}`,
        `curl -i -X POST "${targetEndpoint}" \\`,
        `  -H "Accept: application/json" \\`,
        `  -H "Content-Type: application/json" \\`,
        `  -H "Authorization: Bearer ${displayToken}" \\`,
        `  -d '${JSON.stringify(mcpRpcPayload)}'`
      ].join("\n")
    : [
        `# Choreo Labs · Stateless RS256 JWKS Resource API Call`,
        `# Stage: ${selectedStage.toUpperCase()} | Active Fault: ${faultEval.title}`,
        `curl -i -X ${method} "${targetEndpoint}" \\`,
        `  -H "Accept: application/json" \\`,
        `  -H "Authorization: Bearer ${displayToken}"`
      ].join("\n");

  const typescript = isMcpTarget
    ? [
        `// Strict TypeScript MCP Client (Zero 'any', RFC 8693 Delegated OBO Token)`,
        `type McpToolResponse =`,
        `  | { readonly status: "ALLOWED"; readonly tool: string; readonly result: Record<string, unknown> }`,
        `  | { readonly error: string; readonly message: string };`,
        ``,
        `export async function callMcpTool(delegatedJwt: string): Promise<McpToolResponse> {`,
        `  const res = await fetch("${targetEndpoint}", {`,
        `    method: "POST",`,
        `    headers: {`,
        `      Accept: "application/json",`,
        `      "Content-Type": "application/json",`,
        `      Authorization: \`Bearer \${delegatedJwt}\``,
        `    },`,
        `    body: JSON.stringify(${mcpBody.replace(/\n/g, "\n    ")})`,
        `  });`,
        `  return (await res.json()) as McpToolResponse;`,
        `}`
      ].join("\n")
    : [
        `// Strict TypeScript OIDC Resource Client (${IDP_PRESETS[config.preset].label})`,
        `type ApiEnvelope =`,
        `  | { readonly ok: true; readonly status: number; readonly payload: Record<string, unknown> }`,
        `  | { readonly ok: false; readonly status: number; readonly error: string };`,
        ``,
        `export async function callProtectedResource(accessToken: string): Promise<ApiEnvelope> {`,
        `  const res = await fetch("${targetEndpoint}", {`,
        `    method: "${method}",`,
        `    headers: {`,
        `      Accept: "application/json",`,
        `      Authorization: \`Bearer \${accessToken}\``,
        `    }`,
        `  });`,
        `  const payload: unknown = await res.json();`,
        `  if (!res.ok) {`,
        `    return { ok: false, status: res.status, error: JSON.stringify(payload) };`,
        `  }`,
        `  return { ok: true, status: res.status, payload: payload as Record<string, unknown> };`,
        `}`
      ].join("\n");

  const oidcConfigObj: Record<string, unknown> = {
    platform: IDP_PRESETS[config.preset].label,
    providerFamily: "Choreo Labs (formerly WSO2)",
    clientType: "public_spa",
    clientId: config.clientId || "choreo-spa-public-client",
    redirectUri: config.redirectUri,
    pkce: {
      required: true,
      codeChallengeMethod: "S256",
      verifierEntropyBits: 384
    },
    endpoints: {
      authorizationEndpoint: `${config.baseUrl}/oauth2/authorize`,
      tokenEndpoint: config.issuer,
      jwksUri: config.jwksUri
    },
    jwtValidation: {
      algorithms: ["RS256"],
      issuer: config.issuer,
      audience: config.audience,
      clockToleranceSeconds: 5,
      jwksCacheMaxAgeMs: 600_000,
      jwksRateLimitRpm: 10
    },
    ...(flowMode === "agent"
      ? {
          agentDelegation: {
            grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
            rfc: "RFC 8693",
            actorSub: delegatedSession?.actor.sub ?? "agent:choreo-integrator-bot",
            downScopedScopes: delegatedSession?.grantedScopes ?? ["orders:read"],
            strippedScopes: delegatedSession?.strippedScopes ?? [
              "admin:write",
              "refunds:execute"
            ],
            maxTtlSeconds: AGENT_TOKEN_MAX_TTL_SECONDS,
            mcpGatewayEndpoint: "/api/mcp/tools/call"
          }
        }
      : {})
  };

  const synapseXml = [
    `<!-- WSO2 Micro Integrator (MI 4.3 / Apache Synapse) Mediation Artifact -->`,
    `<api context="/api/integration/orders" name="EnterpriseOrderIntegrationAPI" version="1.0.0" version-type="context" xmlns="http://ws.apache.org/ns/synapse">`,
    `  <resource methods="POST" uri-template="/{orderId}/mediate">`,
    `    <inSequence>`,
    `      <property expression="$trp:X-JWT-Assertion" name="APIM_BACKEND_JWT" scope="default" type="STRING"/>`,
    `      <property expression="json-eval($.amountUsd)" name="AMOUNT_USD" scope="default" type="STRING"/>`,
    `      <!-- Content-Based Router (CBR) -->`,
    `      <filter xpath="number(get-property('AMOUNT_USD')) &gt;= 1000">`,
    `        <then><property name="CBR_ROUTE" value="HIGH_VALUE_FRAUD_SCREEN"/></then>`,
    `        <else><property name="CBR_ROUTE" value="FAST_TRACK_STANDARD_ROUTE"/></else>`,
    `      </filter>`,
    `      <!-- Scatter-Gather Parallel Clone Mediator -->`,
    `      <clone id="ORDER_SCATTER_GATHER" sequential="false">`,
    `        <target><sequence><call><endpoint key="OrderCoreServiceEP"/></call></sequence></target>`,
    `        <target><sequence><call><endpoint key="WarehouseInventoryFailoverEP"/></call></sequence></target>`,
    `        <target><sequence><call><endpoint key="FraudRiskScoringServiceEP"/></call></sequence></target>`,
    `      </clone>`,
    `    </inSequence>`,
    `    <outSequence>`,
    `      <aggregate id="ORDER_SCATTER_GATHER">`,
    `        <completeCondition timeout="3"><messageCount max="-1" min="3"/></completeCondition>`,
    `        <onComplete enclosingElementProperty="AggregatedRoot" expression="$body/*">`,
    `          <payloadFactory media-type="json">`,
    `            <format>{"schemaVersion":"urn:wso2:mi:canonical-order:v3","route":"$1","aggregated":$2}</format>`,
    `            <args>`,
    `              <arg evaluator="xml" expression="get-property('CBR_ROUTE')"/>`,
    `              <arg evaluator="json" expression="$.AggregatedRoot"/>`,
    `            </args>`,
    `          </payloadFactory>`,
    `          <respond/>`,
    `        </onComplete>`,
    `      </aggregate>`,
    `    </outSequence>`,
    `  </resource>`,
    `</api>`
  ].join("\n");

  const ballerinaBal = [
    `// WSO2 Ballerina (Swan Lake) — Concurrent Scatter-Gather & Circuit Breaker Service`,
    `import ballerina/http;`,
    ``,
    `service /api/integration/orders on new http:Listener(8290) {`,
    `    isolated resource function post [string orderId]/mediate(`,
    `            @http:Header {name: "X-JWT-Assertion"} string? apimBackendJwt,`,
    `            @http:Payload json payload) returns json|error {`,
    `        decimal amountUsd = check payload.amountUsd.ensureType(decimal);`,
    `        string cbrRoute = amountUsd >= 1000d ? "HIGH_VALUE_FRAUD_SCREEN" : "FAST_TRACK_STANDARD_ROUTE";`,
    `        fork {`,
    `            worker OrderW returns json { return {orderId, status: "COMMITTED"}; }`,
    `            worker InventoryW returns json { return {warehouse: "RESERVED_PRIMARY"}; }`,
    `            worker RiskW returns json { return {route: cbrRoute, verdict: "APPROVED"}; }`,
    `        }`,
    `        record {json OrderW; json InventoryW; json RiskW;} branches = wait {OrderW, InventoryW, RiskW};`,
    `        return {schemaVersion: "urn:wso2:ballerina:canonical-order:v3", orderId, cbrRoute, branches};`,
    `    }`,
    `}`
  ].join("\n");

  return {
    curl,
    typescript,
    oidcConfigJson: JSON.stringify(oidcConfigObj, null, 2),
    synapseXml,
    ballerinaBal,
    targetEndpoint
  };
}
