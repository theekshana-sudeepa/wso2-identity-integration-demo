import crypto from "node:crypto";
import express, { type Router } from "express";
import * as jose from "jose";
import jwt from "jsonwebtoken";
import { AGENT_TOKEN_MAX_TTL_SECONDS } from "../config/agentPolicy.js";
import identityConfig from "../config/identityConfig.js";
import { cibaApprovalStore } from "../mcp/cibaStore.js";
import {
  evaluateActChain,
  evaluateMayAct,
  parseActorChain
} from "../middleware/delegationPolicy.js";
import { computeEcJwkThumbprint } from "../middleware/dpopMiddleware.js";
import type { ActorClaim, DefenseTrace } from "../types/auth.js";
import { devIdpKeyStore, ROGUE_UNTRUSTED_KID } from "./keyStore.js";
import {
  DEV_IDP_PERSONAS,
  resolveDevIdpPersona,
  type DevIdpPersonaId
} from "./personas.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

interface StoredAuthorizationCode {
  readonly code: string;
  readonly codeChallenge: string;
  readonly persona: DevIdpPersonaId;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scope: string;
  readonly expiresAtMs: number;
}

const PRIVILEGED_NON_DELEGATABLE_SCOPES = new Set<string>([
  "admin:write",
  "admin:audit",
  "write:reports",
  "refunds:execute",
  "users:export"
]);

const ALLOWED_DELEGATED_SCOPES = new Set<string>(["orders:read"]);

function computeS256Challenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");
}

function base64UrlEncodeJson(obj: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
}

export function createDevIdpRouter(): Router {
  const router = express.Router();
  const authCodes = new Map<string, StoredAuthorizationCode>();

  router.use(express.urlencoded({ extended: false }));
  router.use(express.json());

  router.get("/.well-known/openid-configuration", (_req, res) => {
    const base = identityConfig.devIdpBaseUrl;
    res.json({
      issuer: identityConfig.issuer,
      authorization_endpoint: `${base}/oauth2/authorize`,
      token_endpoint: `${base}/oauth2/token`,
      jwks_uri: `${base}/oauth2/jwks`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"],
      grant_types_supported: [
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:token-exchange"
      ],
      activeKid: devIdpKeyStore.getActiveKid(),
      rotatedKid: devIdpKeyStore.getRotatedKid(),
      personas: Object.keys(DEV_IDP_PERSONAS)
    });
  });

  router.get("/oauth2/jwks", async (_req, res) => {
    const jwks = await devIdpKeyStore.getJwks();
    res.json(jwks);
  });

  const handleAuthorize: express.RequestHandler = (req, res) => {
    const source: Record<string, unknown> =
      req.method === "POST" && isRecord(req.body)
        ? req.body
        : isRecord(req.query)
          ? req.query
          : {};

    const codeChallenge =
      typeof source.code_challenge === "string" ? source.code_challenge.trim() : "";
    const challengeMethod =
      typeof source.code_challenge_method === "string"
        ? source.code_challenge_method.trim()
        : "S256";

    if (!codeChallenge || challengeMethod !== "S256") {
      res.status(400).json({
        error: "invalid_request",
        error_description:
          "RFC 7636 S256 code_challenge and code_challenge_method=S256 are required."
      });
      return;
    }

    const persona = resolveDevIdpPersona(source.persona);
    const clientId =
      typeof source.client_id === "string" && source.client_id.trim().length > 0
        ? source.client_id.trim()
        : "choreo-spa-public-client";
    const redirectUri =
      typeof source.redirect_uri === "string" && source.redirect_uri.trim().length > 0
        ? source.redirect_uri.trim()
        : "http://localhost:5173/callback";
    const state = typeof source.state === "string" ? source.state.trim() : "";
    const scope =
      typeof source.scope === "string" && source.scope.trim().length > 0
        ? source.scope.trim()
        : persona.scopes.join(" ");

    const code = `authz_${crypto.randomBytes(16).toString("base64url")}`;
    if (authCodes.size > 500) {
      const oldestKey = authCodes.keys().next().value;
      if (oldestKey) authCodes.delete(oldestKey);
    }

    authCodes.set(code, {
      code,
      codeChallenge,
      persona: persona.id,
      clientId,
      redirectUri,
      scope,
      expiresAtMs: Date.now() + 5 * 60 * 1000
    });

    const wantsJson =
      req.method === "POST" ||
      source.response_mode === "json" ||
      (typeof req.headers.accept === "string" &&
        req.headers.accept.includes("application/json") &&
        !req.headers.accept.includes("text/html"));

    if (wantsJson) {
      res.status(200).json({
        code,
        state,
        persona: persona.id,
        code_challenge: codeChallenge,
        code_challenge_method: "S256"
      });
      return;
    }

    const redirectUrl = new URL(redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (state) {
      redirectUrl.searchParams.set("state", state);
    }
    res.redirect(302, redirectUrl.toString());
  };

  router.get("/oauth2/authorize", handleAuthorize);
  router.post("/oauth2/authorize", handleAuthorize);

  router.post("/oauth2/token", async (req, res) => {
    const body = isRecord(req.body) ? req.body : {};
    const grantType = typeof body.grant_type === "string" ? body.grant_type.trim() : "";

    if (grantType === "authorization_code") {
      const code = typeof body.code === "string" ? body.code.trim() : "";
      const codeVerifier =
        typeof body.code_verifier === "string" ? body.code_verifier.trim() : "";

      const stored = authCodes.get(code);
      if (stored) {
        authCodes.delete(code);
      }

      const inlineChallenge =
        typeof body.code_challenge === "string" ? body.code_challenge.trim() : "";
      const expectedChallenge = stored?.codeChallenge ?? inlineChallenge;

      if (!expectedChallenge || (stored && stored.expiresAtMs < Date.now())) {
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Authorization code is invalid, expired, or has already been redeemed."
        });
        return;
      }

      if (!codeVerifier) {
        res.status(400).json({
          error: "invalid_request",
          error_description: "Missing required RFC 7636 code_verifier parameter."
        });
        return;
      }

      const computedChallenge = computeS256Challenge(codeVerifier);
      if (computedChallenge !== expectedChallenge) {
        const defenseTrace: DefenseTrace = {
          layer: "Dev IdP Token Endpoint PKCE S256 Guard",
          middleware: "backend/src/devIdp/devIdpRouter.ts -> POST /dev-idp/oauth2/token",
          rfc: "RFC 7636 §4.6 (Server Verifies code_verifier)",
          check: `BASE64URL(SHA256(code_verifier)) [${computedChallenge}] === stored_code_challenge [${expectedChallenge}]`,
          outcome: "REJECTED",
          details: `PKCE S256 digest mismatch: computed "${computedChallenge}" !== stored "${expectedChallenge}".`
        };
        res.status(400).json({
          error: "invalid_grant",
          error_description: "PKCE code_verifier does not match stored S256 code_challenge.",
          expected_code_challenge: expectedChallenge,
          computed_code_challenge: computedChallenge,
          defenseTrace
        });
        return;
      }

      const persona = resolveDevIdpPersona(stored?.persona ?? body.persona);
      const nowSec = Math.floor(Date.now() / 1000);
      const expiresIn = 3600;

      const accessPayload: Record<string, unknown> = {
        sub: persona.sub,
        username: persona.username,
        preferred_username: persona.username,
        email: persona.email,
        iss: identityConfig.issuer,
        aud: identityConfig.audience,
        azp: stored?.clientId ?? "choreo-spa-public-client",
        groups: [...persona.groups],
        scope: persona.scopes.join(" "),
        may_act: persona.mayAct,
        iat: nowSec,
        exp: nowSec + expiresIn
      };

      const accessToken = await devIdpKeyStore.signRs256Jwt(accessPayload);
      const idToken = await devIdpKeyStore.signRs256Jwt({
        ...accessPayload,
        aud: stored?.clientId ?? "choreo-spa-public-client"
      });

      res.status(200).json({
        access_token: accessToken,
        id_token: idToken,
        token_type: "Bearer",
        expires_in: expiresIn,
        scope: persona.scopes.join(" "),
        persona: persona.id,
        kid: devIdpKeyStore.getActiveKid()
      });
      return;
    }

    if (grantType === "urn:ietf:params:oauth:grant-type:token-exchange") {
      const subjectToken =
        typeof body.subject_token === "string" ? body.subject_token.trim() : "";
      if (!subjectToken) {
        res.status(400).json({
          error: "invalid_request",
          error_description: "Missing subject_token for RFC 8693 token exchange."
        });
        return;
      }

      let subjectPayload: Record<string, unknown>;
      try {
        const verified = await devIdpKeyStore.verifyToken(subjectToken, identityConfig.issuer);
        subjectPayload = isRecord(verified.payload) ? verified.payload : {};
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Invalid subject_token signature";
        res.status(400).json({
          error: "invalid_grant",
          error_description: `Subject token verification failed at STS: ${msg}`
        });
        return;
      }

      const rawActorToken =
        typeof body.actor_token === "string" ? body.actor_token.trim() : "";
      let actorSub = "agent:choreo-integrator-bot";
      let actorClientId = "choreo-mcp-agent-v1";

      if (rawActorToken) {
        if (rawActorToken.startsWith("agent:")) {
          actorSub = rawActorToken;
        } else if (rawActorToken.split(".").length === 3) {
          try {
            const verifiedActor = await devIdpKeyStore.verifyToken(rawActorToken);
            if (typeof verifiedActor.payload.sub === "string") {
              actorSub = verifiedActor.payload.sub;
            }
            if (typeof verifiedActor.payload.client_id === "string") {
              actorClientId = verifiedActor.payload.client_id;
            }
          } catch {
            res.status(400).json({
              error: "invalid_grant",
              error_description: "Invalid actor_token signature."
            });
            return;
          }
        } else {
          actorSub = rawActorToken;
        }
      }

      const mayActVerdict = evaluateMayAct(subjectPayload, actorSub, {
        requireExplicitMayAct: true
      });
      if (!mayActVerdict.permitted) {
        const defenseTrace: DefenseTrace = {
          layer: "STS RFC 8693 §4.4 may_act Guard",
          middleware: "backend/src/devIdp/devIdpRouter.ts -> evaluateMayAct()",
          rfc: "RFC 8693 §4.4 (may_act Authorized Actor Claim)",
          check: `verify(subject_token.may_act allows "${actorSub}")`,
          outcome: "REJECTED",
          details: `Actor "${actorSub}" is not authorized by subject_token may_act claim (${mayActVerdict.reason}).`
        };
        res.status(400).json({
          error: "unauthorized_client",
          error_description: `Actor "${actorSub}" is not authorized in subject_token may_act claim.`,
          reason: mayActVerdict.reason,
          defenseTrace
        });
        return;
      }

      const subjectScopes =
        typeof subjectPayload.scope === "string"
          ? subjectPayload.scope
              .split(" ")
              .map((s) => s.trim())
              .filter(Boolean)
          : ["openid", "profile", "orders:read"];

      const requestedScopeStr =
        typeof body.scope === "string" && body.scope.trim().length > 0
          ? body.scope.trim()
          : "orders:read";
      const requestedScopes = requestedScopeStr
        .split(" ")
        .map((s) => s.trim())
        .filter(Boolean);

      for (const reqScope of requestedScopes) {
        if (
          PRIVILEGED_NON_DELEGATABLE_SCOPES.has(reqScope) ||
          !ALLOWED_DELEGATED_SCOPES.has(reqScope) ||
          !subjectScopes.includes(reqScope)
        ) {
          const defenseTrace: DefenseTrace = {
            layer: "STS RFC 8693 Scope Down-Scoping Guard",
            middleware: "backend/src/devIdp/devIdpRouter.ts -> token-exchange",
            rfc: "RFC 8693 §2.1 & §5 (Privilege Attenuation)",
            check: `requestedScope("${reqScope}") in (subjectScopes intersect allowedAgentScopes)`,
            outcome: "REJECTED",
            details: `STS rejected scope escalation request for "${reqScope}". Delegated AI agents are restricted to [${Array.from(ALLOWED_DELEGATED_SCOPES).join(", ")}].`
          };
          res.status(400).json({
            error: "invalid_scope",
            error_description: `Requested scope "${reqScope}" cannot be granted to a delegated AI agent during OBO token exchange.`,
            requested_scopes: requestedScopes,
            allowed_agent_scopes: Array.from(ALLOWED_DELEGATED_SCOPES),
            defenseTrace
          });
          return;
        }
      }

      const existingChain = parseActorChain(subjectPayload.act);
      const newActor: ActorClaim = {
        sub: actorSub,
        client_id: actorClientId,
        delegation_protocol: "urn:ietf:params:oauth:grant-type:token-exchange",
        ...(existingChain.chain[0] ? { act: existingChain.chain[0] } : {})
      };

      const combinedChain = parseActorChain(newActor);
      const subjectSub =
        typeof subjectPayload.sub === "string" ? subjectPayload.sub : "usr_4b21d90e_dev";
      const chainVerdict = evaluateActChain(
        subjectSub,
        combinedChain.chain,
        combinedChain.truncated
      );
      if (!chainVerdict.ok) {
        res.status(400).json({
          error: "invalid_request",
          error_description: chainVerdict.details,
          reason: chainVerdict.reason
        });
        return;
      }

      const requestedResource =
        typeof body.resource === "string" ? body.resource.trim() : "";
      if (
        requestedResource.length > 0 &&
        requestedResource !== identityConfig.mcpAudience &&
        requestedResource !== identityConfig.audience
      ) {
        const defenseTrace: DefenseTrace = {
          layer: "STS RFC 8707 Resource Indicator Guard",
          middleware: "backend/src/devIdp/devIdpRouter.ts -> token-exchange",
          rfc: "RFC 8707 §2 (Resource Indicators for OAuth 2.0)",
          check: `resource("${requestedResource}") in registeredProtectedResources`,
          outcome: "REJECTED",
          details: `Requested resource indicator "${requestedResource}" is not a registered Protected Resource URI. Expected "${identityConfig.mcpAudience}".`
        };
        res.status(400).json({
          error: "invalid_target",
          error_description: `Unregistered RFC 8707 resource indicator "${requestedResource}".`,
          expected_resource: identityConfig.mcpAudience,
          defenseTrace
        });
        return;
      }

      const targetAudience =
        requestedResource ||
        (typeof body.audience === "string" && body.audience.trim()) ||
        identityConfig.mcpAudience;

      const strippedScopes = subjectScopes.filter(
        (s) =>
          !requestedScopes.includes(s) &&
          s !== "openid" &&
          s !== "profile" &&
          s !== "email" &&
          s !== "groups"
      );
      for (const priv of ["admin:write", "refunds:execute"]) {
        if (!strippedScopes.includes(priv)) {
          strippedScopes.push(priv);
        }
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const ttlSeconds = AGENT_TOKEN_MAX_TTL_SECONDS;

      let dpopJkt: string | null =
        typeof body.dpop_jkt === "string" && body.dpop_jkt.trim().length > 0
          ? body.dpop_jkt.trim()
          : null;
      if (!dpopJkt && typeof req.headers.dpop === "string") {
        try {
          const dpopHeader = jose.decodeProtectedHeader(req.headers.dpop.trim());
          if (isRecord(dpopHeader.jwk)) {
            dpopJkt = computeEcJwkThumbprint(dpopHeader.jwk);
          }
        } catch {
          dpopJkt = null;
        }
      }

      const oboPayload: Record<string, unknown> = {
        sub: subjectSub,
        username:
          typeof subjectPayload.username === "string"
            ? subjectPayload.username
            : subjectSub,
        iss: identityConfig.issuer,
        aud: targetAudience,
        azp: actorClientId,
        act: newActor,
        scope: requestedScopes.join(" "),
        groups: ["delegated-agent-readonly"],
        delegation_depth: combinedChain.chain.length,
        original_scopes: subjectScopes,
        stripped_scopes: strippedScopes,
        ...(dpopJkt ? { cnf: { jkt: dpopJkt } } : {}),
        jti: `obo_${crypto.randomBytes(12).toString("base64url")}`,
        iat: nowSec,
        exp: nowSec + ttlSeconds
      };

      const delegatedToken = await devIdpKeyStore.signRs256Jwt(oboPayload, {
        typ: "at+jwt"
      });

      res.status(200).json({
        access_token: delegatedToken,
        issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
        token_type: dpopJkt ? "DPoP" : "Bearer",
        expires_in: ttlSeconds,
        scope: requestedScopes.join(" "),
        audience: targetAudience,
        actor: newActor,
        ...(dpopJkt ? { cnf: { jkt: dpopJkt } } : {}),
        original_scopes: subjectScopes,
        stripped_scopes: strippedScopes,
        issued_at: nowSec,
        expires_at: nowSec + ttlSeconds
      });
      return;
    }

    res.status(400).json({
      error: "unsupported_grant_type",
      error_description: `Unsupported grant_type "${grantType}".`
    });
  });

  router.post("/oauth2/ciba/decide", async (req, res) => {
    const body = isRecord(req.body) ? req.body : {};
    const authReqId =
      typeof body.auth_req_id === "string" ? body.auth_req_id.trim() : "";
    const decision = body.decision === "DENIED" ? "DENIED" : "APPROVED";

    if (!authReqId) {
      res.status(400).json({
        error: "invalid_request",
        error_description: "Missing auth_req_id for CIBA step-up decision."
      });
      return;
    }

    const decided = cibaApprovalStore.decideRequest(authReqId, decision);
    if (!decided) {
      res.status(404).json({
        error: "expired_token",
        error_description: `CIBA request "${authReqId}" was not found.`
      });
      return;
    }

    if (decided.status === "DENIED") {
      res.status(200).json({
        status: "DENIED",
        auth_req_id: decided.authReqId,
        error: "access_denied",
        error_description: "Human principal explicitly denied step-up consent."
      });
      return;
    }

    if (decided.status !== "APPROVED" || !decided.approvalToken) {
      res.status(400).json({
        error: "invalid_grant",
        error_description: `CIBA request "${authReqId}" is in status "${decided.status}".`
      });
      return;
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const ttlSeconds = AGENT_TOKEN_MAX_TTL_SECONDS;
    const dpopJkt =
      typeof body.dpop_jkt === "string" && body.dpop_jkt.trim().length > 0
        ? body.dpop_jkt.trim()
        : null;

    const actor: ActorClaim = {
      sub: decided.actorSub,
      client_id: "choreo-mcp-agent-v1",
      delegation_protocol: "urn:ietf:params:oauth:grant-type:token-exchange"
    };

    const stepUpScopes = ["orders:read", decided.requiredScope];
    const stepUpPayload: Record<string, unknown> = {
      sub: decided.sub,
      username: decided.sub,
      iss: identityConfig.issuer,
      aud: identityConfig.mcpAudience,
      azp: actor.client_id,
      act: actor,
      scope: stepUpScopes.join(" "),
      groups: ["delegated-agent-stepup"],
      delegation_depth: 1,
      human_approval_token: decided.approvalToken,
      approval: {
        auth_req_id: decided.authReqId,
        tool: decided.tool,
        bound_jti: decided.boundJti,
        approved_by: decided.sub,
        expires_at: decided.expiresAtSec
      },
      ...(dpopJkt ? { cnf: { jkt: dpopJkt } } : {}),
      jti: `obo_ciba_${crypto.randomBytes(10).toString("base64url")}`,
      iat: nowSec,
      exp: nowSec + ttlSeconds
    };

    const stepUpJwt = await devIdpKeyStore.signRs256Jwt(stepUpPayload, {
      typ: "at+jwt"
    });

    res.status(200).json({
      status: "APPROVED",
      auth_req_id: decided.authReqId,
      approval_token: decided.approvalToken,
      access_token: stepUpJwt,
      token_type: dpopJkt ? "DPoP" : "Bearer",
      expires_in: ttlSeconds,
      scope: stepUpScopes.join(" "),
      actor,
      approval: stepUpPayload.approval
    });
  });

  router.post("/oauth2/revoke", (req, res) => {
    const body = isRecord(req.body) ? req.body : {};
    const token = typeof body.token === "string" ? body.token.trim() : "";
    if (!token) {
      res.status(400).json({
        error: "invalid_request",
        error_description: "Missing token parameter for RFC 7009 revocation."
      });
      return;
    }

    let jti: string | undefined;
    try {
      const decoded = jose.decodeJwt(token);
      if (typeof decoded.jti === "string") {
        jti = decoded.jti;
      }
    } catch {
      jti = undefined;
    }

    devIdpKeyStore.revokeToken(token, jti);
    res.status(200).json({
      revoked: true,
      jti: jti ?? null,
      rfc: "RFC 7009 (OAuth 2.0 Token Revocation)",
      tradeoffNote:
        "Stateless JWKS verification (0 IdP hops) continues accepting this token until exp; RFC 7662 Token Introspection (+1 IdP hop) rejects it immediately with active: false."
    });
  });

  router.post("/oauth2/introspect", async (req, res) => {
    const body = isRecord(req.body) ? req.body : {};
    const token = typeof body.token === "string" ? body.token.trim() : "";
    if (!token) {
      res.status(200).json({ active: false });
      return;
    }

    try {
      const verified = await devIdpKeyStore.verifyToken(token, identityConfig.issuer);
      const jti =
        typeof verified.payload.jti === "string" ? verified.payload.jti : undefined;
      if (devIdpKeyStore.isTokenRevoked(token, jti)) {
        res.status(200).json({
          active: false,
          revoked: true,
          sub: verified.payload.sub ?? null,
          jti: jti ?? null
        });
        return;
      }

      res.status(200).json({
        active: true,
        ...verified.payload
      });
    } catch {
      res.status(200).json({ active: false });
    }
  });

  router.post("/admin/rotate-keys", async (_req, res) => {
    const rotation = devIdpKeyStore.rotateKeys();
    const jwks = await devIdpKeyStore.getJwks();
    res.status(200).json({
      rotated: true,
      ...rotation,
      jwks
    });
  });

  router.post("/admin/mint-fault-token", async (req, res) => {
    const body = isRecord(req.body) ? req.body : {};
    const fault = isRecord(body.fault) ? body.fault : { id: "none" };
    const faultId = typeof fault.id === "string" ? fault.id : "none";
    const targetAudience =
      typeof body.targetAudience === "string" && body.targetAudience.trim().length > 0
        ? body.targetAudience.trim()
        : identityConfig.audience;
    const persona = resolveDevIdpPersona(body.persona ?? "admin");
    const nowSec = Math.floor(Date.now() / 1000);

    const baseClaims: Record<string, unknown> = {
      sub: persona.sub,
      username: persona.username,
      email: persona.email,
      iss: identityConfig.issuer,
      aud: targetAudience,
      groups: [...persona.groups],
      ...(targetAudience === identityConfig.mcpAudience
        ? {
            act: {
              sub: "agent:choreo-integrator-bot",
              client_id: "choreo-mcp-agent-v1",
              delegation_protocol: "urn:ietf:params:oauth:grant-type:token-exchange"
            },
            scope: "orders:read",
            iat: nowSec,
            exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
          }
        : {
            scope: persona.scopes.join(" "),
            iat: nowSec,
            exp: nowSec + 3600
          })
    };

    if (faultId === "jwt_alg_downgrade") {
      const alg = fault.algorithm === "HS256" ? "HS256" : "none";
      if (alg === "none") {
        const header = base64UrlEncodeJson({ alg: "none", typ: "JWT" });
        const payload = base64UrlEncodeJson(baseClaims);
        res.json({
          faultId,
          algorithm: "none",
          token: `${header}.${payload}.`
        });
        return;
      }

      const publicPem = devIdpKeyStore.getActiveKey().publicKeyPem;
      const hs256Token = jwt.sign(baseClaims, publicPem, {
        algorithm: "HS256",
        keyid: devIdpKeyStore.getActiveKid()
      });
      res.json({
        faultId,
        algorithm: "HS256",
        token: hs256Token
      });
      return;
    }

    if (faultId === "jwks_kid_miss") {
      const recover = fault.resolution === "recover_rotated_key";
      const token = await devIdpKeyStore.signRs256Jwt(baseClaims, {
        useKey: recover ? "rotated" : "rogue",
        kid: recover ? devIdpKeyStore.getRotatedKid() : ROGUE_UNTRUSTED_KID
      });
      res.json({
        faultId,
        resolution: recover ? "recover_rotated_key" : "reject_unknown_kid",
        kid: recover ? devIdpKeyStore.getRotatedKid() : ROGUE_UNTRUSTED_KID,
        token
      });
      return;
    }

    if (faultId === "aud_iss_spoof") {
      const spoofTarget = fault.spoofTarget === "iss" ? "iss" : "aud";
      const spoofedClaims: Record<string, unknown> = {
        ...baseClaims,
        iss:
          spoofTarget === "iss"
            ? "https://evil-idp.attacker.example/oauth2/token"
            : identityConfig.issuer,
        aud: spoofTarget === "aud" ? "wrong-tenant-billing-api" : targetAudience
      };
      const token = await devIdpKeyStore.signRs256Jwt(spoofedClaims);
      res.json({
        faultId,
        spoofTarget,
        token
      });
      return;
    }

    if (faultId === "expired_token_skew") {
      const skewSeconds =
        typeof fault.skewSeconds === "number" && fault.skewSeconds > 0
          ? fault.skewSeconds
          : 185;
      const expSec = nowSec - skewSeconds;
      const expiredClaims: Record<string, unknown> = {
        ...baseClaims,
        iat: expSec - 60,
        exp: expSec
      };
      const token = await devIdpKeyStore.signRs256Jwt(expiredClaims);
      res.json({
        faultId,
        skewSeconds,
        token
      });
      return;
    }

    if (faultId === "dpop_token_replay") {
      const dpopBoundClaims: Record<string, unknown> = {
        ...baseClaims,
        aud: identityConfig.mcpAudience,
        act: {
          sub: "agent:choreo-integrator-bot",
          client_id: "choreo-mcp-agent-v1",
          delegation_protocol: "urn:ietf:params:oauth:grant-type:token-exchange"
        },
        scope: "orders:read",
        cnf: {
          jkt: "dpop_bound_jkt_expected_2026"
        },
        iat: nowSec,
        exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
      };
      const token = await devIdpKeyStore.signRs256Jwt(dpopBoundClaims, {
        typ: "at+jwt"
      });
      res.json({
        faultId,
        token
      });
      return;
    }

    if (faultId === "rfc8707_token_passthrough") {
      const passthroughClaims: Record<string, unknown> = {
        ...baseClaims,
        aud: identityConfig.audience,
        act: {
          sub: "agent:choreo-integrator-bot",
          client_id: "choreo-mcp-agent-v1",
          delegation_protocol: "urn:ietf:params:oauth:grant-type:token-exchange"
        },
        scope: "orders:read",
        iat: nowSec,
        exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
      };
      const token = await devIdpKeyStore.signRs256Jwt(passthroughClaims);
      res.json({
        faultId,
        token
      });
      return;
    }

    if (faultId === "act_chain_violation") {
      const variant = fault.variant === "cycle_detected" ? "cycle_detected" : "depth_exceeded";
      const badAct =
        variant === "cycle_detected"
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
      const badActClaims: Record<string, unknown> = {
        ...baseClaims,
        aud: identityConfig.mcpAudience,
        act: badAct,
        scope: "orders:read",
        iat: nowSec,
        exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
      };
      const token = await devIdpKeyStore.signRs256Jwt(badActClaims, {
        typ: "at+jwt"
      });
      res.json({
        faultId,
        variant,
        token
      });
      return;
    }

    const nominalToken = await devIdpKeyStore.signRs256Jwt(baseClaims);
    res.json({
      faultId: "none",
      token: nominalToken
    });
  });

  return router;
}
