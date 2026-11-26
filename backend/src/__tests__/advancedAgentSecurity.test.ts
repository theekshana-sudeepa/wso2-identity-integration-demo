import crypto from "node:crypto";
import type { Server } from "node:http";
import * as jose from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import identityConfig from "../config/identityConfig.js";
import { devIdpKeyStore } from "../devIdp/keyStore.js";
import {
  computeAccessTokenHash,
  computeEcJwkThumbprint,
  dpopReplayCache
} from "../middleware/dpopMiddleware.js";
import { createApp } from "../server.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

describe("Phase 4: CIBA Human-in-the-Loop Approval, RFC 9449 DPoP & RFC 7662 Token Introspection", () => {
  let server: Server;
  let baseUrl = "";
  let subjectToken = "";

  async function requestJson(
    path: string,
    init?: {
      readonly method?: "GET" | "POST";
      readonly token?: string;
      readonly dpop?: string;
      readonly verificationMode?: "jwks" | "introspect";
      readonly body?: Record<string, unknown>;
    }
  ): Promise<{
    readonly status: number;
    readonly headers: Headers;
    readonly body: Record<string, unknown>;
  }> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (init?.token) {
      headers.Authorization = `Bearer ${init.token}`;
    }
    if (init?.dpop) {
      headers.DPoP = init.dpop;
    }
    if (init?.verificationMode) {
      headers["X-Verification-Mode"] = init.verificationMode;
    }
    if (init?.body) {
      headers["Content-Type"] = "application/json";
    }
    const res = await fetch(`${baseUrl}${path}`, {
      method: init?.method ?? "GET",
      headers,
      body: init?.body ? JSON.stringify(init.body) : undefined
    });
    const parsed: unknown = await res.json();
    return {
      status: res.status,
      headers: res.headers,
      body: isRecord(parsed) ? parsed : {}
    };
  }

  beforeAll(async () => {
    dpopReplayCache.clear();
    devIdpKeyStore.clearRevocations();
    const app = createApp();
    await new Promise<void>((resolve, reject) => {
      server = app.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        if (!addr || typeof addr === "string") {
          reject(new Error("Expected TCP AddressInfo"));
          return;
        }
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    const verifier = crypto.randomBytes(36).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");
    const authz = await requestJson("/dev-idp/oauth2/authorize", {
      method: "POST",
      body: {
        persona: "admin",
        code_challenge: challenge,
        code_challenge_method: "S256"
      }
    });
    const tokenRes = await requestJson("/dev-idp/oauth2/token", {
      method: "POST",
      body: {
        grant_type: "authorization_code",
        code: authz.body.code,
        code_verifier: verifier
      }
    });
    subjectToken =
      typeof tokenRes.body.access_token === "string" ? tokenRes.body.access_token : "";
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("completes CIBA-style human step-up approval for export_all_users and enforces one-time approval consumption", async () => {
    const oboRes = await requestJson("/dev-idp/oauth2/token", {
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: subjectToken,
        actor_token: "agent:choreo-integrator-bot",
        resource: identityConfig.mcpAudience,
        scope: "orders:read"
      }
    });
    const baseAgentJwt =
      typeof oboRes.body.access_token === "string" ? oboRes.body.access_token : "";

    // 1. Initial export_all_users returns 403 human_approval_required with auth_req_id
    const blockedRes = await requestJson("/api/mcp", {
      method: "POST",
      token: baseAgentJwt,
      body: {
        jsonrpc: "2.0",
        id: 201,
        method: "tools/call",
        params: {
          name: "export_all_users",
          arguments: { format: "csv", includePii: true }
        }
      }
    });
    expect(blockedRes.status).toBe(403);
    expect(blockedRes.body.error).toBe("human_approval_required");
    const authReqId =
      typeof blockedRes.body.auth_req_id === "string" ? blockedRes.body.auth_req_id : "";
    expect(authReqId).toMatch(/^ciba_/);

    // 2. Human clicks Approve -> Dev IdP mints one-time approval token & step-up OBO JWT
    const approveRes = await requestJson("/dev-idp/oauth2/ciba/decide", {
      method: "POST",
      body: {
        auth_req_id: authReqId,
        decision: "APPROVED"
      }
    });
    expect(approveRes.status).toBe(200);
    expect(approveRes.body.status).toBe("APPROVED");
    const stepUpJwt =
      typeof approveRes.body.access_token === "string"
        ? approveRes.body.access_token
        : "";

    // 3. Retried export_all_users call with step-up JWT succeeds (200 ALLOWED)
    const retryRes = await requestJson("/api/mcp", {
      method: "POST",
      token: stepUpJwt,
      body: {
        jsonrpc: "2.0",
        id: 202,
        method: "tools/call",
        params: {
          name: "export_all_users",
          arguments: { format: "csv", includePii: true }
        }
      }
    });
    expect(retryRes.status).toBe(200);
    expect(retryRes.body.status).toBe("ALLOWED");

    // 4. Reusing the same one-time approval token a second time is rejected (403)
    const replayApprovalRes = await requestJson("/api/mcp", {
      method: "POST",
      token: stepUpJwt,
      body: {
        jsonrpc: "2.0",
        id: 203,
        method: "tools/call",
        params: {
          name: "export_all_users",
          arguments: { format: "csv", includePii: true }
        }
      }
    });
    expect(replayApprovalRes.status).toBe(403);
    expect(replayApprovalRes.body.error).toBe("human_approval_required");
  });

  it("enforces RFC 9449 DPoP sender-constrained agent tokens and rejects stolen token replay or jti replay", async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    const publicJwk = await jose.exportJWK(publicKey);
    const jkt = computeEcJwkThumbprint({
      kty: publicJwk.kty,
      crv: publicJwk.crv,
      x: publicJwk.x,
      y: publicJwk.y
    });
    expect(jkt).not.toBeNull();

    // 1. Exchange OBO token bound to cnf.jkt
    const oboRes = await requestJson("/dev-idp/oauth2/token", {
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: subjectToken,
        actor_token: "agent:choreo-integrator-bot",
        resource: identityConfig.mcpAudience,
        scope: "orders:read",
        dpop_jkt: jkt
      }
    });
    expect(oboRes.status).toBe(200);
    const dpopBoundJwt =
      typeof oboRes.body.access_token === "string" ? oboRes.body.access_token : "";

    // 2. Stolen token replay WITHOUT DPoP proof is rejected with 401 invalid_dpop_proof
    const stolenReplayRes = await requestJson("/api/mcp", {
      method: "POST",
      token: dpopBoundJwt,
      body: {
        jsonrpc: "2.0",
        id: 301,
        method: "tools/call",
        params: { name: "get_order_status", arguments: { orderId: "ORD-2026-88412" } }
      }
    });
    expect(stolenReplayRes.status).toBe(401);
    expect(stolenReplayRes.body.error).toBe("invalid_dpop_proof");

    // 3. Valid ES256 DPoP proof signed by the agent's private key succeeds (200)
    const nowSec = Math.floor(Date.now() / 1000);
    const dpopJti = `dpop_jti_${crypto.randomBytes(8).toString("base64url")}`;
    const validDpopProof = await new jose.SignJWT({
      htm: "POST",
      htu: `${baseUrl}/api/mcp`,
      iat: nowSec,
      jti: dpopJti,
      ath: computeAccessTokenHash(dpopBoundJwt)
    })
      .setProtectedHeader({
        alg: "ES256",
        typ: "dpop+jwt",
        jwk: {
          kty: "EC",
          crv: "P-256",
          x: publicJwk.x,
          y: publicJwk.y
        }
      })
      .sign(privateKey);

    const validDpopRes = await requestJson("/api/mcp", {
      method: "POST",
      token: dpopBoundJwt,
      dpop: validDpopProof,
      body: {
        jsonrpc: "2.0",
        id: 302,
        method: "tools/call",
        params: { name: "get_order_status", arguments: { orderId: "ORD-2026-88412" } }
      }
    });
    expect(validDpopRes.status).toBe(200);
    expect(validDpopRes.body.status).toBe("ALLOWED");

    // 4. Replaying the exact same DPoP proof (same jti) is rejected by the LRU replay cache
    const replayedProofRes = await requestJson("/api/mcp", {
      method: "POST",
      token: dpopBoundJwt,
      dpop: validDpopProof,
      body: {
        jsonrpc: "2.0",
        id: 303,
        method: "tools/call",
        params: { name: "get_order_status", arguments: { orderId: "ORD-2026-88412" } }
      }
    });
    expect(replayedProofRes.status).toBe(401);
    expect(replayedProofRes.body.error).toBe("invalid_dpop_proof");
  });

  it("contrasts Stateless JWKS Verification with RFC 7662 Token Introspection after RFC 7009 Revocation", async () => {
    // 1. Revoke the human subjectToken via POST /dev-idp/oauth2/revoke
    const revokeRes = await requestJson("/dev-idp/oauth2/revoke", {
      method: "POST",
      body: { token: subjectToken }
    });
    expect(revokeRes.status).toBe(200);
    expect(revokeRes.body.revoked).toBe(true);

    // 2. Stateless JWKS mode (0 IdP hops) continues accepting the valid RS256 signature until exp
    const statelessRes = await requestJson("/api/v1/user/profile", {
      token: subjectToken,
      verificationMode: "jwks"
    });
    expect(statelessRes.status).toBe(200);

    // 3. Stateful Introspection mode (RFC 7662) detects revocation and rejects with 401 token_revoked
    const introspectRes = await requestJson("/api/v1/user/profile", {
      token: subjectToken,
      verificationMode: "introspect"
    });
    expect(introspectRes.status).toBe(401);
    expect(introspectRes.body.error).toBe("token_revoked");
  });
});
