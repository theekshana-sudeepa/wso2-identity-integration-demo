import crypto from "node:crypto";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import identityConfig from "../config/identityConfig.js";
import { createApp } from "../server.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function createPkcePair(): { readonly verifier: string; readonly challenge: string } {
  const verifier = crypto.randomBytes(36).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");
  return { verifier, challenge };
}

describe("Local Dev IdP / STS (OIDC PKCE S256 + RFC 8693 Token Exchange + Live Attack Lab)", () => {
  let server: Server;
  let baseUrl = "";

  async function requestJson(
    path: string,
    init?: {
      readonly method?: "GET" | "POST";
      readonly token?: string;
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
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("publishes OIDC Discovery metadata and RSA-2048 JWKS keys", async () => {
    const discovery = await requestJson("/dev-idp/.well-known/openid-configuration");
    expect(discovery.status).toBe(200);
    expect(discovery.body.issuer).toBe(identityConfig.issuer);
    expect(discovery.body.code_challenge_methods_supported).toEqual(["S256"]);

    const jwks = await requestJson("/dev-idp/oauth2/jwks");
    expect(jwks.status).toBe(200);
    expect(Array.isArray(jwks.body.keys)).toBe(true);
    const keys = Array.isArray(jwks.body.keys) ? jwks.body.keys : [];
    expect(keys.length).toBeGreaterThanOrEqual(2);
  });

  it("verifies real S256 PKCE authorization_code exchanges for seeded personas and rejects tampered verifiers", async () => {
    const pkce = createPkcePair();

    const authzRes = await requestJson("/dev-idp/oauth2/authorize", {
      method: "POST",
      body: {
        persona: "admin",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        state: "state_123"
      }
    });
    expect(authzRes.status).toBe(200);
    const code = typeof authzRes.body.code === "string" ? authzRes.body.code : "";
    expect(code.length).toBeGreaterThan(8);

    // 1. Exchange with valid code_verifier succeeds and mints a real RS256 JWT
    const tokenRes = await requestJson("/dev-idp/oauth2/token", {
      method: "POST",
      body: {
        grant_type: "authorization_code",
        code,
        code_verifier: pkce.verifier
      }
    });
    expect(tokenRes.status).toBe(200);
    const adminToken =
      typeof tokenRes.body.access_token === "string" ? tokenRes.body.access_token : "";
    expect(adminToken.split(".")).toHaveLength(3);

    // 2. Resource server accepts the Dev-IdP-signed admin token with 200 OK
    const profileRes = await requestJson("/api/v1/user/profile", { token: adminToken });
    expect(profileRes.status).toBe(200);
    const auditRes = await requestJson("/api/v1/admin/audit-logs", { token: adminToken });
    expect(auditRes.status).toBe(200);

    // 3. Developer and Auditor personas have distinct RBAC enforcement
    const auditorPkce = createPkcePair();
    const auditorAuthz = await requestJson("/dev-idp/oauth2/authorize", {
      method: "POST",
      body: {
        persona: "auditor",
        code_challenge: auditorPkce.challenge,
        code_challenge_method: "S256"
      }
    });
    const auditorTokenRes = await requestJson("/dev-idp/oauth2/token", {
      method: "POST",
      body: {
        grant_type: "authorization_code",
        code: auditorAuthz.body.code,
        code_verifier: auditorPkce.verifier
      }
    });
    expect(auditorTokenRes.status).toBe(200);
    const auditorToken =
      typeof auditorTokenRes.body.access_token === "string"
        ? auditorTokenRes.body.access_token
        : "";
    const auditorProfile = await requestJson("/api/v1/user/profile", { token: auditorToken });
    expect(auditorProfile.status).toBe(200);
    const auditorAdminDeny = await requestJson("/api/v1/admin/audit-logs", {
      token: auditorToken
    });
    expect(auditorAdminDeny.status).toBe(403);

    // 4. Tampered PKCE code_verifier is rejected with 400 invalid_grant and side-by-side SHA-256 digests
    const badPkce = createPkcePair();
    const badAuthz = await requestJson("/dev-idp/oauth2/authorize", {
      method: "POST",
      body: {
        persona: "developer",
        code_challenge: badPkce.challenge,
        code_challenge_method: "S256"
      }
    });
    const mismatchRes = await requestJson("/dev-idp/oauth2/token", {
      method: "POST",
      body: {
        grant_type: "authorization_code",
        code: badAuthz.body.code,
        code_verifier: `${badPkce.verifier}_TAMPERED`
      }
    });
    expect(mismatchRes.status).toBe(400);
    expect(mismatchRes.body.error).toBe("invalid_grant");
    expect(mismatchRes.body.expected_code_challenge).toBe(badPkce.challenge);
    expect(mismatchRes.body.computed_code_challenge).not.toBe(badPkce.challenge);
  });

  it("mints RFC 8693 down-scoped OBO tokens at the STS and blocks scope escalation & unauthorized actors", async () => {
    const pkce = createPkcePair();
    const authz = await requestJson("/dev-idp/oauth2/authorize", {
      method: "POST",
      body: {
        persona: "admin",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256"
      }
    });
    const humanTokenRes = await requestJson("/dev-idp/oauth2/token", {
      method: "POST",
      body: {
        grant_type: "authorization_code",
        code: authz.body.code,
        code_verifier: pkce.verifier
      }
    });
    const subjectToken =
      typeof humanTokenRes.body.access_token === "string"
        ? humanTokenRes.body.access_token
        : "";

    // 1. Valid RFC 8693 exchange produces a signed 60s token with aud = MCP_AUDIENCE
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
    expect(oboRes.status).toBe(200);
    expect(oboRes.body.issued_token_type).toBe(
      "urn:ietf:params:oauth:token-type:access_token"
    );
    expect(oboRes.body.expires_in).toBe(60);
    const agentJwt =
      typeof oboRes.body.access_token === "string" ? oboRes.body.access_token : "";

    const mcpAllow = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: agentJwt,
      body: { tool: "get_order_status", arguments: { orderId: "ORD-2026-88412" } }
    });
    expect(mcpAllow.status).toBe(200);
    expect(mcpAllow.body.status).toBe("ALLOWED");

    // 2. Scope escalation at STS is rejected with 400 invalid_scope
    const escalationRes = await requestJson("/dev-idp/oauth2/token", {
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: subjectToken,
        actor_token: "agent:choreo-integrator-bot",
        resource: identityConfig.mcpAudience,
        scope: "orders:read refunds:execute"
      }
    });
    expect(escalationRes.status).toBe(400);
    expect(escalationRes.body.error).toBe("invalid_scope");

    // 3. Unauthorized actor violating may_act is rejected with 400 unauthorized_client
    const unauthorizedActorRes = await requestJson("/dev-idp/oauth2/token", {
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: subjectToken,
        actor_token: "agent:unlisted-rogue-bot",
        resource: identityConfig.mcpAudience,
        scope: "orders:read"
      }
    });
    expect(unauthorizedActorRes.status).toBe(400);
    expect(unauthorizedActorRes.body.error).toBe("unauthorized_client");
  });

  it("executes Live Attack Lab forged tokens and key rotation against the real Express middleware", async () => {
    const cases: ReadonlyArray<{
      readonly fault: Record<string, unknown>;
      readonly expectedStatus: number;
      readonly expectedError?: string;
    }> = [
      {
        fault: { id: "jwt_alg_downgrade", algorithm: "none" },
        expectedStatus: 401,
        expectedError: "invalid_algorithm"
      },
      {
        fault: { id: "jwt_alg_downgrade", algorithm: "HS256" },
        expectedStatus: 401,
        expectedError: "invalid_algorithm"
      },
      {
        fault: { id: "jwks_kid_miss", resolution: "reject_unknown_kid" },
        expectedStatus: 401,
        expectedError: "unknown_signing_key"
      },
      {
        fault: { id: "jwks_kid_miss", resolution: "recover_rotated_key" },
        expectedStatus: 200
      },
      {
        fault: { id: "aud_iss_spoof", spoofTarget: "aud" },
        expectedStatus: 401,
        expectedError: "invalid_audience"
      },
      {
        fault: { id: "aud_iss_spoof", spoofTarget: "iss" },
        expectedStatus: 401,
        expectedError: "invalid_issuer"
      },
      {
        fault: { id: "expired_token_skew", skewSeconds: 185 },
        expectedStatus: 401,
        expectedError: "token_expired"
      }
    ];

    for (const testCase of cases) {
      const minted = await requestJson("/dev-idp/admin/mint-fault-token", {
        method: "POST",
        body: { fault: testCase.fault }
      });
      expect(minted.status).toBe(200);
      const token = typeof minted.body.token === "string" ? minted.body.token : "";

      const apiRes = await requestJson("/api/v1/user/profile", { token });
      expect(apiRes.status).toBe(testCase.expectedStatus);
      if (testCase.expectedError) {
        expect(apiRes.body.error).toBe(testCase.expectedError);
      }
    }

    // Trigger live key rotation and verify new tokens continue to validate cleanly
    const rotated = await requestJson("/dev-idp/admin/rotate-keys", { method: "POST" });
    expect(rotated.status).toBe(200);
    expect(rotated.body.rotated).toBe(true);

    const nominalAfterRotate = await requestJson("/dev-idp/admin/mint-fault-token", {
      method: "POST",
      body: { fault: { id: "none" } }
    });
    const freshToken =
      typeof nominalAfterRotate.body.token === "string"
        ? nominalAfterRotate.body.token
        : "";
    const verifyAfterRotate = await requestJson("/api/v1/user/profile", {
      token: freshToken
    });
    expect(verifyAfterRotate.status).toBe(200);
  });
});
