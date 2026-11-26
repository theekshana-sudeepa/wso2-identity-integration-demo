import crypto from "node:crypto";
import type { Server } from "node:http";
import jwt, { type JwtHeader, type SigningKeyCallback } from "jsonwebtoken";
import jwksRsa from "jwks-rsa";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AGENT_TOKEN_MAX_TTL_SECONDS } from "../config/agentPolicy.js";
import { createAuthMiddleware } from "../middleware/authMiddleware.js";
import { createApp } from "../server.js";

const TEST_ISSUER = "https://idp.choreo-labs.test/oauth2/token";
const TEST_AUDIENCE = "wso2-api-demo";
const TEST_MCP_AUDIENCE = "http://localhost:5050/api/mcp";
const ACTIVE_KID = "test-rs256-kid-2026";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertAsciiChallenge(header: string | null): string {
  expect(header).not.toBeNull();
  const value = header ?? "";
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    expect(code).toBeGreaterThanOrEqual(0x20);
    expect(code).toBeLessThanOrEqual(0x7e);
  }
  return value;
}

describe("Express Resource Server Security & RFC 8693 MCP Guard", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });

  const { privateKey: roguePrivateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });

  let server: Server;
  let baseUrl = "";

  const keyResolver = (header: JwtHeader, callback: SigningKeyCallback): void => {
    if (header.kid === ACTIVE_KID) {
      callback(null, publicKey);
      return;
    }
    callback(
      new jwksRsa.SigningKeyNotFoundError(
        `Unable to find a signing key that matches '${header.kid ?? "missing"}'`
      )
    );
  };

  function signRs256(
    payload: Record<string, unknown>,
    options?: {
      readonly kid?: string;
      readonly expiresIn?: number;
      readonly signingKey?: string;
    }
  ): string {
    return jwt.sign(payload, options?.signingKey ?? privateKey, {
      algorithm: "RS256",
      keyid: options?.kid ?? ACTIVE_KID,
      ...(typeof payload.iss === "string" ? {} : { issuer: TEST_ISSUER }),
      ...(typeof payload.aud === "string" || Array.isArray(payload.aud)
        ? {}
        : { audience: TEST_AUDIENCE }),
      ...(options?.expiresIn !== undefined ? { expiresIn: options.expiresIn } : {})
    });
  }

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
    const authMiddleware = createAuthMiddleware({
      issuer: TEST_ISSUER,
      audience: TEST_AUDIENCE,
      clockToleranceSec: 5,
      keyResolver
    });
    const mcpAuthMiddleware = createAuthMiddleware({
      issuer: TEST_ISSUER,
      audience: TEST_MCP_AUDIENCE,
      clockToleranceSec: 5,
      keyResolver
    });
    const app = createApp({ authMiddleware, mcpAuthMiddleware });
    await new Promise<void>((resolve, reject) => {
      server = app.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        if (!addr || typeof addr === "string") {
          reject(new Error("Expected TCP AddressInfo from ephemeral test server"));
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

  it("rejects alg:none unsigned JWTs via strict RS256 pinning (RFC 8725)", async () => {
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({
        sub: "usr_attacker",
        iss: TEST_ISSUER,
        aud: TEST_AUDIENCE,
        groups: ["admin"],
        exp: Math.floor(Date.now() / 1000) + 300
      })
    ).toString("base64url");
    const unsignedToken = `${header}.${payload}.`;

    const res = await requestJson("/api/v1/user/profile", { token: unsignedToken });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("invalid_algorithm");
    expect(assertAsciiChallenge(res.headers.get("www-authenticate"))).toContain('error="invalid_token"');
  });

  it("rejects HS256 key-confusion tokens signed with the public RSA PEM", async () => {
    const hs256Token = jwt.sign(
      {
        sub: "usr_attacker",
        groups: ["admin"],
        iss: TEST_ISSUER,
        aud: TEST_AUDIENCE
      },
      publicKey,
      { algorithm: "HS256", keyid: ACTIVE_KID, expiresIn: 300 }
    );

    const res = await requestJson("/api/v1/user/profile", { token: hs256Token });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("invalid_algorithm");
  });

  it("rejects expired RS256 tokens beyond clockTolerance (RFC 7519)", async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const expiredToken = signRs256({
      sub: "usr_dev",
      iat: nowSec - 600,
      exp: nowSec - 120
    });

    const res = await requestJson("/api/v1/user/profile", { token: expiredToken });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("token_expired");
    expect(assertAsciiChallenge(res.headers.get("www-authenticate"))).toContain('error="invalid_token"');
  });

  it("rejects tokens with future nbf beyond clockTolerance (RFC 7519 §4.1.5)", async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const futureNbfToken = signRs256({
      sub: "usr_dev",
      nbf: nowSec + 120,
      exp: nowSec + 600
    });

    const res = await requestJson("/api/v1/user/profile", { token: futureNbfToken });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("token_not_yet_valid");
  });

  it("rejects RS256 tokens with invalid cryptographic signature", async () => {
    const forgedToken = signRs256(
      { sub: "usr_dev" },
      { kid: ACTIVE_KID, expiresIn: 300, signingKey: roguePrivateKey }
    );

    const res = await requestJson("/api/v1/user/profile", { token: forgedToken });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("invalid_signature");
  });

  it("rejects malformed non-3-segment or non-JSON tokens cleanly", async () => {
    for (const badToken of ["not-a-jwt", "abc.def", "!!!.@@@.###"]) {
      const res = await requestJson("/api/v1/user/profile", { token: badToken });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("malformed_token");
      assertAsciiChallenge(res.headers.get("www-authenticate"));
    }
  });

  it("rejects valid RS256 signatures with spoofed audience or issuer separately", async () => {
    const wrongAudToken = signRs256(
      {
        sub: "usr_dev",
        aud: "other-tenant-api"
      },
      { expiresIn: 300 }
    );
    const wrongIssToken = signRs256(
      {
        sub: "usr_dev",
        iss: "https://evil-idp.example/oauth2/token"
      },
      { expiresIn: 300 }
    );

    const audRes = await requestJson("/api/v1/user/profile", { token: wrongAudToken });
    expect(audRes.status).toBe(401);
    expect(audRes.body.error).toBe("invalid_audience");

    const issRes = await requestJson("/api/v1/user/profile", { token: wrongIssToken });
    expect(issRes.status).toBe(401);
    expect(issRes.body.error).toBe("invalid_issuer");
  });

  it("rejects unknown JWKS kid with 401 fail-closed", async () => {
    const unknownKidToken = signRs256(
      { sub: "usr_dev" },
      { kid: "revoked-unknown-kid", expiresIn: 300 }
    );

    const res = await requestJson("/api/v1/user/profile", { token: unknownKidToken });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("unknown_signing_key");
  });

  it("classifies jwks-rsa JwksRateLimitError as jwks_rate_limited", async () => {
    const rateLimitedMiddleware = createAuthMiddleware({
      issuer: TEST_ISSUER,
      audience: TEST_AUDIENCE,
      clockToleranceSec: 5,
      keyResolver: (_header, callback) => {
        callback(new jwksRsa.JwksRateLimitError("JWKS endpoint rate limit exceeded"));
      }
    });
    const limitedApp = createApp({ authMiddleware: rateLimitedMiddleware });
    let limitedServer: Server | undefined;
    try {
      const limitedBaseUrl = await new Promise<string>((resolve, reject) => {
        limitedServer = limitedApp.listen(0, "127.0.0.1", () => {
          const addr = limitedServer?.address();
          if (!addr || typeof addr === "string") {
            reject(new Error("Expected TCP AddressInfo"));
            return;
          }
          resolve(`http://127.0.0.1:${addr.port}`);
        });
      });

      const validToken = signRs256({ sub: "usr_dev" }, { expiresIn: 300 });
      const res = await fetch(`${limitedBaseUrl}/api/v1/user/profile`, {
        headers: { Authorization: `Bearer ${validToken}` }
      });
      const parsed: unknown = await res.json();
      expect(res.status).toBe(401);
      expect(isRecord(parsed) ? parsed.error : null).toBe("jwks_rate_limited");
    } finally {
      if (limitedServer) {
        await new Promise<void>((resolve, reject) => {
          limitedServer?.close((err) => (err ? reject(err) : resolve()));
        });
      }
    }
  });

  it("emits compliant RFC 6750 WWW-Authenticate headers on 401/403 responses", async () => {
    const missingAuth = await requestJson("/api/v1/user/profile");
    expect(missingAuth.status).toBe(401);
    expect(assertAsciiChallenge(missingAuth.headers.get("www-authenticate"))).toBe(
      'Bearer realm="choreo-demo"'
    );

    const devToken = signRs256(
      {
        sub: "usr_dev",
        username: "dev@example.com",
        groups: ["developer"],
        scope: "openid profile read:profile"
      },
      { expiresIn: 300 }
    );

    const devReportDeny = await requestJson("/api/v1/reports", {
      method: "POST",
      token: devToken,
      body: { title: "Unauthorized Report" }
    });
    expect(devReportDeny.status).toBe(403);
    const scopeChallenge = assertAsciiChallenge(devReportDeny.headers.get("www-authenticate"));
    expect(scopeChallenge).toContain('error="insufficient_scope"');
    expect(scopeChallenge).toContain('scope="write:reports"');
  });

  it("enforces requireRoles and requireScopes accurately on protected routes", async () => {
    const devToken = signRs256(
      {
        sub: "usr_dev",
        username: "dev@example.com",
        groups: ["developer"],
        scope: "openid profile read:profile"
      },
      { expiresIn: 300 }
    );

    const adminToken = signRs256(
      {
        sub: "usr_admin",
        username: "admin@example.com",
        groups: ["admin", "developer"],
        scope: "openid profile write:reports admin:audit"
      },
      { expiresIn: 300 }
    );

    const devProfile = await requestJson("/api/v1/user/profile", { token: devToken });
    expect(devProfile.status).toBe(200);

    const devAdminDeny = await requestJson("/api/v1/admin/audit-logs", { token: devToken });
    expect(devAdminDeny.status).toBe(403);
    expect(devAdminDeny.body.error).toBe("forbidden");
    expect(assertAsciiChallenge(devAdminDeny.headers.get("www-authenticate"))).toContain(
      'error="insufficient_scope"'
    );

    const adminAllow = await requestJson("/api/v1/admin/audit-logs", { token: adminToken });
    expect(adminAllow.status).toBe(200);

    const devReportDeny = await requestJson("/api/v1/reports", {
      method: "POST",
      token: devToken,
      body: { title: "Unauthorized Report" }
    });
    expect(devReportDeny.status).toBe(403);
    expect(devReportDeny.body.error).toBe("insufficient_scope");

    const adminReportAllow = await requestJson("/api/v1/reports", {
      method: "POST",
      token: adminToken,
      body: { title: "Quarterly Compliance Audit" }
    });
    expect(adminReportAllow.status).toBe(201);
  });

  it("prevents token passthrough between Human API audience and MCP Gateway audience", async () => {
    const nowSec = Math.floor(Date.now() / 1000);

    // Human API audience token (even with valid act + 60s TTL) rejected at MCP gateway
    const humanAudAgentToken = signRs256({
      sub: "usr_admin",
      aud: TEST_AUDIENCE,
      act: { sub: "agent:choreo-integrator-bot", client_id: "choreo-mcp-agent-v1" },
      scope: "orders:read",
      iat: nowSec,
      exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
    });
    const mcpReject = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: humanAudAgentToken,
      body: { tool: "get_order_status" }
    });
    expect(mcpReject.status).toBe(401);
    expect(mcpReject.body.error).toBe("invalid_audience");

    // MCP audience token rejected at Human API
    const mcpAudToken = signRs256({
      sub: "usr_admin",
      aud: TEST_MCP_AUDIENCE,
      act: { sub: "agent:choreo-integrator-bot", client_id: "choreo-mcp-agent-v1" },
      scope: "orders:read",
      iat: nowSec,
      exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
    });
    const apiReject = await requestJson("/api/v1/user/profile", { token: mcpAudToken });
    expect(apiReject.status).toBe(401);
    expect(apiReject.body.error).toBe("invalid_audience");
  });

  it("enforces RFC 8693 AI Agent Delegation, 60s TTL boundary, nested act chains, and scope attenuation", async () => {
    const nowSec = Math.floor(Date.now() / 1000);

    // 1. Direct human token without act claim must be rejected
    const humanToken = signRs256({
      sub: "usr_admin",
      aud: TEST_MCP_AUDIENCE,
      groups: ["admin"],
      scope: "orders:read refunds:execute",
      iat: nowSec,
      exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
    });
    const noActRes = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: humanToken,
      body: { tool: "get_order_status" }
    });
    expect(noActRes.status).toBe(403);
    expect(noActRes.body.error).toBe("delegation_required");

    // 2. Delegated token exceeding 60s TTL boundary (61s) must be rejected
    const overTtlAgentToken = signRs256({
      sub: "usr_admin",
      aud: TEST_MCP_AUDIENCE,
      act: { sub: "agent:choreo-integrator-bot", client_id: "choreo-mcp-agent-v1" },
      scope: "orders:read",
      iat: nowSec,
      exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS + 1
    });
    const ttlRes = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: overTtlAgentToken,
      body: { tool: "get_order_status" }
    });
    expect(ttlRes.status).toBe(403);
    expect(ttlRes.body.error).toBe("delegation_ttl_exceeded");

    // 3. Valid depth-2 nested act chain with exact 60s TTL succeeds
    const depth2Token = signRs256({
      sub: "usr_admin",
      aud: TEST_MCP_AUDIENCE,
      act: {
        sub: "agent:a",
        client_id: "mcp-sub-agent",
        act: {
          sub: "agent:orchestrator",
          client_id: "choreo-mcp-orchestrator"
        }
      },
      scope: "orders:read",
      iat: nowSec,
      exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
    });
    const depth2Res = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: depth2Token,
      body: { tool: "get_order_status", arguments: { orderId: "ORD-2026-88412" } }
    });
    expect(depth2Res.status).toBe(200);
    expect(depth2Res.body.status).toBe("ALLOWED");

    // 4. Depth-3 nested act chain must be rejected
    const depth3Token = signRs256({
      sub: "usr_admin",
      aud: TEST_MCP_AUDIENCE,
      act: {
        sub: "agent:a",
        act: {
          sub: "agent:b",
          act: { sub: "agent:c" }
        }
      },
      scope: "orders:read",
      iat: nowSec,
      exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
    });
    const depth3Res = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: depth3Token,
      body: { tool: "get_order_status" }
    });
    expect(depth3Res.status).toBe(403);
    expect(depth3Res.body.error).toBe("delegation_chain_too_deep");

    // 5. Nested act cycle (agent:a -> agent:a) must be rejected
    const cycleToken = signRs256({
      sub: "usr_admin",
      aud: TEST_MCP_AUDIENCE,
      act: {
        sub: "agent:a",
        act: { sub: "agent:a" }
      },
      scope: "orders:read",
      iat: nowSec,
      exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
    });
    const cycleRes = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: cycleToken,
      body: { tool: "get_order_status" }
    });
    expect(cycleRes.status).toBe(403);
    expect(cycleRes.body.error).toBe("delegation_cycle_detected");

    // 6. Actor sub equal to token sub must be rejected as cycle
    const selfCycleToken = signRs256({
      sub: "agent:a",
      aud: TEST_MCP_AUDIENCE,
      act: { sub: "agent:a" },
      scope: "orders:read",
      iat: nowSec,
      exp: nowSec + AGENT_TOKEN_MAX_TTL_SECONDS
    });
    const selfCycleRes = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: selfCycleToken,
      body: { tool: "get_order_status" }
    });
    expect(selfCycleRes.status).toBe(403);
    expect(selfCycleRes.body.error).toBe("delegation_cycle_detected");

    // 7. Scope escalation and step-up checks + RFC 6750 insufficient_scope header
    const escalationRes = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: depth2Token,
      body: { tool: "issue_refund", arguments: { orderId: "ORD-2026-88412" } }
    });
    expect(escalationRes.status).toBe(403);
    expect(escalationRes.body.error).toBe("scope_escalation_blocked");
    const mcpChallenge = assertAsciiChallenge(escalationRes.headers.get("www-authenticate"));
    expect(mcpChallenge).toContain('error="insufficient_scope"');
    expect(mcpChallenge).toContain('scope="refunds:execute"');

    const stepUpRes = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: depth2Token,
      body: { tool: "export_all_users" }
    });
    expect(stepUpRes.status).toBe(403);
    expect(stepUpRes.body.error).toBe("human_approval_required");
  });
});
