import crypto from "node:crypto";
import type { Server } from "node:http";
import jwt, { type JwtHeader, type SigningKeyCallback } from "jsonwebtoken";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAuthMiddleware } from "../middleware/authMiddleware.js";
import { createApp } from "../server.js";

const TEST_ISSUER = "https://idp.choreo-labs.test/oauth2/token";
const TEST_AUDIENCE = "wso2-api-demo";
const ACTIVE_KID = "test-rs256-kid-2026";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

describe("Express Resource Server Security & RFC 8693 MCP Guard", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
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
    callback(new Error(`Unable to find a signing key that matches '${header.kid ?? "missing"}'`));
  };

  function signRs256(
    payload: Record<string, unknown>,
    options?: { readonly kid?: string; readonly expiresIn?: number }
  ): string {
    return jwt.sign(payload, privateKey, {
      algorithm: "RS256",
      keyid: options?.kid ?? ACTIVE_KID,
      ...(typeof payload.iss === "string" ? {} : { issuer: TEST_ISSUER }),
      ...(typeof payload.aud === "string" ? {} : { audience: TEST_AUDIENCE }),
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
  ): Promise<{ readonly status: number; readonly body: Record<string, unknown> }> {
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
    const app = createApp({ authMiddleware });
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
  });

  it("rejects valid RS256 signatures with spoofed audience or issuer", async () => {
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
    expect(audRes.body.error).toBe("invalid_claims");

    const issRes = await requestJson("/api/v1/user/profile", { token: wrongIssToken });
    expect(issRes.status).toBe(401);
    expect(issRes.body.error).toBe("invalid_claims");
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

  it("enforces RFC 8693 AI Agent Delegation & blocks scope escalation on POST /api/mcp/tools/call", async () => {
    const nowSec = Math.floor(Date.now() / 1000);

    // 1. Direct human token without act claim must be rejected
    const humanToken = signRs256(
      {
        sub: "usr_admin",
        groups: ["admin"],
        scope: "orders:read refunds:execute",
        iat: nowSec,
        exp: nowSec + 60
      }
    );
    const noActRes = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: humanToken,
      body: { tool: "get_order_status" }
    });
    expect(noActRes.status).toBe(403);
    expect(noActRes.body.error).toBe("delegation_required");

    // 2. Delegated token exceeding short-TTL window (> 300s) must be rejected
    const longLivedAgentToken = signRs256({
      sub: "usr_admin",
      act: { sub: "agent:choreo-integrator-bot", client_id: "choreo-mcp-agent-v1" },
      scope: "orders:read",
      iat: nowSec,
      exp: nowSec + 3600
    });
    const ttlRes = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: longLivedAgentToken,
      body: { tool: "get_order_status" }
    });
    expect(ttlRes.status).toBe(403);
    expect(ttlRes.body.error).toBe("delegation_ttl_exceeded");

    // 3. Valid short-lived (60s) down-scoped delegated token
    const delegatedToken = signRs256({
      sub: "usr_admin",
      act: { sub: "agent:choreo-integrator-bot", client_id: "choreo-mcp-agent-v1" },
      scope: "orders:read",
      iat: nowSec,
      exp: nowSec + 60
    });

    const allowedRes = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: delegatedToken,
      body: { tool: "get_order_status", arguments: { orderId: "ORD-2026-88412" } }
    });
    expect(allowedRes.status).toBe(200);
    expect(allowedRes.body.status).toBe("ALLOWED");

    const escalationRes = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: delegatedToken,
      body: { tool: "issue_refund", arguments: { orderId: "ORD-2026-88412" } }
    });
    expect(escalationRes.status).toBe(403);
    expect(escalationRes.body.error).toBe("scope_escalation_blocked");

    const stepUpRes = await requestJson("/api/mcp/tools/call", {
      method: "POST",
      token: delegatedToken,
      body: { tool: "export_all_users" }
    });
    expect(stepUpRes.status).toBe(403);
    expect(stepUpRes.body.error).toBe("human_approval_required");
  });
});
