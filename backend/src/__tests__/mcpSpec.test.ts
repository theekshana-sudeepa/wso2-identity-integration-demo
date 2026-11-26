import crypto from "node:crypto";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import identityConfig from "../config/identityConfig.js";
import { mcpAuditLog } from "../mcp/auditLog.js";
import { createApp } from "../server.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

describe("Phase 3: MCP JSON-RPC 2.0, RFC 9728 Protected Resource Metadata, RFC 8707 & Audit Log", () => {
  let server: Server;
  let baseUrl = "";
  let delegatedAgentJwt = "";

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
    mcpAuditLog.clear();
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
    const subjectToken =
      typeof tokenRes.body.access_token === "string" ? tokenRes.body.access_token : "";

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
    delegatedAgentJwt =
      typeof oboRes.body.access_token === "string" ? oboRes.body.access_token : "";
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("serves RFC 9728 Protected Resource Metadata and includes resource_metadata in MCP 401 WWW-Authenticate", async () => {
    const metadataRes = await requestJson("/.well-known/oauth-protected-resource");
    expect(metadataRes.status).toBe(200);
    expect(metadataRes.body.resource).toBe(identityConfig.mcpAudience);
    expect(metadataRes.body.authorization_servers).toEqual([identityConfig.issuer]);
    expect(metadataRes.body.scopes_supported).toEqual([
      "orders:read",
      "refunds:execute",
      "users:export"
    ]);
    expect(metadataRes.body.bearer_methods_supported).toEqual(["header"]);

    const unauthMcp = await requestJson("/api/mcp", {
      method: "POST",
      body: { jsonrpc: "2.0", id: 1, method: "tools/list" }
    });
    expect(unauthMcp.status).toBe(401);
    const challenge = unauthMcp.headers.get("www-authenticate") ?? "";
    expect(challenge).toContain('resource_metadata="');
    expect(challenge).toContain("/.well-known/oauth-protected-resource");
  });

  it("enforces RFC 8707 Resource Indicators on token exchange", async () => {
    const verifier = crypto.randomBytes(36).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");
    const authz = await requestJson("/dev-idp/oauth2/authorize", {
      method: "POST",
      body: {
        persona: "developer",
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

    const badResourceRes = await requestJson("/dev-idp/oauth2/token", {
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: tokenRes.body.access_token,
        actor_token: "agent:choreo-integrator-bot",
        resource: "https://unregistered-downstream.example/api",
        scope: "orders:read"
      }
    });
    expect(badResourceRes.status).toBe(400);
    expect(badResourceRes.body.error).toBe("invalid_target");
  });

  it("handles JSON-RPC 2.0 tools/list and tools/call with declarative inputSchema validation and records audit timeline", async () => {
    // 1. tools/list returns declarative tool definitions and inputSchemas
    const listRes = await requestJson("/api/mcp", {
      method: "POST",
      token: delegatedAgentJwt,
      body: {
        jsonrpc: "2.0",
        id: 101,
        method: "tools/list"
      }
    });
    expect(listRes.status).toBe(200);
    expect(listRes.body.jsonrpc).toBe("2.0");
    expect(listRes.body.id).toBe(101);
    const resultObj = isRecord(listRes.body.result) ? listRes.body.result : {};
    const tools = Array.isArray(resultObj.tools) ? resultObj.tools : [];
    expect(tools).toHaveLength(3);

    // 2. tools/call with invalid arguments fails inputSchema validation (-32602)
    const invalidArgsRes = await requestJson("/api/mcp", {
      method: "POST",
      token: delegatedAgentJwt,
      body: {
        jsonrpc: "2.0",
        id: 102,
        method: "tools/call",
        params: {
          name: "get_order_status",
          arguments: { orderId: "x" } // minLength is 3
        }
      }
    });
    expect(invalidArgsRes.status).toBe(400);
    expect(invalidArgsRes.body.error).toBe("invalid_tool_arguments");

    // 3. tools/call get_order_status succeeds
    const callAllow = await requestJson("/api/mcp", {
      method: "POST",
      token: delegatedAgentJwt,
      body: {
        jsonrpc: "2.0",
        id: 103,
        method: "tools/call",
        params: {
          name: "get_order_status",
          arguments: { orderId: "ORD-2026-99104" }
        }
      }
    });
    expect(callAllow.status).toBe(200);
    expect(callAllow.body.jsonrpc).toBe("2.0");
    expect(callAllow.body.id).toBe(103);
    expect(callAllow.body.status).toBe("ALLOWED");

    // 4. tools/call issue_refund is denied and recorded in audit log
    const callDeny = await requestJson("/api/mcp", {
      method: "POST",
      token: delegatedAgentJwt,
      body: {
        jsonrpc: "2.0",
        id: 104,
        method: "tools/call",
        params: {
          name: "issue_refund",
          arguments: { orderId: "ORD-2026-99104", amountUsd: 120 }
        }
      }
    });
    expect(callDeny.status).toBe(403);
    expect(callDeny.body.error).toBe("scope_escalation_blocked");

    // 5. GET /api/mcp/audit returns the recorded agent activity timeline
    const auditRes = await requestJson("/api/mcp/audit");
    expect(auditRes.status).toBe(200);
    const entries = Array.isArray(auditRes.body.entries) ? auditRes.body.entries : [];
    expect(entries.length).toBeGreaterThanOrEqual(2);
    const firstEntry = isRecord(entries[0]) ? entries[0] : {};
    expect(firstEntry.tool).toBe("issue_refund");
    expect(firstEntry.decision).toBe("DENIED");
    expect(firstEntry.actorSub).toBe("agent:choreo-integrator-bot");
  });
});
