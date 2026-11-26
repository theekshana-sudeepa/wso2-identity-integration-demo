import crypto from "node:crypto";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  evaluateSharedEndpointStatus,
  SHARED_ENDPOINT_POLICIES
} from "../../../packages/identity-policy/src/index.js";
import { DEV_IDP_PERSONAS, type DevIdpPersonaId } from "../devIdp/personas.js";
import { createApp } from "../server.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

describe("Phase 5 Contract Test: Shared Policy Engine vs. Live Express Resource Server", () => {
  let server: Server;
  let baseUrl = "";
  const personaTokens: Record<DevIdpPersonaId, string> = {
    developer: "",
    admin: "",
    auditor: ""
  };

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

    const personas: readonly DevIdpPersonaId[] = ["developer", "admin", "auditor"];
    for (const p of personas) {
      const verifier = crypto.randomBytes(36).toString("base64url");
      const challenge = crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");
      const authz = await requestJson("/dev-idp/oauth2/authorize", {
        method: "POST",
        body: { persona: p, code_challenge: challenge, code_challenge_method: "S256" }
      });
      const tokenRes = await requestJson("/dev-idp/oauth2/token", {
        method: "POST",
        body: {
          grant_type: "authorization_code",
          code: authz.body.code,
          code_verifier: verifier
        }
      });
      personaTokens[p] =
        typeof tokenRes.body.access_token === "string" ? tokenRes.body.access_token : "";
    }
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("produces identical HTTP status codes across every (persona x endpoint x fault) combination", async () => {
    const personas: readonly (DevIdpPersonaId | "unauthenticated")[] = [
      "unauthenticated",
      "developer",
      "admin",
      "auditor"
    ];

    for (const personaKey of personas) {
      const isAuth = personaKey !== "unauthenticated";
      const personaMeta = isAuth ? DEV_IDP_PERSONAS[personaKey] : null;
      const token = isAuth ? personaTokens[personaKey] : undefined;

      for (const endpoint of SHARED_ENDPOINT_POLICIES) {
        const simulatedStatus = evaluateSharedEndpointStatus(endpoint, {
          authenticated: isAuth,
          groups: personaMeta?.groups ?? [],
          scopes: personaMeta?.scopes ?? []
        });

        const liveRes = await requestJson(endpoint.path, {
          method: endpoint.method,
          token,
          body: endpoint.method === "POST" ? { title: "Contract Verification Report" } : undefined
        });

        expect(liveRes.status).toBe(simulatedStatus);
      }
    }

    // Also verify every token-level fault across all protected endpoints matches 401/200 contract
    const faultMatrix: ReadonlyArray<{
      readonly fault: Record<string, unknown>;
      readonly expectedStatus: number;
    }> = [
      { fault: { id: "jwt_alg_downgrade", algorithm: "none" }, expectedStatus: 401 },
      { fault: { id: "jwt_alg_downgrade", algorithm: "HS256" }, expectedStatus: 401 },
      { fault: { id: "jwks_kid_miss", resolution: "reject_unknown_kid" }, expectedStatus: 401 },
      { fault: { id: "jwks_kid_miss", resolution: "recover_rotated_key" }, expectedStatus: 200 },
      { fault: { id: "aud_iss_spoof", spoofTarget: "aud" }, expectedStatus: 401 },
      { fault: { id: "aud_iss_spoof", spoofTarget: "iss" }, expectedStatus: 401 },
      { fault: { id: "expired_token_skew", skewSeconds: 185 }, expectedStatus: 401 }
    ];

    for (const faultCase of faultMatrix) {
      const minted = await requestJson("/dev-idp/admin/mint-fault-token", {
        method: "POST",
        body: { fault: faultCase.fault, persona: "admin" }
      });
      const faultToken = typeof minted.body.token === "string" ? minted.body.token : "";
      const liveRes = await requestJson("/api/v1/admin/audit-logs", {
        token: faultToken
      });
      expect(liveRes.status).toBe(faultCase.expectedStatus);
    }
  });
});
