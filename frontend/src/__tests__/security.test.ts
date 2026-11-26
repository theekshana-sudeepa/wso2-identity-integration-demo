import { describe, expect, it } from "vitest";
import { AGENT_TOKEN_MAX_TTL_SECONDS } from "../lib/agentPolicy";
import {
  API_ENDPOINTS,
  evaluateEndpointAccess,
  simulateMcpToolCall,
  simulateRbacPolicyCall
} from "../lib/apiClient";
import {
  base64UrlEncodeJson,
  createDelegatedAgentSession,
  createDemoSession,
  decodeJwt,
  generateCodeChallenge,
  generateLivePkceTelemetry,
  getOidcConfig,
  parseJwtClaims
} from "../lib/pkce";
import { evaluateFaultScenario, MCP_TOOLS } from "../lib/securityLab";

describe("Frontend Identity Security Engine", () => {
  it("computes the exact RFC 7636 Appendix B S256 PKCE code_challenge", async () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const computed = await generateCodeChallenge(verifier);
    expect(computed).toBe(expectedChallenge);
  });

  it("generates 384-bit Base64URL Web Crypto PKCE telemetry with matching digest", async () => {
    const telemetry = await generateLivePkceTelemetry();
    expect(telemetry.challengeMethod).toBe("S256");
    expect(telemetry.entropyBits).toBe(384);
    expect(telemetry.codeVerifier).toMatch(/^[A-Za-z0-9_-]{64}$/);
    expect(telemetry.state).toMatch(/^[A-Za-z0-9_-]{32}$/);

    const recomputed = await generateCodeChallenge(telemetry.codeVerifier);
    expect(recomputed).toBe(telemetry.codeChallenge);
  });

  it("handles JWT decoding & claims parsing edge cases safely", () => {
    expect(decodeJwt("")).toBeNull();
    expect(decodeJwt("not-a-jwt")).toBeNull();
    expect(decodeJwt("!!!.@@@.###")).toBeNull();

    const header = base64UrlEncodeJson({ alg: "RS256", typ: "at+jwt", kid: "kid-1" });
    const payload = base64UrlEncodeJson({
      sub: "usr_edge_case",
      preferred_username: "architect@choreo.dev",
      roles: "Admin, integration-lead",
      aud: ["api-a", "api-b"],
      scope: "openid orders:read write:reports",
      act: {
        sub: "agent:choreo-integrator-bot",
        client_id: "choreo-mcp-agent-v1"
      },
      iat: 1700000000,
      exp: 1700000060
    });

    const decoded = decodeJwt(`${header}.${payload}.sig`);
    expect(decoded).not.toBeNull();
    if (!decoded) return;

    const parsed = parseJwtClaims(decoded);
    expect(parsed.username).toBe("architect@choreo.dev");
    expect(parsed.groups).toEqual(["Admin", "integration-lead"]);
    expect(parsed.isAdmin).toBe(true);
    expect(parsed.hasWriteReports).toBe(true);
    expect(parsed.audience).toBe("api-a, api-b");
    expect(parsed.actor?.sub).toBe("agent:choreo-integrator-bot");
  });

  it("evaluates RBAC policy matrix and dry-run calls for Developer vs Admin and Attack Lab faults", () => {
    const config = getOidcConfig("wso2is");
    const devSession = createDemoSession("user", config);
    const devDecoded = decodeJwt(devSession.accessToken);
    expect(devDecoded).not.toBeNull();
    const devClaims = devDecoded ? parseJwtClaims(devDecoded) : null;

    const adminSession = createDemoSession("admin", config);
    const adminDecoded = decodeJwt(adminSession.accessToken);
    expect(adminDecoded).not.toBeNull();
    const adminClaims = adminDecoded ? parseJwtClaims(adminDecoded) : null;

    const publicSpec = API_ENDPOINTS[0];
    const adminSpec = API_ENDPOINTS[3];
    const reportSpec = API_ENDPOINTS[4];

    expect(evaluateEndpointAccess(publicSpec, null)).toBe("allowed");
    expect(evaluateEndpointAccess(adminSpec, null)).toBe("unauthenticated");
    expect(evaluateEndpointAccess(adminSpec, devClaims)).toBe("forbidden");
    expect(evaluateEndpointAccess(reportSpec, devClaims)).toBe("forbidden");
    expect(evaluateEndpointAccess(adminSpec, adminClaims)).toBe("allowed");
    expect(evaluateEndpointAccess(reportSpec, adminClaims)).toBe("allowed");

    const devAdminCall = simulateRbacPolicyCall(adminSpec, config, devSession, devClaims);
    expect(devAdminCall.status).toBe(403);
    expect(devAdminCall.ok).toBe(false);

    const adminReportCall = simulateRbacPolicyCall(reportSpec, config, adminSession, adminClaims);
    expect(adminReportCall.status).toBe(201);
    expect(adminReportCall.ok).toBe(true);

    // Active Attack Lab fault must override and fail closed with 401
    const algNoneCall = simulateRbacPolicyCall(adminSpec, config, adminSession, adminClaims, {
      id: "jwt_alg_downgrade",
      algorithm: "none"
    });
    expect(algNoneCall.status).toBe(401);
    expect(algNoneCall.defenseTrace?.rfc).toContain("RFC 8725");

    // Rotated key recovery branch succeeds cleanly
    const kidRecovery = evaluateFaultScenario(
      { id: "jwks_kid_miss", resolution: "recover_rotated_key" },
      { config, claims: adminClaims, pkceTelemetry: null }
    );
    expect(kidRecovery.httpStatus).toBe(200);
    expect(kidRecovery.isBlocked).toBe(false);
  });

  it("down-scopes human admin token via RFC 8693 OBO and enforces MCP tool authorization", () => {
    const config = getOidcConfig("asgardeo");
    const adminSession = createDemoSession("admin", config);
    const adminDecoded = decodeJwt(adminSession.accessToken);
    const adminClaims = adminDecoded ? parseJwtClaims(adminDecoded) : null;

    const fixedNow = 1_800_000_000;
    const obo = createDelegatedAgentSession(adminClaims, config, fixedNow);

    expect(obo.ttlSeconds).toBe(AGENT_TOKEN_MAX_TTL_SECONDS);
    expect(obo.expiresAtSec - obo.issuedAtSec).toBe(AGENT_TOKEN_MAX_TTL_SECONDS);
    expect(obo.audience).toBe(config.mcpAudience);
    expect(obo.audience).not.toBe(config.audience);
    expect(obo.actor.sub).toBe("agent:choreo-integrator-bot");
    expect(obo.grantedScopes).toEqual(["orders:read"]);
    expect(obo.strippedScopes).toContain("admin:write");
    expect(obo.strippedScopes).toContain("refunds:execute");

    const orderTool = MCP_TOOLS[0];
    const refundTool = MCP_TOOLS[1];
    const exportTool = MCP_TOOLS[2];

    const allowRes = simulateMcpToolCall(orderTool, obo, config, undefined, fixedNow + 10);
    expect(allowRes.status).toBe(200);
    expect(allowRes.ok).toBe(true);

    const refundRes = simulateMcpToolCall(refundTool, obo, config, undefined, fixedNow + 10);
    expect(refundRes.status).toBe(403);
    expect(refundRes.ok).toBe(false);

    const exportRes = simulateMcpToolCall(exportTool, obo, config, undefined, fixedNow + 10);
    expect(exportRes.status).toBe(403);
    expect(exportRes.ok).toBe(false);

    // After 60s TTL expires, even get_order_status must be rejected with 401
    const expiredRes = simulateMcpToolCall(orderTool, obo, config, undefined, fixedNow + 65);
    expect(expiredRes.status).toBe(401);
    expect(expiredRes.ok).toBe(false);
  });
});
