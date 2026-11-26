import { describe, expect, it } from "vitest";
import {
  buildStageDescriptors,
  getStageOrder
} from "../components/flow/stageDescriptors";
import {
  API_ENDPOINTS,
  revokeActiveToken,
  simulateVerifiedMcpToolCall,
  simulateVerifiedRbacPolicyCall,
  submitCibaApprovalDecision
} from "../lib/apiClient";
import {
  clearSimulatedRevocations,
  createBrowserDpopProof
} from "../lib/browserCrypto";
import {
  createSimulatedStsDelegatedSession,
  createSimulatedStsDemoSession,
  decodeJwt,
  generateLivePkceTelemetry,
  getOidcConfig,
  parseJwtClaims
} from "../lib/pkce";
import {
  evaluateFaultScenario,
  FAULT_PRESETS,
  generateCodeSnippets,
  MCP_TOOLS
} from "../lib/securityLab";
import {
  consoleReducer,
  createInitialConsoleState
} from "../state/consoleReducer";

describe("Phase 5: Console State Machine, Flow Stage Descriptors, DPoP, CIBA & Code Exporter", () => {
  it("transitions ConsoleState deterministically across all discriminated ConsoleAction variants", () => {
    let state = createInitialConsoleState();
    expect(state.flowMode).toBe("human");
    expect(state.selectedStage).toBe("pkce");

    state = consoleReducer(state, { type: "TOGGLE_THEME" });
    expect(state.theme).toBe("light");

    state = consoleReducer(state, { type: "SET_FLOW_MODE", flowMode: "agent" });
    expect(state.flowMode).toBe("agent");
    expect(state.selectedStage).toBe("agent_mcp");

    state = consoleReducer(state, { type: "SET_FLOW_MODE", flowMode: "human" });
    expect(state.flowMode).toBe("human");
    expect(state.selectedStage).toBe("rbac");

    state = consoleReducer(state, { type: "TOGGLE_ATTACK_LAB" });
    expect(state.attackLabOpen).toBe(true);

    state = consoleReducer(state, {
      type: "SET_ACTIVE_FAULT",
      fault: { id: "dpop_token_replay" }
    });
    expect(state.activeFault.id).toBe("dpop_token_replay");

    state = consoleReducer(state, {
      type: "SET_VERIFICATION_MODE",
      mode: "introspect"
    });
    expect(state.verificationMode).toBe("introspect");

    state = consoleReducer(state, { type: "SET_TOKEN_REVOKED", revoked: true });
    expect(state.tokenRevoked).toBe(true);

    state = consoleReducer(state, { type: "TOGGLE_PALETTE" });
    expect(state.paletteOpen).toBe(true);

    state = consoleReducer(state, { type: "SET_EXPORTER_OPEN", open: true });
    expect(state.exporterOpen).toBe(true);

    state = consoleReducer(state, { type: "LOGOUT_SESSION" });
    expect(state.session).toBeNull();
    expect(state.delegatedSession).toBeNull();
    expect(state.tokenRevoked).toBe(false);
  });

  it("builds 5-stage and 6-stage flow descriptors accurately across nominal, blocked, and recovered states", async () => {
    const config = getOidcConfig("wso2is");
    const pkce = await generateLivePkceTelemetry();
    const adminSession = await createSimulatedStsDemoSession("admin", config);
    const decoded = decodeJwt(adminSession.accessToken);
    const claims = decoded ? parseJwtClaims(decoded) : null;
    const delegatedSession = await createSimulatedStsDelegatedSession(claims, config);

    expect(getStageOrder("human")).toEqual(["spa", "pkce", "idp", "jwks", "rbac"]);
    expect(getStageOrder("agent")).toEqual([
      "spa",
      "pkce",
      "idp",
      "jwks",
      "rbac",
      "agent_mcp"
    ]);

    const nominalFault = evaluateFaultScenario(
      { id: "none" },
      { config, claims, pkceTelemetry: pkce }
    );
    const humanStages = buildStageDescriptors({
      config,
      flowMode: "human",
      session: adminSession,
      claims,
      delegatedSession: null,
      pkceTelemetry: pkce,
      lastApiResult: null,
      lastMcpResult: null,
      faultEval: nominalFault
    });
    expect(humanStages).toHaveLength(5);
    expect(humanStages[0].stateTone).toBe("verified");

    const dpopFault = evaluateFaultScenario(
      { id: "dpop_token_replay" },
      { config, claims, pkceTelemetry: pkce }
    );
    const agentStages = buildStageDescriptors({
      config,
      flowMode: "agent",
      session: adminSession,
      claims,
      delegatedSession,
      pkceTelemetry: pkce,
      lastApiResult: null,
      lastMcpResult: null,
      faultEval: dpopFault
    });
    expect(agentStages).toHaveLength(6);
    expect(agentStages[5].id).toBe("agent_mcp");
    expect(agentStages[5].stateTone).toBe("blocked");
  });

  it("generates Web Crypto ES256 DPoP proofs, executes CIBA step-up approval, and contrasts JWKS vs Introspection revocation", async () => {
    clearSimulatedRevocations();
    const config = getOidcConfig("wso2is");
    const adminSession = await createSimulatedStsDemoSession("admin", config);
    const decoded = decodeJwt(adminSession.accessToken);
    const claims = decoded ? parseJwtClaims(decoded) : null;
    const delegatedSession = await createSimulatedStsDelegatedSession(claims, config);

    // 1. DPoP proof generation produces a 3-segment ES256 dpop+jwt with matching jkt
    const dpop = await createBrowserDpopProof({
      accessToken: delegatedSession.accessToken,
      httpMethod: "POST",
      httpUrl: `${config.backendApiUrl}/api/mcp`
    });
    expect(dpop.dpopProof.split(".")).toHaveLength(3);
    expect(dpop.jkt).toBe(delegatedSession.dpopJkt);

    // 2. CIBA step-up approval upgrades export_all_users from 403 to 200
    const exportTool = MCP_TOOLS[2];
    const initialDeny = await simulateVerifiedMcpToolCall(
      exportTool,
      delegatedSession,
      config
    );
    expect(initialDeny.status).toBe(403);

    const cibaOutcome = await submitCibaApprovalDecision({
      baseUrl: config.backendApiUrl,
      authReqId: "ciba_sim_test_1",
      decision: "APPROVED",
      delegatedSession,
      config,
      useLiveDevIdp: false
    });
    expect(cibaOutcome.approved).toBe(true);
    expect(cibaOutcome.updatedSession?.hasHumanApproval).toBe(true);

    if (cibaOutcome.updatedSession) {
      const approvedExport = await simulateVerifiedMcpToolCall(
        exportTool,
        cibaOutcome.updatedSession,
        config
      );
      expect(approvedExport.status).toBe(200);
    }

    // 3. Token revocation contrast: Stateless JWKS (200) vs RFC 7662 Introspection (401)
    await revokeActiveToken(config.backendApiUrl, adminSession.accessToken, false);
    const profileSpec = API_ENDPOINTS[1];
    const jwksAfterRevoke = await simulateVerifiedRbacPolicyCall(
      profileSpec,
      config,
      adminSession,
      claims,
      { id: "none" },
      null,
      "jwks"
    );
    expect(jwksAfterRevoke.status).toBe(200);

    const introspectAfterRevoke = await simulateVerifiedRbacPolicyCall(
      profileSpec,
      config,
      adminSession,
      claims,
      { id: "none" },
      null,
      "introspect"
    );
    expect(introspectAfterRevoke.status).toBe(401);

    // 4. Code exporter redact vs reveal toggle and all 10 Attack Lab presets
    expect(FAULT_PRESETS).toHaveLength(11);
    const nominalEval = evaluateFaultScenario(
      { id: "none" },
      { config, claims, pkceTelemetry: null }
    );
    const redactedSnippets = generateCodeSnippets({
      config,
      flowMode: "agent",
      selectedStage: "agent_mcp",
      activeToken: adminSession.accessToken,
      faultEval: nominalEval,
      delegatedSession,
      redactToken: true
    });
    expect(redactedSnippets.curl).toContain("[REDACTED_");
    expect(redactedSnippets.curl).toContain('"jsonrpc":"2.0"');

    const revealedSnippets = generateCodeSnippets({
      config,
      flowMode: "agent",
      selectedStage: "agent_mcp",
      activeToken: adminSession.accessToken,
      faultEval: nominalEval,
      delegatedSession,
      redactToken: false
    });
    expect(revealedSnippets.curl).not.toContain("[REDACTED_");
    expect(revealedSnippets.curl).toContain(delegatedSession.accessToken);
  });
});
