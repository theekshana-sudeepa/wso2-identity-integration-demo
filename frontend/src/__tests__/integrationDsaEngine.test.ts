import { describe, expect, it } from "vitest";
import {
  browserIntegrationEngine,
  buildStandardMediationDagNodes,
  planMediationDag
} from "../lib/integrationDsaEngine";
import { getOidcConfig } from "../lib/pkce";
import { evaluateFaultScenario, generateCodeSnippets } from "../lib/securityLab";

describe("Frontend WSO2 APIM + Micro Integrator EIP & Core DSA Simulation Parity", () => {
  it("executes full APIM + Micro Integrator Scatter-Gather mediation and exports Synapse XML & Ballerina", () => {
    const res = browserIntegrationEngine.executeMediation({
      subscriber: "developer@acme-identity.example",
      groups: ["developer"],
      tier: "Silver",
      faultMode: "nominal",
      order: {
        orderId: "ORD-2026-77310",
        customerId: "CUST-EU-9912",
        amountUsd: 680,
        currency: "EUR",
        region: "EU",
        priority: "STANDARD",
        items: [{ sku: "WSO2-CHOREO-CELL", qty: 1 }]
      }
    });

    expect(res.ok).toBe(true);
    expect(res.httpStatus).toBe(200);
    expect(res.microIntegrator.selectedCbrRoute).toBe("EU_GDPR_COMPLIANCE_ROUTE");
    expect(res.apimGateway.backendJwtAssertion.claims["http://wso2.org/claims/tier"]).toBe(
      "Silver"
    );

    const dag = planMediationDag(buildStandardMediationDagNodes(false));
    expect(dag.ok).toBe(true);

    const config = getOidcConfig("wso2is");
    const faultEval = evaluateFaultScenario(
      { id: "none" },
      { config, claims: null, pkceTelemetry: null }
    );
    const snippets = generateCodeSnippets({
      config,
      flowMode: "human",
      selectedStage: "rbac",
      activeToken: null,
      faultEval,
      delegatedSession: null,
      redactToken: true
    });

    expect(snippets.synapseXml).toContain("EnterpriseOrderIntegrationAPI");
    expect(snippets.synapseXml).toContain("<clone id=\"ORDER_SCATTER_GATHER\"");
    expect(snippets.ballerinaBal).toContain("service /api/integration/orders");
  });
});
