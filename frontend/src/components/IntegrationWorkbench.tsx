import { memo, useCallback, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Code2,
  Copy,
  Cpu,
  GitBranch,
  Layers,
  Network,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Zap
} from "lucide-react";
import {
  APIM_SUBSCRIPTION_TIERS,
  browserIntegrationEngine,
  type ApimSubscriptionTier,
  type EipMediationResponse,
  type IntegrationFaultMode,
  type IntegrationOrderPayload
} from "../lib/integrationDsaEngine";
import type { BackendHealthStatus, ExecutionMode } from "../lib/apiClient";
import type { ParsedJwtClaims, TokenSession } from "../lib/pkce";
import { JsonHighlighter } from "./JsonHighlighter";

export interface IntegrationWorkbenchProps {
  readonly baseUrl: string;
  readonly executionMode: ExecutionMode;
  readonly backendHealth: BackendHealthStatus;
  readonly session: TokenSession | null;
  readonly claims: ParsedJwtClaims | null;
  readonly onNotify: (message: string) => void;
}

type WorkbenchTab = "eip_pipeline" | "dsa_telemetry" | "wso2_artifacts";
type ArtifactKind = "synapse_xml" | "apim_yaml" | "ballerina_bal";

interface OrderPreset {
  readonly id: string;
  readonly label: string;
  readonly badge: string;
  readonly payload: IntegrationOrderPayload;
}

const ORDER_PRESETS: readonly OrderPreset[] = [
  {
    id: "high-value",
    label: "High-Value Order ($2,450 · Fraud Screen CBR)",
    badge: "amountUsd >= 1000",
    payload: {
      orderId: "ORD-2026-99201",
      customerId: "CUST-ENT-4410",
      amountUsd: 2450.0,
      currency: "USD",
      region: "US-EAST",
      priority: "HIGH_RISK",
      items: [
        { sku: "WSO2-APIM-ENTERPRISE-NODE", qty: 2 },
        { sku: "WSO2-MI-SYNAPSE-RUNTIME", qty: 4 }
      ]
    }
  },
  {
    id: "eu-gdpr",
    label: "EU Sovereign Order (€680 · EU GDPR CBR)",
    badge: "region == 'EU'",
    payload: {
      orderId: "ORD-2026-77310",
      customerId: "CUST-EU-9912",
      amountUsd: 680.0,
      currency: "EUR",
      region: "EU",
      priority: "STANDARD",
      items: [{ sku: "WSO2-CHOREO-CELL-GATEWAY", qty: 1 }]
    }
  },
  {
    id: "fast-track",
    label: "Standard Order ($190 · Fast-Track CBR)",
    badge: "default route",
    payload: {
      orderId: "ORD-2026-55104",
      customerId: "CUST-APAC-2041",
      amountUsd: 190.0,
      currency: "USD",
      region: "APAC",
      priority: "STANDARD",
      items: [{ sku: "WSO2-BALLERINA-CONNECTOR", qty: 3 }]
    }
  }
];

const FAULT_MODES: ReadonlyArray<{
  readonly id: IntegrationFaultMode;
  readonly label: string;
  readonly hint: string;
}> = [
  {
    id: "nominal",
    label: "Nominal APIM + MI Scatter-Gather",
    hint: "200 OK · Radix Trie + LRU + Clone/Aggregate"
  },
  {
    id: "throttle_spike",
    label: "APIM Tier Quota Spike (429)",
    hint: "Token Bucket O(1) Burst Exhausted"
  },
  {
    id: "upstream_timeout_cb",
    label: "Upstream Inventory Failure (Circuit Breaker + DLQ)",
    hint: "FSM Trips OPEN -> Failover Replica + Min-Heap Retry"
  },
  {
    id: "dag_cycle_fault",
    label: "Cyclic Mediation Sequence Fault (400)",
    hint: "Kahn's O(V+E) Topological Cycle Detection"
  }
];

const SYNAPSE_XML_ARTIFACT = `<?xml version="1.0" encoding="UTF-8"?>
<api context="/api/integration/orders" name="EnterpriseOrderIntegrationAPI" version="1.0.0" version-type="context" xmlns="http://ws.apache.org/ns/synapse">
  <resource methods="POST" uri-template="/{orderId}/mediate">
    <inSequence>
      <property expression="$trp:X-JWT-Assertion" name="APIM_BACKEND_JWT" scope="default" type="STRING"/>
      <property expression="json-eval($.orderId)" name="ORDER_ID" scope="default" type="STRING"/>
      <property expression="json-eval($.amountUsd)" name="AMOUNT_USD" scope="default" type="STRING"/>
      <property expression="json-eval($.region)" name="ORDER_REGION" scope="default" type="STRING"/>

      <!-- Content-Based Router (CBR) -->
      <filter xpath="number(get-property('AMOUNT_USD')) &gt;= 1000">
        <then>
          <property name="CBR_SELECTED_ROUTE" value="HIGH_VALUE_FRAUD_SCREEN"/>
        </then>
        <else>
          <switch source="get-property('ORDER_REGION')">
            <case regex="EU"><property name="CBR_SELECTED_ROUTE" value="EU_GDPR_COMPLIANCE_ROUTE"/></case>
            <default><property name="CBR_SELECTED_ROUTE" value="FAST_TRACK_STANDARD_ROUTE"/></default>
          </switch>
        </else>
      </filter>

      <!-- Scatter-Gather Parallel Fan-Out (Clone Mediator) -->
      <clone id="ORDER_SCATTER_GATHER" sequential="false">
        <target><sequence><call><endpoint key="OrderCoreServiceEP"/></call></sequence></target>
        <target><sequence><call><endpoint key="WarehouseInventoryFailoverEP"/></call></sequence></target>
        <target><sequence><call><endpoint key="FraudRiskScoringServiceEP"/></call></sequence></target>
      </clone>
    </inSequence>
    <outSequence>
      <!-- Scatter-Gather Aggregation + PayloadFactory Transformation -->
      <aggregate id="ORDER_SCATTER_GATHER">
        <completeCondition timeout="3"><messageCount max="-1" min="3"/></completeCondition>
        <onComplete enclosingElementProperty="AggregatedRoot" expression="$body/*">
          <payloadFactory media-type="json">
            <format>{"schemaVersion":"urn:wso2:mi:canonical-order:v3","orderId":"$1","route":"$2","branches":$3}</format>
            <args>
              <arg evaluator="xml" expression="get-property('ORDER_ID')"/>
              <arg evaluator="xml" expression="get-property('CBR_SELECTED_ROUTE')"/>
              <arg evaluator="json" expression="$.AggregatedRoot"/>
            </args>
          </payloadFactory>
          <respond/>
        </onComplete>
      </aggregate>
    </outSequence>
    <faultSequence>
      <store messageStore="InventoryDeadLetterQueueStore"/>
      <respond/>
    </faultSequence>
  </resource>
</api>`;

const APIM_YAML_ARTIFACT = `type: api
version: v4.3.0
data:
  name: EnterpriseOrderIntegrationAPI
  context: /api/integration/orders
  version: v1.0.0
  lifeCycleStatus: PUBLISHED
  responseCachingEnabled: true
  cacheTimeout: 60
  policies: [Bronze, Silver, Gold, AI-Agent-MCP]
  securityScheme: [oauth2]
  backendJwtConfiguration:
    enabled: true
    jwtHeader: X-JWT-Assertion
    signingAlgorithm: SHA256withRSA
    customClaims:
      - claimUri: http://wso2.org/claims/enduser
      - claimUri: http://wso2.org/claims/tier
      - claimUri: http://wso2.org/claims/role
  endpointConfig:
    endpoint_type: http
    production_endpoints:
      url: http://choreo-micro-integrator:8290/api/integration/orders
    failover_endpoints:
      - url: http://choreo-micro-integrator-replica:8290/api/integration/orders`;

const BALLERINA_ARTIFACT = `import ballerina/http;

final http:Client inventoryClient = check new ("http://inventory-primary.choreo.internal:8082", {
    circuitBreaker: {
        rollingWindow: {timeWindow: 60, bucketSize: 10, requestVolumeThreshold: 2},
        failureThreshold: 0.5,
        resetTime: 15,
        statusCodes: [500, 502, 503, 504]
    },
    retryConfig: {count: 3, interval: 1, backOffFactor: 2.0, maxWaitInterval: 16}
});

service /api/integration/orders on new http:Listener(8290) {
    isolated resource function post [string orderId]/mediate(
            @http:Header {name: "X-JWT-Assertion"} string? apimBackendJwt,
            @http:Payload record {|string orderId; decimal amountUsd; string region;|} payload) returns json {
        string cbrRoute = payload.amountUsd >= 1000d
            ? "HIGH_VALUE_FRAUD_SCREEN"
            : (payload.region == "EU" ? "EU_GDPR_COMPLIANCE_ROUTE" : "FAST_TRACK_STANDARD_ROUTE");

        fork {
            worker OrderWorker returns json { return {orderId, ledger: "COMMITTED"}; }
            worker InventoryWorker returns json {
                json|error res = inventoryClient->/v1/reserve.post(payload);
                return res is json ? res : {warehouse: "RESERVED_ON_FAILOVER_REPLICA"};
            }
            worker RiskWorker returns json { return {cbrRoute, verdict: "APPROVED"}; }
        }
        record {json OrderWorker; json InventoryWorker; json RiskWorker;} merged =
            wait {OrderWorker, InventoryWorker, RiskWorker};
        return {schemaVersion: "urn:wso2:ballerina:canonical-order:v3", orderId, cbrRoute, merged};
    }
}`;

export const IntegrationWorkbench = memo(function IntegrationWorkbench({
  baseUrl,
  executionMode,
  backendHealth,
  session,
  claims,
  onNotify
}: IntegrationWorkbenchProps) {
  const [activeTab, setActiveTab] = useState<WorkbenchTab>("eip_pipeline");
  const [selectedTier, setSelectedTier] = useState<ApimSubscriptionTier>("Silver");
  const [selectedPresetId, setSelectedPresetId] = useState<string>("high-value");
  const [faultMode, setFaultMode] = useState<IntegrationFaultMode>("nominal");
  const [artifactKind, setArtifactKind] = useState<ArtifactKind>("synapse_xml");
  const [isExecuting, setIsExecuting] = useState(false);

  const activePreset = useMemo(
    () => ORDER_PRESETS.find((p) => p.id === selectedPresetId) ?? ORDER_PRESETS[0],
    [selectedPresetId]
  );

  const [mediationResult, setMediationResult] = useState<EipMediationResponse>(() =>
    browserIntegrationEngine.executeMediation({
      subscriber: claims?.username ?? "developer@acme-identity.example",
      groups: claims?.groups ?? ["developer"],
      tier: "Silver",
      faultMode: "nominal",
      order: ORDER_PRESETS[0].payload
    })
  );

  const handleExecuteMediation = useCallback(async () => {
    setIsExecuting(true);
    try {
      const subscriber = claims?.username ?? "developer@acme-identity.example";
      const groups = claims?.groups ?? ["developer"];
      const shouldUseLive =
        executionMode === "live" &&
        backendHealth.reachable &&
        Boolean(session?.accessToken) &&
        session?.stsMode === "dev-idp";

      if (shouldUseLive && session?.accessToken) {
        const res = await fetch(
          `${baseUrl}/api/integration/orders/${activePreset.payload.orderId}/mediate`,
          {
            method: "POST",
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
              Authorization: `Bearer ${session.accessToken}`,
              "X-WSO2-Subscription-Tier": selectedTier
            },
            body: JSON.stringify({
              tier: selectedTier,
              faultMode,
              order: activePreset.payload
            })
          }
        );
        if (res.status !== 401) {
          const parsed = (await res.json()) as EipMediationResponse;
          if (parsed && typeof parsed.httpStatus === "number" && parsed.apimGateway) {
            setMediationResult(parsed);
            onNotify(
              `WSO2 APIM + Micro Integrator Mediation: HTTP ${parsed.httpStatus} (${parsed.microIntegrator.selectedCbrRoute})`
            );
            return;
          }
        }
      }

      const simulated = browserIntegrationEngine.executeMediation({
        subscriber,
        groups,
        tier: selectedTier,
        faultMode,
        order: activePreset.payload
      });
      setMediationResult(simulated);
      onNotify(
        `Executed WSO2 APIM + MI EIP Pipeline (${simulated.httpStatus} · ${simulated.microIntegrator.selectedCbrRoute})`
      );
    } catch {
      const simulated = browserIntegrationEngine.executeMediation({
        subscriber: claims?.username ?? "developer@acme-identity.example",
        groups: claims?.groups ?? ["developer"],
        tier: selectedTier,
        faultMode,
        order: activePreset.payload
      });
      setMediationResult(simulated);
    } finally {
      setIsExecuting(false);
    }
  }, [
    activePreset.payload,
    backendHealth.reachable,
    baseUrl,
    claims?.groups,
    claims?.username,
    executionMode,
    faultMode,
    onNotify,
    selectedTier,
    session?.accessToken,
    session?.stsMode
  ]);

  const handleResetDsaState = useCallback(async () => {
    browserIntegrationEngine.responseLruCache.clear();
    browserIntegrationEngine.throttler.reset();
    browserIntegrationEngine.inventoryCircuitBreaker.forceState("CLOSED");
    browserIntegrationEngine.retryMinHeap.clear();

    if (executionMode === "live" && backendHealth.reachable) {
      try {
        await fetch(`${baseUrl}/api/integration/reset`, { method: "POST" });
      } catch {
        // Ignore network errors in offline mode
      }
    }

    const fresh = browserIntegrationEngine.executeMediation({
      subscriber: claims?.username ?? "developer@acme-identity.example",
      groups: claims?.groups ?? ["developer"],
      tier: selectedTier,
      faultMode: "nominal",
      order: activePreset.payload
    });
    setFaultMode("nominal");
    setMediationResult(fresh);
    onNotify("Reset WSO2 APIM Token Buckets, Doubly-Linked LRU, Circuit Breaker FSM & Min-Heap DLQ");
  }, [
    activePreset.payload,
    backendHealth.reachable,
    baseUrl,
    claims?.groups,
    claims?.username,
    executionMode,
    onNotify,
    selectedTier
  ]);

  const activeArtifactText =
    artifactKind === "synapse_xml"
      ? SYNAPSE_XML_ARTIFACT
      : artifactKind === "apim_yaml"
        ? APIM_YAML_ARTIFACT
        : BALLERINA_ARTIFACT;

  const { apimGateway, microIntegrator } = mediationResult;

  return (
    <section
      className="card"
      aria-label="WSO2 API Manager, Micro Integrator EIP, and Core DSA Workbench"
    >
      <div className="bench-header">
        <div className="card-title">
          <span className="icon-box">
            <Network size={16} />
          </span>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.55rem", flexWrap: "wrap" }}>
              <h2>WSO2 API Manager (APIM 4.x) · Micro Integrator (EIP) &amp; Core DSA Workbench</h2>
              <span className="brand-tag">APIM + MI + 5 Core Data Structures</span>
            </div>
            <p className="card-caption">
              Interactive Gateway Mediation (<code>X-JWT-Assertion</code>, Token Bucket Tiers, LRU
              Cache), Micro Integrator EIP (Content-Based Router, Scatter-Gather{" "}
              <code>&lt;clone&gt;/&lt;aggregate&gt;</code>, <code>&lt;payloadFactory&gt;</code>,
              Circuit Breaker + Min-Heap DLQ) &amp; Big-O DSA Telemetry
            </p>
          </div>
        </div>

        <div className="segmented-tabs" role="tablist" aria-label="Integration Workbench Views">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "eip_pipeline"}
            className={`seg-tab ${activeTab === "eip_pipeline" ? "seg-tab-active" : ""}`}
            onClick={() => setActiveTab("eip_pipeline")}
          >
            <Layers size={13} />
            APIM + Micro Integrator EIP
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "dsa_telemetry"}
            className={`seg-tab ${activeTab === "dsa_telemetry" ? "seg-tab-active" : ""}`}
            onClick={() => setActiveTab("dsa_telemetry")}
          >
            <Cpu size={13} />
            Core DSA Telemetry (5 Structures)
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "wso2_artifacts"}
            className={`seg-tab ${activeTab === "wso2_artifacts" ? "seg-tab-active" : ""}`}
            onClick={() => setActiveTab("wso2_artifacts")}
          >
            <Code2 size={13} />
            Synapse XML · api.yaml · Ballerina
          </button>
        </div>
      </div>

      {/* Control Bar: APIM Tier + Order Payload Preset + Fault Injection */}
      <div
        className="fault-subcontrols"
        style={{
          marginBottom: "1rem",
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))",
          gap: "0.85rem",
          alignItems: "end"
        }}
      >
        <div>
          <div className="subcontrol-label" style={{ marginBottom: "0.35rem" }}>
            1. WSO2 APIM Subscription Tier (Token Bucket O(1)):
          </div>
          <div className="segmented-tabs" style={{ flexWrap: "wrap" }}>
            {(Object.keys(APIM_SUBSCRIPTION_TIERS) as ApimSubscriptionTier[]).map((tier) => (
              <button
                key={tier}
                type="button"
                className={`seg-tab ${selectedTier === tier ? "seg-tab-active" : ""}`}
                onClick={() => setSelectedTier(tier)}
                title={APIM_SUBSCRIPTION_TIERS[tier].description}
              >
                {tier}
              </button>
            ))}
          </div>
        </div>

        <div>
          <div className="subcontrol-label" style={{ marginBottom: "0.35rem" }}>
            2. Order Payload (Micro Integrator Content-Based Router):
          </div>
          <div className="segmented-tabs" style={{ flexWrap: "wrap" }}>
            {ORDER_PRESETS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                className={`seg-tab ${selectedPresetId === preset.id ? "seg-tab-active" : ""}`}
                onClick={() => setSelectedPresetId(preset.id)}
              >
                {preset.id === "high-value"
                  ? "$2,450 High-Value"
                  : preset.id === "eu-gdpr"
                    ? "€680 EU GDPR"
                    : "$190 Fast-Track"}
              </button>
            ))}
          </div>
        </div>

        <div>
          <div className="subcontrol-label" style={{ marginBottom: "0.35rem" }}>
            3. Integration Fault &amp; Resiliency Scenario:
          </div>
          <div className="segmented-tabs" style={{ flexWrap: "wrap" }}>
            {FAULT_MODES.map((fm) => (
              <button
                key={fm.id}
                type="button"
                className={`seg-tab ${faultMode === fm.id ? "seg-tab-active" : ""}`}
                onClick={() => setFaultMode(fm.id)}
                title={fm.hint}
              >
                {fm.id === "nominal"
                  ? "Nominal (200)"
                  : fm.id === "throttle_spike"
                    ? "429 Quota Burst"
                    : fm.id === "upstream_timeout_cb"
                      ? "Circuit Breaker + DLQ"
                      : "DAG Cycle (400)"}
              </button>
            ))}
          </div>
        </div>

        <div style={{ display: "flex", gap: "0.5rem", justifyContent: "flex-end", flexWrap: "wrap" }}>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={isExecuting}
            onClick={() => {
              void handleExecuteMediation();
            }}
          >
            <Play size={13} />
            {isExecuting ? "Mediating..." : "Execute APIM + MI Pipeline"}
          </button>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => {
              void handleResetDsaState();
            }}
            title="Reset Token Buckets, LRU Cache, Circuit Breaker & Min-Heap DLQ"
          >
            <RotateCcw size={13} />
            Reset DSA
          </button>
        </div>
      </div>

      {/* TAB 1: WSO2 APIM Gateway + Micro Integrator EIP Pipeline */}
      {activeTab === "eip_pipeline" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {/* Status Summary Strip */}
          <div
            className={`bench-trace-banner ${
              mediationResult.ok ? "bench-trace-allowed" : "bench-trace-rejected"
            }`}
            style={{ justifyContent: "space-between", flexWrap: "wrap", gap: "0.75rem" }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
              {mediationResult.ok ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />}
              <div>
                <strong>
                  HTTP {mediationResult.httpStatus} ·{" "}
                  {mediationResult.ok
                    ? "WSO2 APIM Gateway & Micro Integrator Mediation Succeeded"
                    : mediationResult.httpStatus === 429
                      ? "WSO2 APIM Traffic Manager Throttled Out (429 Quota Exceeded)"
                      : "Micro Integrator Mediation Sequence Rejected (Cyclic DAG)"}
                </strong>{" "}
                <span>
                  · Correlation ID: <code>{mediationResult.correlationId}</code>
                </span>
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
              <span className="rfc-chip">
                Tier: {apimGateway.throttleDecision.tier} (Remaining:{" "}
                {apimGateway.throttleDecision.remainingTokens}/
                {apimGateway.throttleDecision.capacity})
              </span>
              <span className="rfc-chip">
                LRU Cache: {apimGateway.responseCacheStatus} (Hits:{" "}
                {apimGateway.lruCacheTelemetry.hits})
              </span>
              <span className="rfc-chip">
                Circuit Breaker: {microIntegrator.circuitBreaker.state}
              </span>
            </div>
          </div>

          {/* 2-Column APIM Gateway vs Micro Integrator CBR & Scatter-Gather */}
          <div className="grid-2">
            {/* Left: WSO2 API Manager 4.x Gateway Mediation */}
            <div className="inspector-pane">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "0.55rem"
                }}
              >
                <span className="pane-label">
                  Stage A · WSO2 API Manager 4.x Gateway Mediation
                </span>
                <span className="rfc-chip">X-JWT-Assertion + Radix Trie</span>
              </div>

              <div className="telemetry-stack" style={{ marginBottom: "0.75rem" }}>
                <div className="telemetry-row">
                  <span className="telemetry-label">Radix Trie Route Match</span>
                  <span className="telemetry-value">
                    {apimGateway.routeMatch.matched
                      ? `${apimGateway.routeMatch.pattern} (param orderId=${apimGateway.routeMatch.params.orderId ?? ""})`
                      : "MISS"}
                  </span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-label">Token Bucket Policy</span>
                  <span className="telemetry-value">
                    {APIM_SUBSCRIPTION_TIERS[apimGateway.throttleDecision.tier].description}
                  </span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-label">Response Cache (Doubly-Linked LRU)</span>
                  <span className="telemetry-value">
                    {apimGateway.responseCacheStatus} · Hit Ratio{" "}
                    {(apimGateway.lruCacheTelemetry.hitRatio * 100).toFixed(0)}% (
                    {apimGateway.lruCacheTelemetry.size}/{apimGateway.lruCacheTelemetry.capacity}{" "}
                    slots)
                  </span>
                </div>
              </div>

              <div className="pane-label" style={{ marginBottom: "0.35rem" }}>
                Minted WSO2 APIM Backend Context Token (<code>X-JWT-Assertion</code> Claims)
              </div>
              <JsonHighlighter
                data={apimGateway.backendJwtAssertion.claims}
                maxHeight={185}
                copyLabel="Copy WSO2 X-JWT-Assertion claims"
              />
            </div>

            {/* Right: WSO2 Micro Integrator Content-Based Router & Scatter-Gather */}
            <div className="inspector-pane">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "0.55rem"
                }}
              >
                <span className="pane-label">
                  Stage B · WSO2 Micro Integrator (CBR + Scatter-Gather)
                </span>
                <span className="rfc-chip">
                  {microIntegrator.sequentialLatencySumMs}ms seq →{" "}
                  {microIntegrator.parallelAggregatedLatencyMs}ms parallel
                </span>
              </div>

              <div className="telemetry-stack" style={{ marginBottom: "0.75rem" }}>
                <div className="telemetry-row">
                  <span className="telemetry-label">Content-Based Router (CBR)</span>
                  <span className="telemetry-value">{microIntegrator.selectedCbrRoute}</span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-label">Synapse Switch / Filter Predicate</span>
                  <span className="telemetry-value">
                    <code>{microIntegrator.cbrExpression}</code>
                  </span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-label">Inventory Endpoint Circuit Breaker</span>
                  <span className="telemetry-value">
                    State: {microIntegrator.circuitBreaker.state} (Failures:{" "}
                    {microIntegrator.circuitBreaker.consecutiveFailures}/
                    {microIntegrator.circuitBreaker.failureThreshold}) · DLQ Heap:{" "}
                    {microIntegrator.retryQueueDlqSnapshot.length} msg(s)
                  </span>
                </div>
              </div>

              <div className="pane-label" style={{ marginBottom: "0.4rem" }}>
                Scatter-Gather (<code>&lt;clone&gt;</code> Fan-Out &amp;{" "}
                <code>&lt;aggregate&gt;</code> Branches)
              </div>
              {microIntegrator.scatterGatherBranches.length === 0 ? (
                <div className="state-callout tone-blocked">
                  <ShieldAlert size={14} />
                  <span>
                    Scatter-Gather halted prior to fan-out (HTTP {mediationResult.httpStatus}).
                  </span>
                </div>
              ) : (
                <div style={{ display: "grid", gap: "0.45rem" }}>
                  {microIntegrator.scatterGatherBranches.map((branch) => (
                    <div
                      key={branch.branchId}
                      style={{
                        padding: "0.5rem 0.7rem",
                        borderRadius: "8px",
                        border: "1px solid var(--border-subtle)",
                        background: "var(--bg-surface-elevated)",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        gap: "0.5rem",
                        fontSize: "0.77rem"
                      }}
                    >
                      <div>
                        <strong>{branch.serviceName}</strong>{" "}
                        <span style={{ color: "var(--text-secondary)" }}>
                          ({branch.endpointUrl})
                        </span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.45rem" }}>
                        <span className="latency-chip">{branch.latencyMs} ms</span>
                        <span
                          className={`mcp-expect-badge ${
                            branch.status === "SUCCESS" ? "mcp-expect-allow" : "mcp-expect-deny"
                          }`}
                        >
                          {branch.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Side-by-Side Message Transformation (<payloadFactory> Legacy XML -> Canonical JSON) */}
          <div className="grid-2">
            <div className="inspector-pane">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "0.45rem"
                }}
              >
                <span className="pane-label">
                  Upstream Legacy SOAP/XML Envelope (Pre-Mediation)
                </span>
                <span className="rfc-chip">application/soap+xml</span>
              </div>
              <pre
                className="code-block"
                style={{
                  maxHeight: "190px",
                  overflow: "auto",
                  fontSize: "0.74rem",
                  padding: "0.75rem"
                }}
              >
                {microIntegrator.payloadFactoryTransform.legacyUpstreamXml}
              </pre>
            </div>

            <div className="inspector-pane">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "0.45rem"
                }}
              >
                <span className="pane-label">
                  Micro Integrator <code>&lt;payloadFactory&gt;</code> Canonical Enterprise JSON
                </span>
                <span className="rfc-chip">application/json</span>
              </div>
              <JsonHighlighter
                data={microIntegrator.payloadFactoryTransform.canonicalEnterpriseJson}
                maxHeight={190}
                copyLabel="Copy transformed canonical JSON"
              />
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Core DSA Under-the-Hood Telemetry (5 Structures) */}
      {activeTab === "dsa_telemetry" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div className="grid-2">
            {/* DSA #1: Radix Prefix Segment Trie */}
            <div className="inspector-pane">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "0.45rem"
                }}
              >
                <span className="pane-label">
                  1. Radix Prefix Segment Trie (<code>RadixRouteTrie</code>)
                </span>
                <span className="rfc-chip">Time: O(k) · Space: O(N·k)</span>
              </div>
              <p style={{ fontSize: "0.77rem", color: "var(--text-secondary)", marginBottom: "0.6rem" }}>
                Matches API Gateway URI templates in <code>O(k)</code> path segments rather than{" "}
                <code>O(N)</code> linear regex scans across registered routes.
              </p>
              <div className="telemetry-stack">
                <div className="telemetry-row">
                  <span className="telemetry-label">Complexity Proof</span>
                  <span className="telemetry-value">{apimGateway.routeMatch.complexity}</span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-label">Matched Pattern</span>
                  <span className="telemetry-value">
                    {apimGateway.routeMatch.matched ? apimGateway.routeMatch.pattern : "No Match"}
                  </span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-label">Extracted Path Params</span>
                  <span className="telemetry-value">
                    <code>
                      {apimGateway.routeMatch.matched
                        ? JSON.stringify(apimGateway.routeMatch.params)
                        : "{}"}
                    </code>
                  </span>
                </div>
              </div>
            </div>

            {/* DSA #2: Doubly-Linked List + HashMap LRU Cache */}
            <div className="inspector-pane">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "0.45rem"
                }}
              >
                <span className="pane-label">
                  2. Doubly-Linked List + HashMap LRU Cache (<code>DoublyLinkedLruTtlCache</code>)
                </span>
                <span className="rfc-chip">get / put / evict: Strict O(1)</span>
              </div>
              <p style={{ fontSize: "0.77rem", color: "var(--text-secondary)", marginBottom: "0.6rem" }}>
                Pointer-based <code>Node &#123; prev, next, key, value, expiresAtMs &#125;</code>{" "}
                splices accessed items to MRU head and evicts LRU tail in <code>O(1)</code>.
              </p>
              <div className="telemetry-stack">
                <div className="telemetry-row">
                  <span className="telemetry-label">Hits / Misses / Evictions</span>
                  <span className="telemetry-value">
                    {apimGateway.lruCacheTelemetry.hits} hits ·{" "}
                    {apimGateway.lruCacheTelemetry.misses} misses ·{" "}
                    {apimGateway.lruCacheTelemetry.evictions} evictions
                  </span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-label">MRU ↔ LRU Pointer Chain</span>
                  <span className="telemetry-value">
                    <code>
                      {apimGateway.lruCacheTelemetry.mruToLruKeys.length > 0
                        ? apimGateway.lruCacheTelemetry.mruToLruKeys.join(" <-> ")
                        : "[EMPTY_CACHE]"}
                    </code>
                  </span>
                </div>
              </div>
            </div>

            {/* DSA #3: Token Bucket Continuous Refill Throttler */}
            <div className="inspector-pane">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "0.45rem"
                }}
              >
                <span className="pane-label">
                  3. Token Bucket Rate Limiter (<code>TokenBucketThrottler</code>)
                </span>
                <span className="rfc-chip">Time: O(1) · Space: O(1)/key</span>
              </div>
              <p style={{ fontSize: "0.77rem", color: "var(--text-secondary)", marginBottom: "0.6rem" }}>
                Computes lazy continuous refill{" "}
                <code>tokens = min(cap, tokens + Δt × refillRate)</code> without background timers.
              </p>
              <div className="telemetry-stack">
                <div className="telemetry-row">
                  <span className="telemetry-label">Active WSO2 APIM Tier</span>
                  <span className="telemetry-value">{apimGateway.throttleDecision.tier}</span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-label">Bucket State</span>
                  <span className="telemetry-value">
                    {apimGateway.throttleDecision.remainingTokens} /{" "}
                    {apimGateway.throttleDecision.capacity} tokens (+
                    {apimGateway.throttleDecision.refillPerSecond}/sec)
                  </span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-label">Emitted Gateway Headers</span>
                  <span className="telemetry-value">
                    <code>{JSON.stringify(apimGateway.throttleDecision.headers)}</code>
                  </span>
                </div>
              </div>
            </div>

            {/* DSA #4: FSM Circuit Breaker + Binary Min-Heap Priority Queue */}
            <div className="inspector-pane">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: "0.45rem"
                }}
              >
                <span className="pane-label">
                  4. FSM Circuit Breaker + Binary Min-Heap DLQ (<code>MinHeapRetryQueue</code>)
                </span>
                <span className="rfc-chip">FSM: O(1) · Heap: O(log n)</span>
              </div>
              <p style={{ fontSize: "0.77rem", color: "var(--text-secondary)", marginBottom: "0.6rem" }}>
                Array-backed binary min-heap (<code>parent = (i-1)&gt;&gt;1</code>) schedules Dead-Letter
                Message Processor retries by earliest{" "}
                <code>nextRetry = now + 1000 × 2^attempt</code>.
              </p>
              <div className="telemetry-stack">
                <div className="telemetry-row">
                  <span className="telemetry-label">Circuit Breaker FSM</span>
                  <span className="telemetry-value">
                    {microIntegrator.circuitBreaker.state} (Consecutive Failures:{" "}
                    {microIntegrator.circuitBreaker.consecutiveFailures})
                  </span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-label">Min-Heap DLQ Size</span>
                  <span className="telemetry-value">
                    {microIntegrator.retryQueueDlqSnapshot.length} queued message(s)
                  </span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-label">Heap Root (O(1) Peek Earliest Retry)</span>
                  <span className="telemetry-value">
                    <code>
                      {microIntegrator.retryQueueDlqSnapshot[0]
                        ? `${microIntegrator.retryQueueDlqSnapshot[0].messageId} (attempt #${microIntegrator.retryQueueDlqSnapshot[0].attempt})`
                        : "Heap Empty"}
                    </code>
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* DSA #5: Kahn's BFS Topological Sort & Parallel Execution Waves */}
          <div className="inspector-pane">
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "0.5rem",
                flexWrap: "wrap",
                gap: "0.5rem"
              }}
            >
              <span className="pane-label">
                5. Directed Acyclic Graph (DAG) Kahn&apos;s Topological Sort &amp; Cycle Verifier (
                <code>planMediationDag</code>)
              </span>
              <span className="rfc-chip">{microIntegrator.dagPlan.complexity}</span>
            </div>

            {microIntegrator.dagPlan.ok ? (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.45rem",
                  flexWrap: "wrap",
                  marginTop: "0.35rem"
                }}
              >
                {microIntegrator.dagPlan.parallelWaves.map((wave, idx, allWaves) => (
                  <div
                    key={`wave-${idx}`}
                    style={{ display: "flex", alignItems: "center", gap: "0.45rem" }}
                  >
                    <div
                      style={{
                        padding: "0.45rem 0.65rem",
                        borderRadius: "8px",
                        border:
                          wave.length > 1
                            ? "1px solid var(--accent-primary-border)"
                            : "1px solid var(--border-subtle)",
                        background:
                          wave.length > 1
                            ? "var(--accent-primary-soft)"
                            : "var(--bg-surface-elevated)",
                        fontSize: "0.74rem"
                      }}
                    >
                      <div
                        style={{
                          fontWeight: 600,
                          marginBottom: "0.18rem",
                          color:
                            wave.length > 1 ? "var(--accent-primary)" : "var(--text-secondary)"
                        }}
                      >
                        Wave {idx + 1} {wave.length > 1 ? "(Parallel Clone Fan-Out)" : ""}
                      </div>
                      <code>{wave.join(" || ")}</code>
                    </div>
                    {idx < allWaves.length - 1 && (
                      <ArrowRight size={14} style={{ color: "var(--text-muted)" }} />
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="state-callout tone-blocked">
                <ShieldAlert size={15} />
                <span>
                  <strong>Cyclic Mediation Graph Blocked:</strong> Kahn&apos;s in-degree topological
                  verifier detected a cycle across{" "}
                  <code>{microIntegrator.dagPlan.cycleNodes.join(" -> ")}</code>.
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: Authentic WSO2 Micro Integrator Synapse XML, APIM api.yaml & Ballerina */}
      {activeTab === "wso2_artifacts" && (
        <div>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "0.6rem",
              marginBottom: "0.75rem"
            }}
          >
            <div className="segmented-tabs">
              <button
                type="button"
                className={`seg-tab ${artifactKind === "synapse_xml" ? "seg-tab-active" : ""}`}
                onClick={() => setArtifactKind("synapse_xml")}
              >
                <GitBranch size={13} />
                WSO2 Micro Integrator (Synapse XML)
              </button>
              <button
                type="button"
                className={`seg-tab ${artifactKind === "apim_yaml" ? "seg-tab-active" : ""}`}
                onClick={() => setArtifactKind("apim_yaml")}
              >
                <Activity size={13} />
                WSO2 API Manager (api.yaml)
              </button>
              <button
                type="button"
                className={`seg-tab ${artifactKind === "ballerina_bal" ? "seg-tab-active" : ""}`}
                onClick={() => setArtifactKind("ballerina_bal")}
              >
                <Zap size={13} />
                WSO2 Ballerina (order_integration_service.bal)
              </button>
            </div>

            <button
              type="button"
              className="btn btn-xs btn-primary"
              onClick={() => {
                navigator.clipboard
                  .writeText(activeArtifactText)
                  .then(() => onNotify("Copied WSO2 integration artifact to clipboard"))
                  .catch(() => onNotify("Clipboard unavailable"));
              }}
            >
              <Copy size={12} />
              Copy WSO2 Artifact
            </button>
          </div>

          <pre
            className="code-block"
            style={{
              maxHeight: "340px",
              overflow: "auto",
              padding: "0.9rem",
              fontSize: "0.76rem"
            }}
          >
            {activeArtifactText}
          </pre>

          <div
            style={{
              marginTop: "0.65rem",
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              fontSize: "0.76rem",
              color: "var(--text-secondary)"
            }}
          >
            <CheckCircle2 size={14} style={{ color: "var(--accent-success)" }} />
            <span>
              Checked into repository under{" "}
              <code>integration-artifacts/wso2-mi-synapse/EnterpriseOrderIntegrationAPI.xml</code>,{" "}
              <code>integration-artifacts/wso2-apim/api.yaml</code>, and{" "}
              <code>integration-artifacts/ballerina/order_integration_service.bal</code>.
            </span>
          </div>
        </div>
      )}
    </section>
  );
});
