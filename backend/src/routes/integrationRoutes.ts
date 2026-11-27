import express, { type RequestHandler, type Router } from "express";
import {
  APIM_SUBSCRIPTION_TIERS,
  buildStandardMediationDagNodes,
  defaultIntegrationEngine,
  planMediationDag,
  type ApimSubscriptionTier,
  type IntegrationFaultMode,
  type IntegrationOrderPayload
} from "../dsa/integrationDsaEngine.js";
import { authenticateToken } from "../middleware/authMiddleware.js";
import { sendBearerError } from "../middleware/bearerChallenge.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseSubscriptionTier(raw: unknown): ApimSubscriptionTier {
  if (raw === "Bronze" || raw === "Silver" || raw === "Gold" || raw === "AI-Agent-MCP") {
    return raw;
  }
  return "Silver";
}

function parseFaultMode(raw: unknown): IntegrationFaultMode {
  if (
    raw === "nominal" ||
    raw === "throttle_spike" ||
    raw === "upstream_timeout_cb" ||
    raw === "dag_cycle_fault"
  ) {
    return raw;
  }
  return "nominal";
}

function parseOrderPayload(body: unknown, paramOrderId?: string): IntegrationOrderPayload {
  const rec = isRecord(body) ? body : {};
  const nestedOrder = isRecord(rec.order) ? rec.order : rec;

  const orderId =
    paramOrderId && paramOrderId.trim().length > 0
      ? paramOrderId.trim()
      : typeof nestedOrder.orderId === "string" && nestedOrder.orderId.trim().length > 0
        ? nestedOrder.orderId.trim()
        : "ORD-2026-99201";
  const customerId =
    typeof nestedOrder.customerId === "string" && nestedOrder.customerId.trim().length > 0
      ? nestedOrder.customerId.trim()
      : "CUST-LK-8841";
  const amountUsd =
    typeof nestedOrder.amountUsd === "number" && Number.isFinite(nestedOrder.amountUsd)
      ? Math.max(1, nestedOrder.amountUsd)
      : 1450.0;
  const currency = nestedOrder.currency === "EUR" ? "EUR" : "USD";
  const region =
    nestedOrder.region === "EU" || nestedOrder.region === "APAC"
      ? nestedOrder.region
      : "US-EAST";
  const priority = nestedOrder.priority === "HIGH_RISK" ? "HIGH_RISK" : "STANDARD";

  return {
    orderId,
    customerId,
    amountUsd,
    currency,
    region,
    priority,
    items: [
      { sku: "WSO2-APIM-ENTERPRISE-NODE", qty: 2 },
      { sku: "WSO2-MI-SYNAPSE-RUNTIME", qty: 4 }
    ]
  };
}

export function createIntegrationRouter(
  authMiddleware: RequestHandler = authenticateToken
): Router {
  const router = express.Router();

  router.get("/dsa-telemetry", (_req, res) => {
    const dagPlan = planMediationDag(buildStandardMediationDagNodes(false));
    res.status(200).json({
      engine: "WSO2 API Manager 4.x + Micro Integrator EIP + Core DSA Runtime",
      subscriptionTiers: APIM_SUBSCRIPTION_TIERS,
      dsaTelemetry: {
        radixRouteTrie: {
          registeredRoutes: defaultIntegrationEngine.routeTrie.size(),
          sampleLookup: defaultIntegrationEngine.routeTrie.lookup(
            "POST",
            "/api/integration/orders/ORD-2026-99201/mediate"
          ),
          timeComplexity: "O(k) where k = URL path segments",
          spaceComplexity: "O(N * k)"
        },
        doublyLinkedLruCache: defaultIntegrationEngine.responseLruCache.getTelemetry(),
        circuitBreakerFsm: defaultIntegrationEngine.inventoryCircuitBreaker.snapshot(),
        minHeapRetryQueue: {
          size: defaultIntegrationEngine.retryMinHeap.size(),
          nextScheduledMessage: defaultIntegrationEngine.retryMinHeap.peek() ?? null,
          allQueuedMessages: defaultIntegrationEngine.retryMinHeap.toSortedSnapshot(),
          timeComplexity: "O(log n) enqueue/dequeue · O(1) peek"
        },
        mediationDagTopologicalSort: dagPlan
      },
      timestamp: new Date().toISOString()
    });
  });

  router.post("/reset", (_req, res) => {
    defaultIntegrationEngine.responseLruCache.clear();
    defaultIntegrationEngine.throttler.reset();
    defaultIntegrationEngine.inventoryCircuitBreaker.forceState("CLOSED");
    defaultIntegrationEngine.retryMinHeap.clear();
    res.status(200).json({
      reset: true,
      message: "Reset WSO2 APIM Token Buckets, Doubly-Linked LRU Cache, Circuit Breaker FSM, and Min-Heap Retry DLQ.",
      timestamp: new Date().toISOString()
    });
  });

  const handleMediate: RequestHandler = (req, res) => {
    const user = req.user;
    if (!user) {
      sendBearerError(res, 401, null, {
        error: "unauthorized",
        message: "Missing verified OAuth2 RS256 user context at WSO2 API Manager Gateway."
      });
      return;
    }

    const body = isRecord(req.body) ? req.body : {};
    const tier = parseSubscriptionTier(
      body.tier ?? req.headers["x-wso2-subscription-tier"]
    );
    const faultMode = parseFaultMode(body.faultMode);
    const paramOrderId =
      typeof req.params.orderId === "string" ? req.params.orderId : undefined;
    const order = parseOrderPayload(body, paramOrderId);

    const outcome = defaultIntegrationEngine.executeMediation({
      subscriber: user.username || user.sub,
      groups: user.groups,
      tier,
      faultMode,
      order
    });

    for (const [headerName, headerVal] of Object.entries(
      outcome.apimGateway.throttleDecision.headers
    )) {
      res.setHeader(headerName, headerVal);
    }
    res.setHeader(
      "X-JWT-Assertion",
      outcome.apimGateway.backendJwtAssertion.compactJwtPreview
    );
    res.setHeader("X-Correlation-ID", outcome.correlationId);

    res.status(outcome.httpStatus).json(outcome);
  };

  router.post("/mediate", authMiddleware, handleMediate);
  router.post("/orders/:orderId/mediate", authMiddleware, handleMediate);

  return router;
}

export default createIntegrationRouter();
