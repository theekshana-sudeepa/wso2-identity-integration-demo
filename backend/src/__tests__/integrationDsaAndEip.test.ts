import crypto from "node:crypto";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildStandardMediationDagNodes,
  CircuitBreakerFsm,
  DoublyLinkedLruTtlCache,
  MinHeapRetryQueue,
  planMediationDag,
  RadixRouteTrie,
  TokenBucketThrottler
} from "../dsa/integrationDsaEngine.js";
import { createApp } from "../server.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

describe("Core DSA Engine & WSO2 APIM + Micro Integrator EIP Suite", () => {
  it("1. RadixRouteTrie matches static, parametric (:param / {param}), and wildcard routes in O(k) segments", () => {
    const trie = new RadixRouteTrie<string>();
    trie.insert("POST", "/api/integration/orders/:orderId/mediate", "mediate-order");
    trie.insert("GET", "/api/integration/orders/{orderId}/status", "order-status");
    trie.insert("POST", "/api/mcp/*", "mcp-wildcard");

    expect(trie.size()).toBe(3);

    const match1 = trie.lookup("POST", "/api/integration/orders/ORD-2026-99201/mediate");
    expect(match1.matched).toBe(true);
    if (match1.matched) {
      expect(match1.meta).toBe("mediate-order");
      expect(match1.params).toEqual({ orderId: "ORD-2026-99201" });
      expect(match1.traversedSegments).toBe(5);
    }

    const match2 = trie.lookup("GET", "/api/integration/orders/ORD-777/status?verbose=true");
    expect(match2.matched).toBe(true);
    if (match2.matched) {
      expect(match2.meta).toBe("order-status");
      expect(match2.params).toEqual({ orderId: "ORD-777" });
    }

    const wildcardMatch = trie.lookup("POST", "/api/mcp/tools/call/deep");
    expect(wildcardMatch.matched).toBe(true);
    if (wildcardMatch.matched) {
      expect(wildcardMatch.meta).toBe("mcp-wildcard");
    }

    const miss = trie.lookup("DELETE", "/api/integration/orders/ORD-1/mediate");
    expect(miss.matched).toBe(false);
  });

  it("2. DoublyLinkedLruTtlCache maintains strict O(1) MRU->LRU pointer order, capacity eviction, and TTL expiry", () => {
    const cache = new DoublyLinkedLruTtlCache<string, number>(3, 1000);
    const t0 = 1_000_000;

    cache.put("A", 1, 1000, t0);
    cache.put("B", 2, 1000, t0);
    cache.put("C", 3, 1000, t0);
    expect(cache.snapshotOrder()).toEqual(["C", "B", "A"]);

    // Accessing "A" splices it to MRU head in O(1)
    expect(cache.get("A", t0 + 100)).toBe(1);
    expect(cache.snapshotOrder()).toEqual(["A", "C", "B"]);

    // Inserting "D" at capacity 3 evicts LRU tail ("B")
    cache.put("D", 4, 1000, t0 + 200);
    expect(cache.snapshotOrder()).toEqual(["D", "A", "C"]);
    expect(cache.get("B", t0 + 200)).toBeUndefined();

    // TTL expiration evicts expired entry on get
    expect(cache.get("C", t0 + 1500)).toBeUndefined();
    const telemetry = cache.getTelemetry();
    expect(telemetry.hits).toBe(1);
    expect(telemetry.evictions).toBe(1);
  });

  it("3. TokenBucketThrottler enforces WSO2 APIM Subscription Tiers with O(1) lazy continuous refill", () => {
    const throttler = new TokenBucketThrottler();
    const t0 = 2_000_000;

    // Bronze tier has burstCapacity = 5, refill = 1/sec
    const fullConsume = throttler.tryConsume("alice@wso2.com", "Bronze", 5, t0);
    expect(fullConsume.allowed).toBe(true);
    expect(fullConsume.remainingTokens).toBe(0);

    // Immediate next request is throttled out (429)
    const blocked = throttler.tryConsume("alice@wso2.com", "Bronze", 1, t0);
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSeconds).toBe(1);
    expect(blocked.headers["X-WSO2-Throttle-Tier"]).toBe("Bronze");

    // Advance clock by 2.5 seconds -> 2.5 tokens refilled
    const afterRefill = throttler.tryConsume("alice@wso2.com", "Bronze", 2, t0 + 2500);
    expect(afterRefill.allowed).toBe(true);
    expect(afterRefill.remainingTokens).toBe(0);
  });

  it("4. CircuitBreakerFsm + MinHeapRetryQueue handle CLOSED -> OPEN -> HALF_OPEN -> CLOSED and O(log n) DLQ ordering", () => {
    const cb = new CircuitBreakerFsm({
      failureThreshold: 2,
      openDurationMs: 5000,
      halfOpenSuccessThreshold: 1
    });
    const t0 = 3_000_000;

    expect(cb.snapshot().state).toBe("CLOSED");
    cb.recordFailure(t0);
    expect(cb.snapshot().state).toBe("CLOSED");
    cb.recordFailure(t0 + 100);
    expect(cb.snapshot().state).toBe("OPEN");
    expect(cb.canExecute(t0 + 1000).permitted).toBe(false);

    // Cooldown elapsed -> transitions to HALF_OPEN
    const probe = cb.canExecute(t0 + 5200);
    expect(probe.permitted).toBe(true);
    expect(probe.state).toBe("HALF_OPEN");

    // Probe succeeds -> transitions back to CLOSED
    expect(cb.recordSuccess().state).toBe("CLOSED");

    // Min-Heap Retry Queue orders by earliest nextRetryEpochMs with priority tie-breaker
    const minHeap = new MinHeapRetryQueue<string>();
    minHeap.enqueue({
      messageId: "msg-late",
      attempt: 3,
      nextRetryEpochMs: t0 + 8000,
      priority: 5,
      targetEndpoint: "ep",
      payload: "late"
    });
    minHeap.enqueue({
      messageId: "msg-earliest-low-prio",
      attempt: 1,
      nextRetryEpochMs: t0 + 2000,
      priority: 5,
      targetEndpoint: "ep",
      payload: "early-low"
    });
    minHeap.enqueue({
      messageId: "msg-earliest-high-prio",
      attempt: 1,
      nextRetryEpochMs: t0 + 2000,
      priority: 1,
      targetEndpoint: "ep",
      payload: "early-high"
    });

    expect(minHeap.peek()?.messageId).toBe("msg-earliest-high-prio");
    expect(minHeap.dequeue()?.messageId).toBe("msg-earliest-high-prio");
    expect(minHeap.dequeue()?.messageId).toBe("msg-earliest-low-prio");
    expect(minHeap.dequeue()?.messageId).toBe("msg-late");
  });

  it("5. planMediationDag computes O(V + E) parallel topological waves and detects cyclic mediator dependencies", () => {
    const acyclicPlan = planMediationDag(buildStandardMediationDagNodes(false));
    expect(acyclicPlan.ok).toBe(true);
    if (acyclicPlan.ok) {
      expect(acyclicPlan.vertexCount).toBe(10);
      // Wave 5 contains the 3 concurrent Clone branches
      const cloneWave = acyclicPlan.parallelWaves.find((wave) => wave.length === 3);
      expect(cloneWave).toEqual([
        "MI_Clone_OrderService",
        "MI_Clone_InventoryService",
        "MI_Clone_FraudRiskService"
      ]);
    }

    const cyclicPlan = planMediationDag(buildStandardMediationDagNodes(true));
    expect(cyclicPlan.ok).toBe(false);
    if (!cyclicPlan.ok) {
      expect(cyclicPlan.error).toBe("mediation_dag_cycle_detected");
      expect(cyclicPlan.cycleNodes.length).toBeGreaterThan(0);
    }
  });
});

describe("Live Express WSO2 APIM & Micro Integrator Endpoints (/api/integration/*)", () => {
  let server: Server;
  let baseUrl = "";
  let developerToken = "";

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

    const verifier = crypto.randomBytes(36).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");
    const authzRes = await fetch(`${baseUrl}/dev-idp/oauth2/authorize`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        persona: "developer",
        code_challenge: challenge,
        code_challenge_method: "S256"
      })
    });
    const authzBody = (await authzRes.json()) as { code: string };
    const tokenRes = await fetch(`${baseUrl}/dev-idp/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code: authzBody.code,
        code_verifier: verifier
      })
    });
    const tokenBody = (await tokenRes.json()) as { access_token: string };
    developerToken = tokenBody.access_token;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("executes nominal WSO2 APIM + MI Scatter-Gather mediation, mints X-JWT-Assertion, and caches in Doubly-Linked LRU", async () => {
    await fetch(`${baseUrl}/api/integration/reset`, { method: "POST" });

    const res1 = await fetch(`${baseUrl}/api/integration/orders/ORD-2026-99201/mediate`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${developerToken}`,
        "X-WSO2-Subscription-Tier": "Silver"
      },
      body: JSON.stringify({
        tier: "Silver",
        faultMode: "nominal",
        order: {
          orderId: "ORD-2026-99201",
          customerId: "CUST-ENT-4410",
          amountUsd: 2450,
          currency: "USD",
          region: "US-EAST",
          priority: "HIGH_RISK"
        }
      })
    });

    expect(res1.status).toBe(200);
    expect(res1.headers.get("x-wso2-throttle-tier")).toBe("Silver");
    expect(res1.headers.get("x-jwt-assertion")).toBeTruthy();

    const body1: unknown = await res1.json();
    expect(isRecord(body1)).toBe(true);
    if (isRecord(body1) && isRecord(body1.apimGateway) && isRecord(body1.microIntegrator)) {
      expect(body1.apimGateway.responseCacheStatus).toBe("MISS");
      expect(body1.microIntegrator.selectedCbrRoute).toBe("HIGH_VALUE_FRAUD_SCREEN");
    }

    // Second identical call hits the O(1) Doubly-Linked LRU Cache
    const res2 = await fetch(`${baseUrl}/api/integration/orders/ORD-2026-99201/mediate`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${developerToken}`
      },
      body: JSON.stringify({
        tier: "Silver",
        faultMode: "nominal",
        order: {
          orderId: "ORD-2026-99201",
          customerId: "CUST-ENT-4410",
          amountUsd: 2450,
          currency: "USD",
          region: "US-EAST",
          priority: "HIGH_RISK"
        }
      })
    });
    const body2 = (await res2.json()) as {
      apimGateway: { responseCacheStatus: string };
    };
    expect(body2.apimGateway.responseCacheStatus).toBe("HIT");
  });

  it("enforces WSO2 APIM 429 Token Bucket quota burst, Circuit Breaker + Min-Heap DLQ failover, and DAG cycle rejection", async () => {
    // 1. 429 Throttle Spike
    const throttleRes = await fetch(`${baseUrl}/api/integration/orders/ORD-2026-429/mediate`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${developerToken}`
      },
      body: JSON.stringify({
        tier: "Bronze",
        faultMode: "throttle_spike"
      })
    });
    expect(throttleRes.status).toBe(429);
    expect(throttleRes.headers.get("retry-after")).toBeTruthy();

    // 2. Upstream Inventory Failure -> Circuit Breaker OPEN + Min-Heap DLQ enqueue
    await fetch(`${baseUrl}/api/integration/reset`, { method: "POST" });
    const cbRes = await fetch(`${baseUrl}/api/integration/orders/ORD-2026-CB/mediate`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${developerToken}`
      },
      body: JSON.stringify({
        tier: "Gold",
        faultMode: "upstream_timeout_cb"
      })
    });
    expect(cbRes.status).toBe(200);
    const cbBody = (await cbRes.json()) as {
      microIntegrator: {
        circuitBreaker: { state: string };
        retryQueueDlqSnapshot: unknown[];
      };
    };
    expect(cbBody.microIntegrator.circuitBreaker.state).toBe("OPEN");
    expect(cbBody.microIntegrator.retryQueueDlqSnapshot.length).toBe(1);

    // 3. Cyclic Mediation Graph -> 400 Bad Request
    const dagRes = await fetch(`${baseUrl}/api/integration/orders/ORD-2026-DAG/mediate`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${developerToken}`
      },
      body: JSON.stringify({
        tier: "Gold",
        faultMode: "dag_cycle_fault"
      })
    });
    expect(dagRes.status).toBe(400);

    // 4. GET /api/integration/dsa-telemetry
    const telemetryRes = await fetch(`${baseUrl}/api/integration/dsa-telemetry`);
    expect(telemetryRes.status).toBe(200);
  });
});
