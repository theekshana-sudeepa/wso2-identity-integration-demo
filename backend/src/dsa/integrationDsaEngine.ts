/**
 * WSO2 API Manager (APIM 4.x) + Micro Integrator (MI / Synapse EIP) + Core DSA Engine
 *
 * Implements 5 textbook Data Structures & Algorithms from first principles (zero external
 * DSA libraries, strict TypeScript, zero `any`) that directly power API Management and
 * Enterprise Integration:
 *  1. Radix Prefix Segment Trie (`RadixRouteTrie`) — O(k) URL path matching & parameter extraction
 *  2. Doubly-Linked List + HashMap LRU Cache with TTL (`DoublyLinkedLruTtlCache`) — strict O(1) get/put/evict
 *  3. Token Bucket Rate Limiter (`TokenBucketThrottler`) — O(1) WSO2 APIM Subscription Tier enforcement
 *  4. Finite State Machine Circuit Breaker (`CircuitBreakerFsm`) + Binary Min-Heap Retry Queue (`MinHeapRetryQueue`) — O(1) FSM & O(log n) Dead-Letter / Message Processor scheduling
 *  5. Directed Acyclic Graph (DAG) Kahn's Topological Sort & Cycle Detector (`MediationDagPlanner`) — O(V + E) WSO2 Micro Integrator mediation sequence verification
 */

export type ApimSubscriptionTier = "Bronze" | "Silver" | "Gold" | "AI-Agent-MCP";

export interface ApimTierPolicy {
  readonly tier: ApimSubscriptionTier;
  readonly burstCapacity: number;
  readonly refillPerSecond: number;
  readonly quotaRpm: number;
  readonly description: string;
}

export const APIM_SUBSCRIPTION_TIERS: Readonly<Record<ApimSubscriptionTier, ApimTierPolicy>> = {
  Bronze: {
    tier: "Bronze",
    burstCapacity: 5,
    refillPerSecond: 1,
    quotaRpm: 60,
    description: "5 burst capacity · 1 token/sec refill (60 req/min)"
  },
  Silver: {
    tier: "Silver",
    burstCapacity: 15,
    refillPerSecond: 3,
    quotaRpm: 180,
    description: "15 burst capacity · 3 tokens/sec refill (180 req/min)"
  },
  Gold: {
    tier: "Gold",
    burstCapacity: 50,
    refillPerSecond: 10,
    quotaRpm: 600,
    description: "50 burst capacity · 10 tokens/sec refill (600 req/min)"
  },
  "AI-Agent-MCP": {
    tier: "AI-Agent-MCP",
    burstCapacity: 10,
    refillPerSecond: 2,
    quotaRpm: 120,
    description: "10 burst capacity · 2 tokens/sec refill (RFC 8693 AI Agent Quota)"
  }
};

// ============================================================================
// 1. Radix Prefix Segment Trie — O(k) API Gateway Route Matching
// ============================================================================

interface TrieNode<T> {
  readonly staticChildren: Map<string, TrieNode<T>>;
  paramChild: { readonly paramName: string; readonly node: TrieNode<T> } | null;
  wildcardChild: TrieNode<T> | null;
   readonly handlers: Map<string, { readonly pattern: string; readonly meta: T }>;
}

function createTrieNode<T>(): TrieNode<T> {
  return {
    staticChildren: new Map(),
    paramChild: null,
    wildcardChild: null,
    handlers: new Map()
  };
}

export interface RadixRouteMatch<T> {
  readonly matched: true;
  readonly method: string;
  readonly pattern: string;
  readonly params: Readonly<Record<string, string>>;
  readonly traversedSegments: number;
  readonly complexity: string;
  readonly meta: T;
}

export interface RadixRouteMiss {
  readonly matched: false;
  readonly method: string;
  readonly traversedSegments: number;
  readonly complexity: string;
}

export type RadixLookupResult<T> = RadixRouteMatch<T> | RadixRouteMiss;

export class RadixRouteTrie<T> {
  private readonly root: TrieNode<T> = createTrieNode<T>();
  private routeCount = 0;

  public insert(method: string, pattern: string, meta: T): void {
    const normalizedMethod = method.toUpperCase().trim();
    const segments = this.splitSegments(pattern);
    let current = this.root;

    for (const seg of segments) {
      if (seg === "*") {
        if (!current.wildcardChild) {
          current.wildcardChild = createTrieNode<T>();
        }
        current = current.wildcardChild;
        break;
      }

      const paramName = this.extractParamName(seg);
      if (paramName) {
        if (!current.paramChild) {
          current.paramChild = { paramName, node: createTrieNode<T>() };
        }
        current = current.paramChild.node;
      } else {
        let next = current.staticChildren.get(seg);
        if (!next) {
          next = createTrieNode<T>();
          current.staticChildren.set(seg, next);
        }
        current = next;
      }
    }

    if (!current.handlers.has(normalizedMethod)) {
      this.routeCount += 1;
    }
    current.handlers.set(normalizedMethod, { pattern, meta });
  }

  public lookup(method: string, path: string): RadixLookupResult<T> {
    const normalizedMethod = method.toUpperCase().trim();
    const segments = this.splitSegments(path);
    const params: Record<string, string> = {};
    let current: TrieNode<T> | undefined = this.root;
    let wildcardFallback: { readonly node: TrieNode<T>; readonly depth: number } | null = null;
    let hops = 0;

    for (const seg of segments) {
      hops += 1;
      if (!current) {
        break;
      }
      if (current.wildcardChild) {
        wildcardFallback = { node: current.wildcardChild, depth: hops };
      }

      const staticNext = current.staticChildren.get(seg);
      if (staticNext) {
        current = staticNext;
        continue;
      }

      if (current.paramChild) {
        params[current.paramChild.paramName] = seg;
        current = current.paramChild.node;
        continue;
      }

      if (current.wildcardChild) {
        current = current.wildcardChild;
        break;
      }

      current = undefined;
      break;
    }

    const resolvedNode =
      current && current.handlers.has(normalizedMethod)
        ? current
        : wildcardFallback && wildcardFallback.node.handlers.has(normalizedMethod)
          ? wildcardFallback.node
          : null;

    const handler = resolvedNode?.handlers.get(normalizedMethod);
    const complexity = `O(k) Radix Trie lookup (k = ${segments.length} segments, N = ${this.routeCount} routes)`;

    if (!handler) {
      return {
        matched: false,
        method: normalizedMethod,
        traversedSegments: hops,
        complexity
      };
    }

    return {
      matched: true,
      method: normalizedMethod,
      pattern: handler.pattern,
      params,
      traversedSegments: hops,
      complexity,
      meta: handler.meta
    };
  }

  public size(): number {
    return this.routeCount;
  }

  private splitSegments(rawPath: string): string[] {
    const clean = rawPath.split("?")[0] ?? rawPath;
    return clean
      .split("/")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  private extractParamName(segment: string): string | null {
    if (segment.startsWith(":") && segment.length > 1) {
      return segment.slice(1);
    }
    if (segment.startsWith("{") && segment.endsWith("}") && segment.length > 2) {
      return segment.slice(1, -1);
    }
    return null;
  }
}

// ============================================================================
// 2. Doubly-Linked List + HashMap LRU Cache with TTL — Strict O(1) get/put
// ============================================================================

interface DoublyLinkedNode<K, V> {
  readonly key: K;
  value: V;
  expiresAtMs: number;
  prev: DoublyLinkedNode<K, V> | null;
  next: DoublyLinkedNode<K, V> | null;
}

export interface LruCacheTelemetry<K> {
  readonly capacity: number;
  readonly size: number;
  readonly hits: number;
  readonly misses: number;
  readonly evictions: number;
  readonly hitRatio: number;
  readonly mruToLruKeys: readonly K[];
  readonly complexity: string;
}

export class DoublyLinkedLruTtlCache<K, V> {
  private readonly capacity: number;
  private readonly defaultTtlMs: number;
  private readonly map = new Map<K, DoublyLinkedNode<K, V>>();
  private head: DoublyLinkedNode<K, V> | null = null;
  private tail: DoublyLinkedNode<K, V> | null = null;
  private hits = 0;
  private misses = 0;
  private evictions = 0;

  constructor(capacity: number, defaultTtlMs = 60_000) {
    if (capacity < 1) {
      throw new Error("LRU cache capacity must be >= 1");
    }
    this.capacity = capacity;
    this.defaultTtlMs = defaultTtlMs;
  }

  public get(key: K, nowMs = Date.now()): V | undefined {
    const node = this.map.get(key);
    if (!node) {
      this.misses += 1;
      return undefined;
    }

    if (node.expiresAtMs <= nowMs) {
      this.removeNode(node);
      this.map.delete(key);
      this.misses += 1;
      return undefined;
    }

    this.hits += 1;
    this.moveToFront(node);
    return node.value;
  }

  public put(key: K, value: V, ttlMs = this.defaultTtlMs, nowMs = Date.now()): void {
    const existing = this.map.get(key);
    if (existing) {
      existing.value = value;
      existing.expiresAtMs = nowMs + ttlMs;
      this.moveToFront(existing);
      return;
    }

    if (this.map.size >= this.capacity && this.tail) {
      const lruKey = this.tail.key;
      this.removeNode(this.tail);
      this.map.delete(lruKey);
      this.evictions += 1;
    }

    const newNode: DoublyLinkedNode<K, V> = {
      key,
      value,
      expiresAtMs: nowMs + ttlMs,
      prev: null,
      next: null
    };
    this.insertAtFront(newNode);
    this.map.set(key, newNode);
  }

  public snapshotOrder(): readonly K[] {
    const order: K[] = [];
    let curr = this.head;
    while (curr) {
      order.push(curr.key);
      curr = curr.next;
    }
    return order;
  }

  public getTelemetry(): LruCacheTelemetry<K> {
    const total = this.hits + this.misses;
    return {
      capacity: this.capacity,
      size: this.map.size,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      hitRatio: total > 0 ? Number((this.hits / total).toFixed(3)) : 0,
      mruToLruKeys: this.snapshotOrder(),
      complexity: "O(1) HashMap lookup + O(1) Doubly-Linked List pointer splice"
    };
  }

  public clear(): void {
    this.map.clear();
    this.head = null;
    this.tail = null;
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
  }

  private moveToFront(node: DoublyLinkedNode<K, V>): void {
    if (this.head === node) {
      return;
    }
    this.removeNode(node);
    this.insertAtFront(node);
  }

  private insertAtFront(node: DoublyLinkedNode<K, V>): void {
    node.prev = null;
    node.next = this.head;
    if (this.head) {
      this.head.prev = node;
    }
    this.head = node;
    if (!this.tail) {
      this.tail = node;
    }
  }

  private removeNode(node: DoublyLinkedNode<K, V>): void {
    if (node.prev) {
      node.prev.next = node.next;
    } else {
      this.head = node.next;
    }

    if (node.next) {
      node.next.prev = node.prev;
    } else {
      this.tail = node.prev;
    }

    node.prev = null;
    node.next = null;
  }
}

// ============================================================================
// 3. Token Bucket Rate Limiter — O(1) WSO2 APIM Subscription Tier Throttling
// ============================================================================

interface TokenBucketState {
  tokens: number;
  lastRefillMs: number;
}

export interface TokenBucketDecision {
  readonly allowed: boolean;
  readonly tier: ApimSubscriptionTier;
  readonly capacity: number;
  readonly remainingTokens: number;
  readonly refillPerSecond: number;
  readonly retryAfterSeconds: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly complexity: string;
}

export class TokenBucketThrottler {
  private readonly buckets = new Map<string, TokenBucketState>();

  public tryConsume(
    subscriberKey: string,
    tier: ApimSubscriptionTier,
    cost = 1,
    nowMs = Date.now()
  ): TokenBucketDecision {
    const policy = APIM_SUBSCRIPTION_TIERS[tier];
    const bucketKey = `${subscriberKey}:${tier}`;
    let state = this.buckets.get(bucketKey);

    if (!state) {
      if (this.buckets.size > 2000) {
        this.buckets.clear();
      }
      state = {
        tokens: policy.burstCapacity,
        lastRefillMs: nowMs
      };
      this.buckets.set(bucketKey, state);
    } else {
      const elapsedSec = Math.max(0, (nowMs - state.lastRefillMs) / 1000);
      const refilled = elapsedSec * policy.refillPerSecond;
      state.tokens = Math.min(policy.burstCapacity, state.tokens + refilled);
      state.lastRefillMs = nowMs;
    }

    if (state.tokens >= cost) {
      state.tokens -= cost;
      const remaining = Math.floor(state.tokens);
      return {
        allowed: true,
        tier,
        capacity: policy.burstCapacity,
        remainingTokens: remaining,
        refillPerSecond: policy.refillPerSecond,
        retryAfterSeconds: 0,
        headers: {
          "X-WSO2-Throttle-Tier": tier,
          "X-RateLimit-Limit": String(policy.burstCapacity),
          "X-RateLimit-Remaining": String(remaining)
        },
        complexity: "O(1) lazy continuous token refill math"
      };
    }

    const deficit = cost - state.tokens;
    const retryAfterSeconds = Math.max(1, Math.ceil(deficit / policy.refillPerSecond));
    return {
      allowed: false,
      tier,
      capacity: policy.burstCapacity,
      remainingTokens: 0,
      refillPerSecond: policy.refillPerSecond,
      retryAfterSeconds,
      headers: {
        "X-WSO2-Throttle-Tier": tier,
        "X-RateLimit-Limit": String(policy.burstCapacity),
        "X-RateLimit-Remaining": "0",
        "Retry-After": String(retryAfterSeconds)
      },
      complexity: "O(1) lazy continuous token refill math"
    };
  }

  public reset(): void {
    this.buckets.clear();
  }
}

// ============================================================================
// 4A. Finite State Machine (FSM) Circuit Breaker — O(1) Endpoint Resiliency
// ============================================================================

export type CircuitBreakerState = "CLOSED" | "OPEN" | "HALF_OPEN";

export interface CircuitBreakerSnapshot {
  readonly state: CircuitBreakerState;
  readonly consecutiveFailures: number;
  readonly failureThreshold: number;
  readonly openDurationMs: number;
  readonly halfOpenSuccesses: number;
  readonly nextAttemptAtMs: number | null;
  readonly complexity: string;
}

export class CircuitBreakerFsm {
  private state: CircuitBreakerState = "CLOSED";
  private consecutiveFailures = 0;
  private halfOpenSuccesses = 0;
  private openedAtMs: number | null = null;
  private readonly failureThreshold: number;
  private readonly openDurationMs: number;
  private readonly halfOpenSuccessThreshold: number;

  constructor(options?: {
    readonly failureThreshold?: number;
    readonly openDurationMs?: number;
    readonly halfOpenSuccessThreshold?: number;
  }) {
    this.failureThreshold = options?.failureThreshold ?? 3;
    this.openDurationMs = options?.openDurationMs ?? 15_000;
    this.halfOpenSuccessThreshold = options?.halfOpenSuccessThreshold ?? 1;
  }

  public canExecute(nowMs = Date.now()): {
    readonly permitted: boolean;
    readonly state: CircuitBreakerState;
    readonly transitionedFromOpenToHalfOpen: boolean;
  } {
    if (this.state === "CLOSED") {
      return { permitted: true, state: "CLOSED", transitionedFromOpenToHalfOpen: false };
    }

    if (this.state === "OPEN") {
      if (this.openedAtMs !== null && nowMs - this.openedAtMs >= this.openDurationMs) {
        this.state = "HALF_OPEN";
        this.halfOpenSuccesses = 0;
        return { permitted: true, state: "HALF_OPEN", transitionedFromOpenToHalfOpen: true };
      }
      return { permitted: false, state: "OPEN", transitionedFromOpenToHalfOpen: false };
    }

    return { permitted: true, state: "HALF_OPEN", transitionedFromOpenToHalfOpen: false };
  }

  public recordSuccess(): CircuitBreakerSnapshot {
    if (this.state === "HALF_OPEN") {
      this.halfOpenSuccesses += 1;
      if (this.halfOpenSuccesses >= this.halfOpenSuccessThreshold) {
        this.state = "CLOSED";
        this.consecutiveFailures = 0;
        this.halfOpenSuccesses = 0;
        this.openedAtMs = null;
      }
    } else {
      this.consecutiveFailures = 0;
    }
    return this.snapshot();
  }

  public recordFailure(nowMs = Date.now()): CircuitBreakerSnapshot {
    this.consecutiveFailures += 1;
    if (this.state === "HALF_OPEN" || this.consecutiveFailures >= this.failureThreshold) {
      this.state = "OPEN";
      this.openedAtMs = nowMs;
      this.halfOpenSuccesses = 0;
    }
    return this.snapshot();
  }

  public forceState(nextState: CircuitBreakerState, nowMs = Date.now()): CircuitBreakerSnapshot {
    this.state = nextState;
    if (nextState === "OPEN") {
      this.consecutiveFailures = this.failureThreshold;
      this.openedAtMs = nowMs;
    } else if (nextState === "CLOSED") {
      this.consecutiveFailures = 0;
      this.halfOpenSuccesses = 0;
      this.openedAtMs = null;
    }
    return this.snapshot();
  }

  public snapshot(): CircuitBreakerSnapshot {
    return {
      state: this.state,
      consecutiveFailures: this.consecutiveFailures,
      failureThreshold: this.failureThreshold,
      openDurationMs: this.openDurationMs,
      halfOpenSuccesses: this.halfOpenSuccesses,
      nextAttemptAtMs:
        this.state === "OPEN" && this.openedAtMs !== null
          ? this.openedAtMs + this.openDurationMs
          : null,
      complexity: "O(1) deterministic Finite State Machine transition"
    };
  }
}

// ============================================================================
// 4B. Binary Min-Heap Priority Queue — O(log n) Message Store Retry Scheduler
// ============================================================================

export interface ScheduledRetryMessage<T> {
  readonly messageId: string;
  readonly attempt: number;
  readonly nextRetryEpochMs: number;
  readonly priority: number;
  readonly targetEndpoint: string;
  readonly payload: T;
}

export class MinHeapRetryQueue<T> {
  private readonly heap: ScheduledRetryMessage<T>[] = [];

  public enqueue(item: ScheduledRetryMessage<T>): void {
    this.heap.push(item);
    this.siftUp(this.heap.length - 1);
  }

  public peek(): ScheduledRetryMessage<T> | undefined {
    return this.heap[0];
  }

  public dequeue(): ScheduledRetryMessage<T> | undefined {
    if (this.heap.length === 0) {
      return undefined;
    }
    const top = this.heap[0];
    const last = this.heap.pop();
    if (this.heap.length > 0 && last !== undefined) {
      this.heap[0] = last;
      this.siftDown(0);
    }
    return top;
  }

  public size(): number {
    return this.heap.length;
  }

  public toSortedSnapshot(): readonly ScheduledRetryMessage<T>[] {
    return [...this.heap].sort((a, b) => this.compare(a, b));
  }

  public clear(): void {
    this.heap.length = 0;
  }

  private compare(a: ScheduledRetryMessage<T>, b: ScheduledRetryMessage<T>): number {
    if (a.nextRetryEpochMs !== b.nextRetryEpochMs) {
      return a.nextRetryEpochMs - b.nextRetryEpochMs;
    }
    return a.priority - b.priority;
  }

  private siftUp(index: number): void {
    let idx = index;
    while (idx > 0) {
      const parentIdx = (idx - 1) >> 1;
      const current = this.heap[idx];
      const parent = this.heap[parentIdx];
      if (!current || !parent || this.compare(current, parent) >= 0) {
        break;
      }
      this.heap[idx] = parent;
      this.heap[parentIdx] = current;
      idx = parentIdx;
    }
  }

  private siftDown(index: number): void {
    let idx = index;
    const length = this.heap.length;

    while (true) {
      const leftIdx = idx * 2 + 1;
      const rightIdx = idx * 2 + 2;
      let smallestIdx = idx;

      const smallestNode = this.heap[smallestIdx];
      const leftNode = this.heap[leftIdx];
      if (
        leftIdx < length &&
        leftNode &&
        smallestNode &&
        this.compare(leftNode, smallestNode) < 0
      ) {
        smallestIdx = leftIdx;
      }

      const updatedSmallest = this.heap[smallestIdx];
      const rightNode = this.heap[rightIdx];
      if (
        rightIdx < length &&
        rightNode &&
        updatedSmallest &&
        this.compare(rightNode, updatedSmallest) < 0
      ) {
        smallestIdx = rightIdx;
      }

      if (smallestIdx === idx) {
        break;
      }

      const current = this.heap[idx];
      const target = this.heap[smallestIdx];
      if (current && target) {
        this.heap[idx] = target;
        this.heap[smallestIdx] = current;
      }
      idx = smallestIdx;
    }
  }
}

// ============================================================================
// 5. Directed Acyclic Graph (DAG) Kahn's Topological Planner — O(V + E)
// ============================================================================

export interface MediationStepNode {
  readonly id: string;
  readonly mediatorType:
    | "APIM_Auth"
    | "APIM_Throttle"
    | "APIM_BackendJWT"
    | "MI_CBR_Switch"
    | "MI_Clone_Branch"
    | "MI_Aggregate"
    | "MI_PayloadFactory"
    | "MI_Respond";
  readonly description: string;
  readonly dependsOn: readonly string[];
}

export type DagScheduleResult =
  | {
      readonly ok: true;
      readonly topologicalOrder: readonly string[];
      readonly parallelWaves: ReadonlyArray<readonly string[]>;
      readonly vertexCount: number;
      readonly edgeCount: number;
      readonly complexity: string;
    }
  | {
      readonly ok: false;
      readonly error: "mediation_dag_cycle_detected";
      readonly cycleNodes: readonly string[];
      readonly vertexCount: number;
      readonly edgeCount: number;
      readonly complexity: string;
    };

/**
 * Executes Kahn's BFS topological sort with level-order parallel wave grouping
 * in O(V + E) time to schedule WSO2 Micro Integrator mediation sequences and
 * detect cyclic mediator dependencies.
 */
export function planMediationDag(nodes: readonly MediationStepNode[]): DagScheduleResult {
  const inDegree = new Map<string, number>();
  const adjacency = new Map<string, string[]>();
  let edgeCount = 0;

  for (const node of nodes) {
    inDegree.set(node.id, 0);
    adjacency.set(node.id, []);
  }

  for (const node of nodes) {
    for (const dep of node.dependsOn) {
      if (!adjacency.has(dep)) {
        continue;
      }
      adjacency.get(dep)?.push(node.id);
      inDegree.set(node.id, (inDegree.get(node.id) ?? 0) + 1);
      edgeCount += 1;
    }
  }

  let currentWave: string[] = [];
  for (const [id, deg] of inDegree.entries()) {
    if (deg === 0) {
      currentWave.push(id);
    }
  }

  const topologicalOrder: string[] = [];
  const parallelWaves: string[][] = [];

  while (currentWave.length > 0) {
    parallelWaves.push([...currentWave]);
    const nextWave: string[] = [];

    for (const currentId of currentWave) {
      topologicalOrder.push(currentId);
      const neighbors = adjacency.get(currentId) ?? [];
      for (const neighbor of neighbors) {
        const nextDeg = (inDegree.get(neighbor) ?? 1) - 1;
        inDegree.set(neighbor, nextDeg);
        if (nextDeg === 0) {
          nextWave.push(neighbor);
        }
      }
    }

    currentWave = nextWave;
  }

  const vertexCount = nodes.length;
  const complexity = `O(V + E) Kahn's BFS Topological Sort (V = ${vertexCount} mediators, E = ${edgeCount} edges)`;

  if (topologicalOrder.length !== vertexCount) {
    const cycleNodes: string[] = [];
    for (const [id, deg] of inDegree.entries()) {
      if (deg > 0) {
        cycleNodes.push(id);
      }
    }
    return {
      ok: false,
      error: "mediation_dag_cycle_detected",
      cycleNodes,
      vertexCount,
      edgeCount,
      complexity
    };
  }

  return {
    ok: true,
    topologicalOrder,
    parallelWaves,
    vertexCount,
    edgeCount,
    complexity
  };
}

// ============================================================================
// 6. WSO2 API Manager + Micro Integrator EIP Runtime Simulator & Orchestrator
// ============================================================================

export type IntegrationFaultMode =
  | "nominal"
  | "throttle_spike"
  | "upstream_timeout_cb"
  | "dag_cycle_fault";

export type CbrRouteKey =
  | "HIGH_VALUE_FRAUD_SCREEN"
  | "EU_GDPR_COMPLIANCE_ROUTE"
  | "FAST_TRACK_STANDARD_ROUTE";

export interface IntegrationOrderPayload {
  readonly orderId: string;
  readonly customerId: string;
  readonly amountUsd: number;
  readonly currency: "USD" | "EUR";
  readonly region: "US-EAST" | "EU" | "APAC";
  readonly items: readonly { readonly sku: string; readonly qty: number }[];
  readonly priority: "STANDARD" | "HIGH_RISK";
}

export interface UpstreamBranchCall {
  readonly branchId: string;
  readonly serviceName: string;
  readonly endpointUrl: string;
  readonly status: "SUCCESS" | "FALLBACK_REPLICA" | "FAILED_ENQUEUED_DLQ";
  readonly latencyMs: number;
  readonly payloadSnippet: Record<string, unknown>;
}

export interface Wso2BackendJwtAssertion {
  readonly header: {
    readonly alg: "RS256";
    readonly typ: "JWT";
    readonly kid: string;
  };
  readonly claims: {
    readonly iss: "wso2.org/products/am";
    readonly exp: number;
    readonly "http://wso2.org/claims/subscriber": string;
    readonly "http://wso2.org/claims/applicationname": string;
    readonly "http://wso2.org/claims/apicontext": string;
    readonly "http://wso2.org/claims/version": string;
    readonly "http://wso2.org/claims/tier": ApimSubscriptionTier;
    readonly "http://wso2.org/claims/keytype": "PRODUCTION";
    readonly "http://wso2.org/claims/enduser": string;
    readonly "http://wso2.org/claims/role": readonly string[];
  };
  readonly compactJwtPreview: string;
}

export interface EipMediationResponse {
  readonly ok: boolean;
  readonly httpStatus: 200 | 400 | 429 | 502;
  readonly correlationId: string;
  readonly faultMode: IntegrationFaultMode;
  readonly apimGateway: {
    readonly routeMatch: RadixLookupResult<{ readonly apiName: string; readonly version: string }>;
    readonly throttleDecision: TokenBucketDecision;
    readonly responseCacheStatus: "HIT" | "MISS" | "BYPASSED";
    readonly lruCacheTelemetry: LruCacheTelemetry<string>;
    readonly backendJwtAssertion: Wso2BackendJwtAssertion;
  };
  readonly microIntegrator: {
    readonly dagPlan: DagScheduleResult;
    readonly selectedCbrRoute: CbrRouteKey;
    readonly cbrExpression: string;
    readonly scatterGatherBranches: readonly UpstreamBranchCall[];
    readonly sequentialLatencySumMs: number;
    readonly parallelAggregatedLatencyMs: number;
    readonly payloadFactoryTransform: {
      readonly legacyUpstreamXml: string;
      readonly canonicalEnterpriseJson: Record<string, unknown>;
    };
    readonly circuitBreaker: CircuitBreakerSnapshot;
    readonly retryQueueDlqSnapshot: ReadonlyArray<ScheduledRetryMessage<IntegrationOrderPayload>>;
  };
  readonly timestamp: string;
}

function encodeBase64UrlSegment(obj: unknown): string {
  const json = JSON.stringify(obj);
  if (typeof Buffer !== "undefined") {
    return Buffer.from(json, "utf8").toString("base64url");
  }
  const bytes = new TextEncoder().encode(json);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function buildWso2BackendJwtAssertion(input: {
  readonly sub: string;
  readonly groups: readonly string[];
  readonly tier: ApimSubscriptionTier;
  readonly apiContext?: string;
  readonly nowSec?: number;
}): Wso2BackendJwtAssertion {
  const nowSec = input.nowSec ?? Math.floor(Date.now() / 1000);
  const header = {
    alg: "RS256" as const,
    typ: "JWT" as const,
    kid: "wso2-apim-gateway-jwt-2026"
  };
  const claims = {
    iss: "wso2.org/products/am" as const,
    exp: nowSec + 900,
    "http://wso2.org/claims/subscriber": input.sub,
    "http://wso2.org/claims/applicationname": "ChoreoEnterpriseOrderPortal",
    "http://wso2.org/claims/apicontext": input.apiContext ?? "/api/integration/v1",
    "http://wso2.org/claims/version": "v1.0.0",
    "http://wso2.org/claims/tier": input.tier,
    "http://wso2.org/claims/keytype": "PRODUCTION" as const,
    "http://wso2.org/claims/enduser": input.sub,
    "http://wso2.org/claims/role": input.groups
  };
  const compactJwtPreview = `${encodeBase64UrlSegment(header)}.${encodeBase64UrlSegment(claims)}.wso2_apim_rs256_gateway_assertion_sig`;
  return {
    header,
    claims,
    compactJwtPreview
  };
}

export function buildStandardMediationDagNodes(
  injectCycle = false
): readonly MediationStepNode[] {
  return [
    {
      id: "APIM_KeyManager_Auth",
      mediatorType: "APIM_Auth",
      description: "Validate OAuth2 RS256 Bearer token via WSO2 IS Key Manager JWKS",
      dependsOn: injectCycle ? ["MI_Aggregate_ScatterGather"] : []
    },
    {
      id: "APIM_TokenBucket_Throttle",
      mediatorType: "APIM_Throttle",
      description: "Enforce Subscription Tier quota via O(1) Token Bucket",
      dependsOn: ["APIM_KeyManager_Auth"]
    },
    {
      id: "APIM_Mint_Backend_JWT",
      mediatorType: "APIM_BackendJWT",
      description: "Attach signed X-JWT-Assertion header for upstream Micro Integrator",
      dependsOn: ["APIM_TokenBucket_Throttle"]
    },
    {
      id: "MI_ContentBasedRouter",
      mediatorType: "MI_CBR_Switch",
      description: "Evaluate Switch/Filter predicate on order amountUsd and region",
      dependsOn: ["APIM_Mint_Backend_JWT"]
    },
    {
      id: "MI_Clone_OrderService",
      mediatorType: "MI_Clone_Branch",
      description: "Clone Target #1: Core Order Persistence Service",
      dependsOn: ["MI_ContentBasedRouter"]
    },
    {
      id: "MI_Clone_InventoryService",
      mediatorType: "MI_Clone_Branch",
      description: "Clone Target #2: Warehouse Inventory Reservation (Circuit-Breaker guarded)",
      dependsOn: ["MI_ContentBasedRouter"]
    },
    {
      id: "MI_Clone_FraudRiskService",
      mediatorType: "MI_Clone_Branch",
      description: "Clone Target #3: Real-Time Fraud & Compliance Scoring Engine",
      dependsOn: ["MI_ContentBasedRouter"]
    },
    {
      id: "MI_Aggregate_ScatterGather",
      mediatorType: "MI_Aggregate",
      description: "Correlate & merge parallel Clone branches on completion condition",
      dependsOn: [
        "MI_Clone_OrderService",
        "MI_Clone_InventoryService",
        "MI_Clone_FraudRiskService"
      ]
    },
    {
      id: "MI_PayloadFactory_Transform",
      mediatorType: "MI_PayloadFactory",
      description: "Transform legacy upstream SOAP/XML envelope into canonical enterprise JSON",
      dependsOn: ["MI_Aggregate_ScatterGather"]
    },
    {
      id: "MI_Respond_Client",
      mediatorType: "MI_Respond",
      description: "Cache response in O(1) Doubly-Linked LRU and emit correlated response",
      dependsOn: ["MI_PayloadFactory_Transform"]
    }
  ];
}

export function evaluateContentBasedRoute(payload: IntegrationOrderPayload): {
  readonly route: CbrRouteKey;
  readonly expression: string;
} {
  if (payload.amountUsd >= 1000 || payload.priority === "HIGH_RISK") {
    return {
      route: "HIGH_VALUE_FRAUD_SCREEN",
      expression: "json-eval($.amountUsd >= 1000 || $.priority == 'HIGH_RISK') -> FraudScreenSequence"
    };
  }
  if (payload.region === "EU") {
    return {
      route: "EU_GDPR_COMPLIANCE_ROUTE",
      expression: "json-eval($.region == 'EU') -> EuGdprResidencySequence"
    };
  }
  return {
    route: "FAST_TRACK_STANDARD_ROUTE",
    expression: "default -> FastTrackOrderSequence"
  };
}

export class Wso2ApimMiIntegrationEngine {
  public readonly routeTrie = new RadixRouteTrie<{
    readonly apiName: string;
    readonly version: string;
  }>();
  public readonly responseLruCache = new DoublyLinkedLruTtlCache<
    string,
    Record<string, unknown>
  >(6, 60_000);
  public readonly throttler = new TokenBucketThrottler();
  public readonly inventoryCircuitBreaker = new CircuitBreakerFsm({
    failureThreshold: 2,
    openDurationMs: 15_000,
    halfOpenSuccessThreshold: 1
  });
  public readonly retryMinHeap = new MinHeapRetryQueue<IntegrationOrderPayload>();

  constructor() {
    this.routeTrie.insert("POST", "/api/integration/orders/:orderId/mediate", {
      apiName: "EnterpriseOrderIntegrationAPI",
      version: "v1.0.0"
    });
    this.routeTrie.insert("GET", "/api/integration/orders/:orderId/status", {
      apiName: "EnterpriseOrderIntegrationAPI",
      version: "v1.0.0"
    });
    this.routeTrie.insert("POST", "/api/mcp/*", {
      apiName: "ChoreoMcpAgentGatewayAPI",
      version: "v2.0.0"
    });
    this.routeTrie.insert("GET", "/api/v1/user/:section", {
      apiName: "HumanCiamIdentityAPI",
      version: "v2.0.0"
    });
  }

  public executeMediation(input: {
    readonly subscriber: string;
    readonly groups: readonly string[];
    readonly tier: ApimSubscriptionTier;
    readonly faultMode: IntegrationFaultMode;
    readonly order: IntegrationOrderPayload;
    readonly nowMs?: number;
  }): EipMediationResponse {
    const nowMs = input.nowMs ?? Date.now();
    const correlationId = `wso2_corr_${nowMs.toString(36)}_${input.order.orderId}`;
    const requestPath = `/api/integration/orders/${input.order.orderId}/mediate`;

    // 1. Radix Trie Route Matching — O(k)
    const routeMatch = this.routeTrie.lookup("POST", requestPath);

    // 2. WSO2 APIM Backend JWT Assertion (X-JWT-Assertion)
    const backendJwtAssertion = buildWso2BackendJwtAssertion({
      sub: input.subscriber,
      groups: input.groups,
      tier: input.tier,
      apiContext: "/api/integration/orders",
      nowSec: Math.floor(nowMs / 1000)
    });

    // 3. Token Bucket Rate Limiting — O(1)
    // In throttle_spike fault mode, consume full burst + 1 to demonstrate 429 behavior deterministically
    const consumeCost =
      input.faultMode === "throttle_spike"
        ? APIM_SUBSCRIPTION_TIERS[input.tier].burstCapacity + 1
        : 1;
    const throttleDecision = this.throttler.tryConsume(
      input.subscriber,
      input.tier,
      consumeCost,
      nowMs
    );

    const cbr = evaluateContentBasedRoute(input.order);
    const dagPlan = planMediationDag(
      buildStandardMediationDagNodes(input.faultMode === "dag_cycle_fault")
    );

    if (!throttleDecision.allowed) {
      return {
        ok: false,
        httpStatus: 429,
        correlationId,
        faultMode: input.faultMode,
        apimGateway: {
          routeMatch,
          throttleDecision,
          responseCacheStatus: "BYPASSED",
          lruCacheTelemetry: this.responseLruCache.getTelemetry(),
          backendJwtAssertion
        },
        microIntegrator: {
          dagPlan,
          selectedCbrRoute: cbr.route,
          cbrExpression: cbr.expression,
          scatterGatherBranches: [],
          sequentialLatencySumMs: 0,
          parallelAggregatedLatencyMs: 0,
          payloadFactoryTransform: {
            legacyUpstreamXml: "<!-- Halted at WSO2 APIM Traffic Manager: HTTP 429 Quota Exceeded -->",
            canonicalEnterpriseJson: {
              code: 900804,
              message: "Message throttled out",
              description: `You have exceeded your quota for tier ${input.tier}. Retry after ${throttleDecision.retryAfterSeconds}s.`
            }
          },
          circuitBreaker: this.inventoryCircuitBreaker.snapshot(),
          retryQueueDlqSnapshot: this.retryMinHeap.toSortedSnapshot()
        },
        timestamp: new Date(nowMs).toISOString()
      };
    }

    if (!dagPlan.ok) {
      return {
        ok: false,
        httpStatus: 400,
        correlationId,
        faultMode: input.faultMode,
        apimGateway: {
          routeMatch,
          throttleDecision,
          responseCacheStatus: "BYPASSED",
          lruCacheTelemetry: this.responseLruCache.getTelemetry(),
          backendJwtAssertion
        },
        microIntegrator: {
          dagPlan,
          selectedCbrRoute: cbr.route,
          cbrExpression: cbr.expression,
          scatterGatherBranches: [],
          sequentialLatencySumMs: 0,
          parallelAggregatedLatencyMs: 0,
          payloadFactoryTransform: {
            legacyUpstreamXml: "<!-- Halted by Mediation DAG Topological Verifier: Cyclic Sequence Detected -->",
            canonicalEnterpriseJson: {
              error: dagPlan.error,
              cycleParticipants: dagPlan.cycleNodes,
              complexity: dagPlan.complexity
            }
          },
          circuitBreaker: this.inventoryCircuitBreaker.snapshot(),
          retryQueueDlqSnapshot: this.retryMinHeap.toSortedSnapshot()
        },
        timestamp: new Date(nowMs).toISOString()
      };
    }

    // 4. Doubly-Linked List LRU Cache Lookup — O(1)
    const cacheKey = `${input.order.orderId}:${cbr.route}:${input.faultMode}`;
    const cachedPayload =
      input.faultMode === "nominal" ? this.responseLruCache.get(cacheKey, nowMs) : undefined;

    // 5. Upstream Circuit Breaker + Min-Heap Retry Queue (Dead-Letter Store)
    let inventoryStatus: UpstreamBranchCall["status"] = "SUCCESS";
    let inventoryLatencyMs = 18;
    if (input.faultMode === "upstream_timeout_cb") {
      // Trip circuit breaker and enqueue to Min-Heap DLQ with exponential backoff
      this.inventoryCircuitBreaker.recordFailure(nowMs);
      this.inventoryCircuitBreaker.recordFailure(nowMs);
      const attempt = this.retryMinHeap.size() + 1;
      const backoffDelayMs = 1000 * Math.pow(2, Math.min(attempt, 5));
      this.retryMinHeap.enqueue({
        messageId: `dlq_msg_${input.order.orderId}_att${attempt}`,
        attempt,
        nextRetryEpochMs: nowMs + backoffDelayMs,
        priority: input.order.priority === "HIGH_RISK" ? 1 : 5,
        targetEndpoint: "https://inventory-core.internal.wso2/v1/reserve",
        payload: input.order
      });
      inventoryStatus = "FALLBACK_REPLICA";
      inventoryLatencyMs = 7;
    } else {
      const canExec = this.inventoryCircuitBreaker.canExecute(nowMs);
      if (!canExec.permitted) {
        this.inventoryCircuitBreaker.forceState("CLOSED", nowMs);
      } else {
        this.inventoryCircuitBreaker.recordSuccess();
      }
    }

    const scatterGatherBranches: UpstreamBranchCall[] = [
      {
        branchId: "clone-branch-1",
        serviceName: "OrderCoreService",
        endpointUrl: "http://order-service.choreo.internal:8081/v1/orders",
        status: "SUCCESS",
        latencyMs: 14,
        payloadSnippet: {
          orderId: input.order.orderId,
          ledgerState: "COMMITTED",
          amountUsd: input.order.amountUsd
        }
      },
      {
        branchId: "clone-branch-2",
        serviceName: "WarehouseInventoryService",
        endpointUrl:
          inventoryStatus === "FALLBACK_REPLICA"
            ? "http://inventory-failover-replica.choreo.internal:8082/v1/reserve"
            : "http://inventory-primary.choreo.internal:8082/v1/reserve",
        status: inventoryStatus,
        latencyMs: inventoryLatencyMs,
        payloadSnippet: {
          warehouseZone: input.order.region,
          reservationState:
            inventoryStatus === "FALLBACK_REPLICA"
              ? "RESERVED_ON_FAILOVER_REPLICA_AND_QUEUED_SYNC"
              : "RESERVED_PRIMARY",
          skuCount: input.order.items.length
        }
      },
      {
        branchId: "clone-branch-3",
        serviceName:
          cbr.route === "EU_GDPR_COMPLIANCE_ROUTE"
            ? "EuGdprDataResidencyService"
            : "FraudRiskScoringService",
        endpointUrl: "http://risk-engine.choreo.internal:8083/v1/evaluate",
        status: "SUCCESS",
        latencyMs: 22,
        payloadSnippet: {
          cbrRoute: cbr.route,
          riskScore: input.order.amountUsd >= 1000 ? 18 : 4,
          verdict: "APPROVED"
        }
      }
    ];

    const sequentialLatencySumMs = scatterGatherBranches.reduce(
      (acc, item) => acc + item.latencyMs,
      0
    );
    const parallelAggregatedLatencyMs = Math.max(
      ...scatterGatherBranches.map((item) => item.latencyMs)
    );

    const legacyUpstreamXml = [
      `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ord="http://ws.apache.org/ns/synapse/order">`,
      `  <soapenv:Header>`,
      `    <ord:CorrelationId>${correlationId}</ord:CorrelationId>`,
      `    <ord:Wso2ApimTier>${input.tier}</ord:Wso2ApimTier>`,
      `  </soapenv:Header>`,
      `  <soapenv:Body>`,
      `    <ord:AggregatedOrderResponse route="${cbr.route}">`,
      `      <ord:OrderId>${input.order.orderId}</ord:OrderId>`,
      `      <ord:CustomerId>${input.order.customerId}</ord:CustomerId>`,
      `      <ord:TotalAmount currency="${input.order.currency}">${input.order.amountUsd.toFixed(2)}</ord:TotalAmount>`,
      `      <ord:InventorySource>${inventoryStatus}</ord:InventorySource>`,
      `    </ord:AggregatedOrderResponse>`,
      `  </soapenv:Body>`,
      `</soapenv:Envelope>`
    ].join("\n");

    const canonicalEnterpriseJson: Record<string, unknown> = cachedPayload ?? {
      schemaVersion: "urn:wso2:mi:canonical-order:v3",
      correlationId,
      orderId: input.order.orderId,
      customerId: input.order.customerId,
      amountUsd: input.order.amountUsd,
      currency: input.order.currency,
      region: input.order.region,
      mediationRoute: cbr.route,
      apimTier: input.tier,
      fulfillmentStatus:
        inventoryStatus === "FALLBACK_REPLICA"
          ? "DEGRADED_FAILOVER_REPLICA"
          : "ORCHESTRATED_SUCCESS",
      parallelSpeedupRatio: `${sequentialLatencySumMs}ms seq -> ${parallelAggregatedLatencyMs}ms parallel`
    };

    if (!cachedPayload && input.faultMode === "nominal") {
      this.responseLruCache.put(cacheKey, canonicalEnterpriseJson, 60_000, nowMs);
    }

    return {
      ok: true,
      httpStatus: 200,
      correlationId,
      faultMode: input.faultMode,
      apimGateway: {
        routeMatch,
        throttleDecision,
        responseCacheStatus: cachedPayload ? "HIT" : "MISS",
        lruCacheTelemetry: this.responseLruCache.getTelemetry(),
        backendJwtAssertion
      },
      microIntegrator: {
        dagPlan,
        selectedCbrRoute: cbr.route,
        cbrExpression: cbr.expression,
        scatterGatherBranches,
        sequentialLatencySumMs,
        parallelAggregatedLatencyMs,
        payloadFactoryTransform: {
          legacyUpstreamXml,
          canonicalEnterpriseJson
        },
        circuitBreaker: this.inventoryCircuitBreaker.snapshot(),
        retryQueueDlqSnapshot: this.retryMinHeap.toSortedSnapshot()
      },
      timestamp: new Date(nowMs).toISOString()
    };
  }
}

export const defaultIntegrationEngine = new Wso2ApimMiIntegrationEngine();
