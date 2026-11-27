# ADR 0005: WSO2 API Manager (APIM 4.x) Gateway Mediation, Micro Integrator EIP Pipeline & Core Data Structures

- **Status:** Accepted (v3.0)
- **Context:** WSO2 Software Engineer (Integration) — End-to-End Identity (WSO2 IS 7.0 / Asgardeo) + API Management (WSO2 APIM 4.x) + Enterprise Integration (WSO2 Micro Integrator / Synapse / Ballerina) Reference Architecture

---

## Context & Problem Statement

In enterprise WSO2 deployments, **WSO2 Identity Server (IS 7.0) / Asgardeo** never operates in isolation. It acts as the **Key Manager** and **STS** feeding into:
1. **WSO2 API Manager (APIM 4.x / APK)** at the edge — responsible for route resolution, subscription-tier throttling (`Bronze`, `Silver`, `Gold`), response caching, and minting signed **`X-JWT-Assertion`** backend context tokens.
2. **WSO2 Micro Integrator (MI / Apache Synapse / Ballerina)** in the integration plane — responsible for **Enterprise Integration Patterns (EIP)** including **Content-Based Routing (CBR)**, **Scatter-Gather (`<clone>` + `<aggregate>`)**, **Message Transformation (`<payloadFactory>`)**, **Endpoint Circuit Breaking (`<suspendOnFailure>`)**, and **Dead-Letter Channel (`<messageStore>` + `<messageProcessor>`)** retries.

To demonstrate both **WSO2 product mastery** and **core Data Structures & Algorithms (DSA)** rigor without opaque third-party dependencies, every stage of the APIM + Micro Integrator pipeline must be powered by an inspectable, complexity-verified data structure built from first principles.

---

## Decision

We implement a unified **Core DSA & WSO2 APIM/MI Integration Engine** (`backend/src/dsa/integrationDsaEngine.ts` and `frontend/src/lib/integrationDsaEngine.ts`) backed by 5 canonical data structures:

| WSO2 Subsystem | Data Structure / Algorithm | Time Complexity | Space Complexity | Why This Structure Over Alternatives |
| :--- | :--- | :--- | :--- | :--- |
| **APIM Gateway Route Dispatcher** | **Radix Prefix Segment Trie (`RadixRouteTrie`)** | `O(k)` where `k` = path segments | `O(N * k)` | Eliminates `O(N)` linear regex evaluation across `N` registered APIs; deterministic `Static > :param > *` precedence. |
| **APIM Response & JWKS Cache** | **Doubly-Linked List + HashMap (`DoublyLinkedLruTtlCache`)** | `O(1)` strict `get`, `put`, `evict` | `O(C)` capacity | Pointer splicing (`prev`/`next`) promotes accessed nodes to MRU head and evicts LRU tail in strict `O(1)` without array shifts. |
| **APIM Traffic Manager Subscription Tiers** | **Token Bucket Continuous Refill (`TokenBucketThrottler`)** | `O(1)` arithmetic refill | `O(S)` subscribers | Handles legitimate traffic bursts up to `burstCapacity` while enforcing sustained `refillPerSecond` rate without background timers. |
| **MI Endpoint Circuit Breaker & Message Processor DLQ** | **FSM (`CircuitBreakerFsm`) + Binary Min-Heap (`MinHeapRetryQueue`)** | `O(1)` FSM · `O(log n)` Heap push/pop | `O(n)` queued messages | Binary Min-Heap always surfaces the earliest `nextRetryEpochMs = now + base * 2^attempt` in `O(1)` peek and `O(log n)` extraction. |
| **MI Mediation Sequence Verifier** | **Kahn's BFS Topological Sort (`planMediationDag`)** | `O(V + E)` | `O(V + E)` | Computes level-order parallel execution waves (proving concurrent `<clone>` scatter-gather stages) and detects cyclic mediator graphs in linear time. |

---

## Consequences

- **Positive:** Reviewers and technical interviewers can inspect both the **live WSO2 APIM / Micro Integrator artifacts** (`X-JWT-Assertion`, Synapse XML, `api.yaml`, Ballerina `service.bal`) and the **exact pointer order, heap state, topological waves, and Big-O complexity** of the underlying data structures in real time.
- **Positive:** Works identically against the live Express server (`POST /api/integration/orders/:orderId/mediate`) and in static GitHub Pages Browser Simulation Mode.
