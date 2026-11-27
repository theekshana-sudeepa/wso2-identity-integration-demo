# Changelog

All notable changes to `wso2-identity-integration-demo` are documented in this file.

## [3.0.0] — 2026-11-27

### Added
- **WSO2 API Manager (APIM 4.x) Gateway Mediation Engine (`POST /api/integration/orders/:orderId/mediate`)**:
  - Subscription Tier Throttling Policies (`Bronze`, `Silver`, `Gold`, `AI-Agent-MCP`) emitting `X-WSO2-Throttle-Tier`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `Retry-After` headers.
  - Signed **`X-JWT-Assertion`** Backend Context JWT generation (`http://wso2.org/claims/enduser`, `subscriber`, `applicationname`, `tier`, `role`) propagated from the API Gateway to WSO2 Micro Integrator.
  - Gateway Response Caching backed by a hand-rolled `O(1)` Doubly-Linked List + HashMap LRU Cache with TTL.
- **WSO2 Micro Integrator (MI / Apache Synapse) Enterprise Integration Patterns (EIP) Pipeline**:
  - **Content-Based Router (CBR)** (`<filter>` / `<switch>` mediator) dynamically routing orders to `HIGH_VALUE_FRAUD_SCREEN`, `EU_GDPR_COMPLIANCE_ROUTE`, or `FAST_TRACK_STANDARD_ROUTE`.
  - **Scatter-Gather Pattern** (`<clone>` + `<aggregate>` mediators) executing concurrent branches across `OrderCoreService`, `WarehouseInventoryService`, and `FraudRiskScoringService`/`EuGdprDataResidencyService` with parallel speedup telemetry.
  - **Message Transformation** (`<payloadFactory>` mediator) converting legacy upstream SOAP/XML envelopes into canonical enterprise JSON.
  - **Endpoint Resiliency & Dead-Letter Channel** (`<suspendOnFailure>` Circuit Breaker + `<store>` Message Store & Scheduled Message Processor with exponential backoff).
- **5-Structure Core Data Structures & Algorithms (DSA) Engine (`backend/src/dsa/integrationDsaEngine.ts` & `frontend/src/lib/integrationDsaEngine.ts`)**:
  1. `RadixRouteTrie` (`O(k)` segment lookup & URI-template parameter extraction)
  2. `DoublyLinkedLruTtlCache` (strict `O(1)` pointer-spliced `get`, `put`, `evict` with live MRU↔LRU snapshot)
  3. `TokenBucketThrottler` (`O(1)` lazy continuous token refill math)
  4. `CircuitBreakerFsm` (`O(1)` state machine) + `MinHeapRetryQueue` (`O(log n)` array-backed binary min-heap Dead-Letter retry scheduler)
  5. `planMediationDag` (`O(V + E)` Kahn's BFS topological sort with level-order parallel execution waves & cycle detection)
- **Deployable WSO2 Artifacts (`integration-artifacts/`) & Code Exporter Tabs**:
  - Added `integration-artifacts/wso2-mi-synapse/EnterpriseOrderIntegrationAPI.xml`, `integration-artifacts/wso2-apim/api.yaml`, `integration-artifacts/ballerina/order_integration_service.bal`, and ADR 0005.
  - Added interactive `IntegrationWorkbench.tsx` and **WSO2 MI Synapse XML** + **Ballerina (`.bal`)** export tabs in `CodeExporterDrawer.tsx`.

## [2.0.0] — 2026-11-26

### Added
- **Local Dev IdP / STS (`/dev-idp/*`)**: In-process RSA-2048 OIDC Identity Provider and RFC 8693 Security Token Service powered by `jose` with active + rotated `kid` keypairs, real S256 PKCE verification, seeded personas (`developer`, `admin`, `auditor`), RFC 8707 Resource Indicators, and live key rotation (`POST /dev-idp/admin/rotate-keys`).
- **Real Web Crypto RS256 & ES256 in Browser Simulation Mode**: In-browser `RSASSA-PKCS1-v1_5` SHA-256 signing and verification (`frontend/src/lib/browserCrypto.ts`) plus side-by-side SHA-256 PKCE mismatch digests.
- **Spec-Compliant MCP Authorization (2025-06-18 Spec)**: JSON-RPC 2.0 `POST /api/mcp` (`tools/list` & `tools/call`), RFC 9728 Protected Resource Metadata (`GET /.well-known/oauth-protected-resource`), declarative tool registry (`backend/src/mcp/toolRegistry.ts`) with JSON Schema argument validation, and live Agent Activity Timeline (`GET /api/mcp/audit`).
- **CIBA Human-in-the-Loop Step-Up Consent**: Interactive `auth_req_id` push approval flow (`POST /dev-idp/oauth2/ciba/decide`) minting one-time 120s step-up claims to unlock `export_all_users`.
- **RFC 9449 DPoP Sender-Constrained Agent Tokens**: Web Crypto `ES256` (`P-256`) keypair generation, `cnf.jkt` thumbprint binding, `dpop+jwt` proof verification, and `jti` replay cache.
- **RFC 7662 Token Introspection vs. Stateless JWKS Trade-Off**: Stage 04 architectural toggle and RFC 7009 token revocation (`POST /dev-idp/oauth2/revoke`) contrasting 0-hop JWKS caching with 1-hop real-time revocation.
- **10-Scenario Break-the-Flow Attack Lab**: Added `Stolen Agent Token Replay (no DPoP key)`, `Token Passthrough to Wrong Resource (RFC 8707)`, `Delegation Chain Too Deep / act Cycle`, and `Unauthorized Actor (may_act violation)`.
- **Architecture & DevOps**: Shared `@choreo-demo/identity-policy` workspace with full-matrix contract tests, `useReducer` console state machine, modular `components/flow/*` architecture, OpenAPI 3.1 (`/api/openapi.json` & `/api/docs`), Docker Compose `dev` & `wso2` profiles, GitHub Actions CI + CodeQL + GitHub Pages deployment, STRIDE threat model, and 4 ADRs.

### Fixed
- Replaced brittle error message substring matching with typed `instanceof` checks (`TokenExpiredError`, `NotBeforeError`, `JsonWebTokenError`, `SigningKeyNotFoundError`, `JwksRateLimitError`) and split `invalid_audience` vs. `invalid_issuer`.
- Added compliant RFC 6750 `WWW-Authenticate` Bearer challenge headers on all `401`/`403` responses (including RFC 9728 `resource_metadata` on MCP challenges).
- Fixed MCP audience binding bug (`MCP_AUDIENCE`) to block human-API token passthrough and unified the `60s` delegated agent TTL constant (`AGENT_TOKEN_MAX_TTL_SECONDS = 60`).
