# Changelog

All notable changes to `wso2-identity-integration-demo` are documented in this file.

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
