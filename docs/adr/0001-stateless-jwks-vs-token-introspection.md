# ADR 0001: Stateless RS256 JWKS Verification vs. Stateful RFC 7662 Token Introspection

- **Status:** Accepted
- **Context:** Resource servers validating OAuth 2.0 access tokens from WSO2 Identity Server 7.0 or Asgardeo can verify tokens either statelessly via RFC 7517 JWKS public keys or statefully via RFC 7662 Token Introspection (`POST /oauth2/introspect`).
- **Decision:** Default to **Stateless RS256 JWKS Verification** with an in-memory LRU cache (`maxEntries: 5`, `ttl: 10m`, `rateLimit: 10 req/min`) for low-latency (`~0.4ms`) 0-hop verification, while supporting **RFC 7662 Introspection (`X-Verification-Mode: introspect`)** and short-lived (`60s`) token TTLs for high-risk or revocation-sensitive flows.
- **Consequences:** Stage 04 of the console includes an interactive toggle and an **RFC 7009 Revoke Token** action demonstrating that stateless JWKS continues accepting a revoked token until `exp`, whereas stateful introspection (+1 IdP hop) rejects it immediately with `401 token_revoked`.
