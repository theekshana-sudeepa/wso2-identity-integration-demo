# ADR 0003: RFC 9449 DPoP Sender-Constrained Tokens for Delegated AI Agents

- **Status:** Accepted
- **Context:** Even with a 60-second TTL, a bearer token intercepted from an AI agent log or tool trace could be replayed by an attacker within the validity window.
- **Decision:** Bind delegated AI agent OBO tokens to an ephemeral Web Crypto **ES256 (ECDSA P-256)** keypair using **RFC 9449 Demonstrating Proof-of-Possession (DPoP)**. The STS embeds the RFC 7638 JWK SHA-256 thumbprint in `cnf.jkt`, and `/api/mcp` verifies a fresh `dpop+jwt` proof (`htm`, `htu`, `iat`, `jti`, `ath`) on every call with an LRU `jti` replay cache.
- **Consequences:** Exfiltrated agent tokens replayed without the agent's private ES256 key are rejected with `401 invalid_dpop_proof` (demonstrated live in Attack Lab Fault #7).
