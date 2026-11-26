# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `2.0.x` | ✅ Active support |
| `< 2.0.0` | ❌ Superseded by `2.0.0` |

## Security Architecture Guardrails

1. **Local Dev IdP Isolation**: The in-process Dev IdP / STS (`backend/src/devIdp/`) is strictly gated by `nodeEnv !== "production" && DEV_IDP_ENABLED === "true"` and never mounts in production environments.
2. **Algorithm Pinning**: All JWT verifiers pin `algorithms: ["RS256"]` for access tokens and `algorithms: ["ES256"]` for RFC 9449 DPoP proofs.
3. **Zero Secret Leakage**: Public SPA clients use 384-bit Web Crypto S256 PKCE with zero static client secrets.

## Reporting a Vulnerability

Please report security issues privately via GitHub Security Advisories on [`theekshana-sudeepa/wso2-identity-integration-demo`](https://github.com/theekshana-sudeepa/wso2-identity-integration-demo/security).
