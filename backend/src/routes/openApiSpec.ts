import identityConfig from "../config/identityConfig.js";
import { MCP_TOOL_LIST } from "../mcp/toolRegistry.js";

export function buildOpenApiSpec(): Record<string, unknown> {
  return {
    openapi: "3.1.0",
    info: {
      title: "Choreo Labs (formerly WSO2) — Human CIAM & AI Agent MCP Identity API",
      version: "2.0.0",
      description:
        "Cryptographically real OAuth 2.0 OIDC PKCE (S256), Stateless RS256 JWKS Resource Server, RFC 8693 OBO Token Exchange, RFC 9449 DPoP, CIBA Step-Up Approval, and JSON-RPC 2.0 MCP Gateway.",
      license: {
        name: "MIT",
        url: "https://opensource.org/licenses/MIT"
      }
    },
    servers: [
      {
        url: `http://localhost:${identityConfig.port}`,
        description: "Local Express Resource Server & Dev IdP / STS"
      }
    ],
    components: {
      securitySchemes: {
        BearerRS256: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "RS256-signed OAuth 2.0 / OIDC or RFC 8693 OBO Access Token"
        }
      }
    },
    paths: {
      "/health": {
        get: {
          summary: "Resource server & Dev IdP health probe",
          tags: ["System"],
          responses: { "200": { description: "Healthy status and active JWKS kid metadata" } }
        }
      },
      "/.well-known/oauth-protected-resource": {
        get: {
          summary: "RFC 9728 OAuth 2.0 Protected Resource Metadata",
          tags: ["MCP Authorization"],
          responses: { "200": { description: "Protected resource metadata for MCP Gateway" } }
        }
      },
      "/api/v1/public/info": {
        get: {
          summary: "Public CIAM & OIDC metadata",
          tags: ["Human CIAM"],
          responses: { "200": { description: "Public service metadata" } }
        }
      },
      "/api/v1/user/profile": {
        get: {
          summary: "Authenticated user profile from RS256 JWT",
          tags: ["Human CIAM"],
          security: [{ BearerRS256: [] }],
          responses: {
            "200": { description: "Verified user claims" },
            "401": { description: "RFC 6750 WWW-Authenticate challenge on invalid/revoked token" }
          }
        }
      },
      "/api/v1/user/roles": {
        get: {
          summary: "Resolved RBAC groups and OAuth2 scopes",
          tags: ["Human CIAM"],
          security: [{ BearerRS256: [] }],
          responses: { "200": { description: "User roles and scopes" } }
        }
      },
      "/api/v1/admin/audit-logs": {
        get: {
          summary: "Admin-only security audit logs (requireRoles('admin'))",
          tags: ["Human CIAM"],
          security: [{ BearerRS256: [] }],
          responses: {
            "200": { description: "Audit log entries" },
            "403": { description: "Forbidden when admin role is missing" }
          }
        }
      },
      "/api/v1/reports": {
        post: {
          summary: "Create compliance report (requireScopes('write:reports'))",
          tags: ["Human CIAM"],
          security: [{ BearerRS256: [] }],
          responses: {
            "201": { description: "Compliance report created" },
            "403": { description: "Insufficient scope write:reports" }
          }
        }
      },
      "/api/mcp": {
        post: {
          summary: "JSON-RPC 2.0 MCP Gateway (tools/list & tools/call)",
          tags: ["MCP Authorization"],
          security: [{ BearerRS256: [] }],
          description: `Registered MCP tools: ${MCP_TOOL_LIST.map((t) => `${t.name} (${t.riskTier})`).join(", ")}`,
          responses: {
            "200": { description: "JSON-RPC 2.0 tool list or tool execution result" },
            "401": { description: "Invalid audience, expired 60s token, or missing RFC 9449 DPoP proof" },
            "403": { description: "Scope escalation blocked or CIBA human step-up approval required" }
          }
        }
      },
      "/api/mcp/audit": {
        get: {
          summary: "In-memory ring buffer of delegated AI agent MCP tool invocations",
          tags: ["MCP Authorization"],
          responses: { "200": { description: "Agent activity audit timeline" } }
        }
      },
      "/api/integration/orders/{orderId}/mediate": {
        post: {
          summary:
            "WSO2 API Manager 4.x Gateway + Micro Integrator EIP Mediation Pipeline (Radix Trie, Token Bucket, X-JWT-Assertion, CBR, Scatter-Gather, PayloadFactory, Circuit Breaker & Min-Heap DLQ)",
          tags: ["WSO2 APIM & Micro Integrator"],
          security: [{ BearerRS256: [] }],
          responses: {
            "200": { description: "Correlated Scatter-Gather + PayloadFactory canonical enterprise JSON response" },
            "400": { description: "Mediation DAG cycle detected by Kahn's O(V + E) topological planner" },
            "401": { description: "Missing or invalid OAuth2 RS256 Bearer token at APIM Key Manager" },
            "429": { description: "WSO2 APIM Subscription Tier quota exceeded (Token Bucket O(1) throttler)" }
          }
        }
      },
      "/api/integration/dsa-telemetry": {
        get: {
          summary:
            "Live telemetry and Big-O complexity metrics for the 5 Core Data Structures & Algorithms powering APIM and Micro Integrator",
          tags: ["WSO2 APIM & Micro Integrator"],
          responses: {
            "200": { description: "Radix Trie, Doubly-Linked LRU, Token Bucket, FSM Circuit Breaker, Min-Heap DLQ & DAG Topological Sort state" }
          }
        }
      },
      "/dev-idp/.well-known/openid-configuration": {
        get: {
          summary: "Local Dev IdP OIDC Discovery document",
          tags: ["Local Dev IdP / STS"],
          responses: { "200": { description: "OIDC discovery metadata" } }
        }
      },
      "/dev-idp/oauth2/jwks": {
        get: {
          summary: "Local Dev IdP RSA-2048 JWK Set (active + rotated keys)",
          tags: ["Local Dev IdP / STS"],
          responses: { "200": { description: "RFC 7517 JWK Set" } }
        }
      },
      "/dev-idp/oauth2/token": {
        post: {
          summary: "OAuth 2.0 Token Endpoint (PKCE S256 authorization_code & RFC 8693 token-exchange)",
          tags: ["Local Dev IdP / STS"],
          responses: {
            "200": { description: "Signed RS256 human JWT or down-scoped 60s OBO agent JWT" },
            "400": { description: "invalid_grant (PKCE mismatch), invalid_scope, invalid_target, or unauthorized_client" }
          }
        }
      },
      "/dev-idp/oauth2/ciba/decide": {
        post: {
          summary: "Approve or Deny a CIBA human-in-the-loop step-up consent request",
          tags: ["Local Dev IdP / STS"],
          responses: { "200": { description: "Mints one-time step-up OBO JWT on approval" } }
        }
      },
      "/dev-idp/oauth2/revoke": {
        post: {
          summary: "RFC 7009 Token Revocation endpoint",
          tags: ["Local Dev IdP / STS"],
          responses: { "200": { description: "Token marked revoked for RFC 7662 introspection" } }
        }
      },
      "/dev-idp/oauth2/introspect": {
        post: {
          summary: "RFC 7662 OAuth 2.0 Token Introspection endpoint",
          tags: ["Local Dev IdP / STS"],
          responses: { "200": { description: "Returns active: true/false" } }
        }
      }
    }
  };
}

export function buildScalarDocsHtml(): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Choreo Labs / WSO2 Identity & MCP Gateway — OpenAPI 3.1 Reference</title>
  </head>
  <body>
    <script id="api-reference" data-url="/api/openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`;
}
