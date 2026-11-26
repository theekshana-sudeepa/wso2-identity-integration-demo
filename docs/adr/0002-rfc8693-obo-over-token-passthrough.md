# ADR 0002: RFC 8693 On-Behalf-Of (OBO) Token Exchange Over Token Passthrough for MCP Agents

- **Status:** Accepted
- **Context:** Passing a human user's primary access token directly to an AI agent or downstream MCP server ("token passthrough") violates least privilege, obscures audit attribution, and enables confused-deputy replay across unrelated APIs.
- **Decision:** Require **RFC 8693 Token Exchange** (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`) combined with **RFC 8707 Resource Indicators** (`resource=http://localhost:5050/api/mcp`) to mint a dedicated, short-lived (`AGENT_TOKEN_MAX_TTL_SECONDS = 60`), down-scoped (`orders:read`) token carrying both `sub` (human) and `act.sub` (AI agent). Enforce a dedicated `MCP_AUDIENCE` on `/api/mcp`, cap nested `act` delegation chains at `MAX_DELEGATION_DEPTH = 2` (acyclic), and validate `may_act` (§4.4) at the STS.
- **Consequences:** Human API tokens (`aud = wso2-api-demo`) are deterministically rejected at `/api/mcp` with `401 invalid_audience`, and privileged scopes (`admin:write`, `refunds:execute`, `users:export`) are stripped unless interactive CIBA human step-up consent is granted.
