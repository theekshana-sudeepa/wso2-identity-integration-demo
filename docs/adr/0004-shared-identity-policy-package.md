# ADR 0004: Shared Pure-TypeScript Identity Policy Package & Contract Testing

- **Status:** Accepted
- **Context:** Because the console supports zero-config static hosting (GitHub Pages Browser Simulation Mode) alongside the live Express Resource Server, policy rules could drift between the browser simulator and the backend middleware.
- **Decision:** Extract canonical constants (`AGENT_TOKEN_MAX_TTL_SECONDS`, `MAX_DELEGATION_DEPTH`), endpoint RBAC/scope rules (`SHARED_ENDPOINT_POLICIES`), and policy evaluators into `packages/identity-policy`, and enforce a Vitest contract suite (`backend/src/__tests__/policyContract.test.ts` + `agentPolicy.drift.test.ts`) that runs every `(persona × endpoint × fault)` combination against both engines.
- **Consequences:** Any policy divergence between Browser Simulation Mode and the live Express server fails CI immediately.
