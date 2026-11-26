import { AGENT_TOKEN_MAX_TTL_SECONDS } from "../../lib/agentPolicy";
import type { ApiCallResult } from "../../lib/apiClient";
import {
  IDP_PRESETS,
  type DelegatedAgentSession,
  type OidcConfig,
  type ParsedJwtClaims,
  type PkceTelemetry,
  type TokenSession
} from "../../lib/pkce";
import type {
  FaultEvaluation,
  FlowMode,
  FlowStageId
} from "../../lib/securityLab";

export type StageTone = "active" | "verified" | "ready" | "blocked" | "recovered";

export interface StageDescriptor {
  readonly id: FlowStageId;
  readonly step: string;
  readonly title: string;
  readonly subtitle: string;
  readonly edgeLabel: string;
  readonly rfcBadge: string;
  readonly stateTone: StageTone;
  readonly stateLabel: string;
  readonly payloadTitle: string;
  readonly payload: Record<string, unknown>;
  readonly invariants: readonly string[];
  readonly telemetry: readonly { readonly label: string; readonly value: string }[];
}

export interface BuildStageDescriptorsInput {
  readonly config: OidcConfig;
  readonly flowMode: FlowMode;
  readonly session: TokenSession | null;
  readonly claims: ParsedJwtClaims | null;
  readonly delegatedSession: DelegatedAgentSession | null;
  readonly pkceTelemetry: PkceTelemetry | null;
  readonly lastApiResult: ApiCallResult | null;
  readonly lastMcpResult: ApiCallResult | null;
  readonly faultEval: FaultEvaluation;
}

export function truncateMiddle(value: string, lead = 12, tail = 8): string {
  if (value.length <= lead + tail + 3) return value;
  return `${value.slice(0, lead)}...${value.slice(-tail)}`;
}

export function getStageOrder(flowMode: FlowMode): readonly FlowStageId[] {
  return flowMode === "agent"
    ? ["spa", "pkce", "idp", "jwks", "rbac", "agent_mcp"]
    : ["spa", "pkce", "idp", "jwks", "rbac"];
}

export function buildStageDescriptors(
  input: BuildStageDescriptorsInput
): readonly StageDescriptor[] {
  const {
    config,
    flowMode,
    session,
    claims,
    delegatedSession,
    pkceTelemetry,
    lastApiResult,
    lastMcpResult,
    faultEval
  } = input;

  const presetMeta = IDP_PRESETS[config.preset];
  const hasSession = Boolean(session && claims);
  const apiBlocked = Boolean(
    lastApiResult && (lastApiResult.status === 401 || lastApiResult.status === 403)
  );
  const apiOk = Boolean(lastApiResult && lastApiResult.ok);

  const faultStage = faultEval.failingStage;
  const pkceBlocked = faultStage === "pkce" && faultEval.isBlocked;
  const idpBlocked = faultStage === "idp" && faultEval.isBlocked;
  const jwksBlocked = faultStage === "jwks" && faultEval.isBlocked;
  const jwksRecovered = faultStage === "jwks" && !faultEval.isBlocked && faultEval.active;

  const baseStages: StageDescriptor[] = [
    {
      id: "spa",
      step: "01",
      title: "React Public SPA",
      subtitle: "Zero Client Secret · Browser",
      edgeLabel: "S256",
      rfcBadge: "OAuth 2.0 Public Client",
      stateTone: hasSession ? "verified" : "active",
      stateLabel: hasSession ? "SESSION ACTIVE" : "CLIENT READY",
      payloadTitle: "Public SPA Client Configuration",
      payload: {
        clientType: "public_spa",
        clientSecretStored: false,
        clientId: config.clientId || "choreo-spa-public-client",
        redirectUri: config.redirectUri,
        requestedScopes: config.scope.split(" "),
        idpTarget: presetMeta.label,
        tokenStorage: "sessionStorage (ephemeral tab scope)"
      },
      invariants: [
        "Public SPAs never bundle or transmit a static client_secret in JavaScript.",
        "Tokens are isolated to browser sessionStorage rather than persistent localStorage.",
        "Strict redirect_uri matching blocks open-redirect token exfiltration."
      ],
      telemetry: [
        { label: "Client Model", value: "Public SPA (No Secret)" },
        { label: "Target IdP", value: presetMeta.shortLabel },
        {
          label: "Session Mode",
          value: session
            ? session.mode === "live"
              ? "Live OIDC"
              : "Demo Simulation"
            : "Unauthenticated"
        }
      ]
    },
    {
      id: "pkce",
      step: "02",
      title: "Web Crypto S256 PKCE",
      subtitle: "384-bit Verifier · CSRF State",
      edgeLabel: "AuthZ",
      rfcBadge: pkceBlocked ? faultEval.rfc : "RFC 7636 · S256",
      stateTone: pkceBlocked ? "blocked" : pkceTelemetry ? "verified" : "ready",
      stateLabel: pkceBlocked
        ? "403 CSRF BLOCKED"
        : pkceTelemetry
          ? "CRYPTO READY"
          : "INITIALIZING",
      payloadTitle: pkceBlocked
        ? `Injected Fault · ${faultEval.title}`
        : "Live Web Crypto API PKCE Artifacts",
      payload: pkceBlocked
        ? faultEval.wirePayload
        : pkceTelemetry
          ? {
              code_challenge_method: pkceTelemetry.challengeMethod,
              entropy_bits: pkceTelemetry.entropyBits,
              code_verifier_preview: truncateMiddle(pkceTelemetry.codeVerifier, 18, 10),
              code_challenge: pkceTelemetry.codeChallenge,
              csrf_state: pkceTelemetry.state,
              generated_at: pkceTelemetry.generatedAt
            }
          : { status: "Generating Web Crypto entropy..." },
      invariants: [
        "Uses native browser crypto.getRandomValues (48 bytes) + SubtleCrypto SHA-256 digest.",
        "Authorization code alone is useless to interceptors without the matching code_verifier.",
        "One-time cryptographic state nonce prevents OAuth 2.0 login CSRF attacks."
      ],
      telemetry: [
        { label: "Challenge Method", value: "S256 (SHA-256)" },
        { label: "Verifier Entropy", value: `${pkceTelemetry?.entropyBits ?? 384} bits` },
        {
          label: "Callback Nonce",
          value: pkceBlocked ? "MISMATCH (Aborted)" : "Bound to sessionStorage"
        }
      ]
    },
    {
      id: "idp",
      step: "03",
      title: "Choreo Labs / WSO2 IS",
      subtitle: `${presetMeta.shortLabel} · OIDC & JWKS`,
      edgeLabel: "RS256",
      rfcBadge: idpBlocked ? faultEval.rfc : "OIDC Core 1.0",
      stateTone: idpBlocked ? "blocked" : hasSession ? "verified" : "ready",
      stateLabel: idpBlocked
        ? "400 INVALID_GRANT"
        : hasSession
          ? "JWT MINTED"
          : "IDP STANDBY",
      payloadTitle: idpBlocked
        ? `Injected Fault · ${faultEval.title}`
        : `${presetMeta.label} OIDC Contract`,
      payload: idpBlocked
        ? faultEval.wirePayload
        : {
            provider: "Choreo Labs (formerly WSO2)",
            platform: presetMeta.label,
            authorizeEndpoint: `${config.baseUrl}/oauth2/authorize`,
            tokenEndpoint: config.issuer,
            jwksEndpoint: config.jwksUri,
            signingAlgorithm: "RS256",
            activeKeyId: claims?.kid ?? presetMeta.demoKid,
            audience: config.audience
          },
      invariants: [
        "Recomputes BASE64URL(SHA256(code_verifier)) at /oauth2/token before minting tokens.",
        "Signs JWTs asymmetrically with tenant RSA private key and publishes public keys at /oauth2/jwks.",
        "Supports zero-downtime key rotation via JWT header kid matching."
      ],
      telemetry: [
        { label: "Platform", value: presetMeta.shortLabel },
        { label: "Signing Key (kid)", value: claims?.kid ?? presetMeta.demoKid },
        {
          label: "Token Exchange",
          value: idpBlocked ? "Rejected (PKCE Fail)" : truncateMiddle(config.issuer, 18, 12)
        }
      ]
    },
    {
      id: "jwks",
      step: "04",
      title: "Stateless RS256 Verify",
      subtitle: "JWKS Cache · iss / aud / exp",
      edgeLabel: "RBAC",
      rfcBadge: jwksBlocked || jwksRecovered ? faultEval.rfc : "RFC 7519 · JWKS",
      stateTone: jwksBlocked
        ? "blocked"
        : jwksRecovered
          ? "recovered"
          : lastApiResult?.status === 401
            ? "blocked"
            : hasSession
              ? "verified"
              : "ready",
      stateLabel: jwksBlocked
        ? "401 UNAUTHORIZED"
        : jwksRecovered
          ? "200 KID RECOVERED"
          : lastApiResult?.status === 401
            ? "401 REJECTED"
            : hasSession
              ? "RS256 VALIDATED"
              : "AWAITING BEARER",
      payloadTitle:
        jwksBlocked || jwksRecovered
          ? `Fault Simulation · ${faultEval.title}`
          : "Express authMiddleware Verification Policy",
      payload:
        jwksBlocked || jwksRecovered
          ? faultEval.wirePayload
          : {
              middleware: "backend/src/middleware/authMiddleware.ts",
              allowedAlgorithms: ["RS256"],
              expectedIssuer: config.issuer,
              expectedAudience: config.audience,
              jwksCachePolicy: {
                ttlMs: 600000,
                maxEntries: 5,
                rateLimitRpm: 10
              },
              tokenHeaderInspect: claims
                ? { alg: claims.alg, typ: claims.typ, kid: claims.kid }
                : { status: "No active Bearer JWT loaded" }
            },
      invariants: [
        "Explicitly pins algorithms: ['RS256'] to eliminate alg:none and HS256 key-confusion attacks.",
        "Stateless verification requires zero IdP introspection hops on cache hits (10-min TTL).",
        "Enforces strict issuer (iss), audience (aud), and expiration (exp ±5s) claim verification."
      ],
      telemetry: [
        { label: "Algorithm Pin", value: "RS256 Only" },
        { label: "JWKS Cache TTL", value: "10 min · 10 req/min" },
        {
          label: "Guard Verdict",
          value: jwksBlocked
            ? `${faultEval.statusBadge} (${faultEval.shortLabel})`
            : jwksRecovered
              ? "Refetched & Verified"
              : lastApiResult?.status === 401
                ? "Rejected (401)"
                : hasSession
                  ? "Claims Verified"
                  : "Awaiting JWT"
        }
      ]
    },
    {
      id: "rbac",
      step: "05",
      title: "RBAC Protected API",
      subtitle: "Groups & OAuth2 Scopes",
      edgeLabel: flowMode === "agent" ? "OBO 8693" : "",
      rfcBadge: "Least-Privilege RBAC",
      stateTone: apiBlocked ? "blocked" : apiOk ? "verified" : hasSession ? "active" : "ready",
      stateLabel: apiBlocked
        ? `HTTP ${lastApiResult?.status} DENIED`
        : apiOk
          ? `HTTP ${lastApiResult?.status} ALLOWED`
          : hasSession
            ? "POLICY READY"
            : "GUARDED",
      payloadTitle: "Authorization Policy & Last API Evaluation",
      payload: {
        middleware: "backend/src/middleware/rbacMiddleware.ts",
        subject: claims?.sub ?? null,
        assignedGroups: claims?.groups ?? [],
        grantedScopes: claims?.scopes ?? [],
        adminRoutePolicy: "requireRoles('admin', 'administrator')",
        reportWritePolicy: "requireScopes('write:reports')",
        lastInvocation: lastApiResult
          ? {
              endpoint: `${lastApiResult.method} ${lastApiResult.endpoint}`,
              status: lastApiResult.status,
              latencyMs: lastApiResult.latencyMs,
              mode: lastApiResult.mode
            }
          : "Invoke any endpoint in the Test Bench below"
      },
      invariants: [
        "Separates coarse-grained organizational roles (groups) from fine-grained API capabilities (scope).",
        "Fails closed with structured 403 Forbidden diagnostics when required roles or scopes are absent.",
        "Hardened Express surface: Helmet security headers, strict CORS allow-list, 1MB JSON body cap."
      ],
      telemetry: [
        {
          label: "Admin Role",
          value: claims
            ? claims.isAdmin
              ? "Granted (admin)"
              : "Denied (developer)"
            : "No Principal"
        },
        {
          label: "write:reports",
          value: claims
            ? claims.hasWriteReports
              ? "Scope Present"
              : "Scope Missing"
            : "No Principal"
        },
        {
          label: "Last HTTP Status",
          value: lastApiResult
            ? `${lastApiResult.status || "ERR"} (${lastApiResult.latencyMs}ms)`
            : "Not Invoked"
        }
      ]
    }
  ];

  if (flowMode === "agent") {
    const mcpFaultBlocked = faultStage === "agent_mcp" && faultEval.isBlocked;
    const mcpBlocked =
      mcpFaultBlocked ||
      Boolean(lastMcpResult && (lastMcpResult.status === 401 || lastMcpResult.status === 403));
    const mcpOk = !mcpFaultBlocked && Boolean(lastMcpResult && lastMcpResult.ok);

    baseStages.push({
      id: "agent_mcp",
      step: "06",
      title: "AI Agent OBO -> MCP",
      subtitle: `RFC 8693 · act · ${AGENT_TOKEN_MAX_TTL_SECONDS}s TTL`,
      edgeLabel: "",
      rfcBadge: mcpFaultBlocked ? faultEval.rfc : "RFC 8693 OBO · MCP Guard",
      stateTone: mcpBlocked ? "blocked" : mcpOk ? "verified" : "active",
      stateLabel: mcpFaultBlocked
        ? faultEval.statusBadge.toUpperCase()
        : mcpBlocked
          ? `MCP ${lastMcpResult?.status} BLOCKED`
          : mcpOk
            ? "MCP 200 ALLOWED"
            : "OBO DELEGATED",
      payloadTitle: "RFC 8693 On-Behalf-Of Token Exchange & MCP Tool Guard",
      payload: {
        sts_issuer_mode:
          delegatedSession?.stsMode === "dev-idp"
            ? "Local Dev IdP / STS (POST /dev-idp/oauth2/token)"
            : "Simulated STS (Browser Web Crypto RS256)",
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        endpoint: "POST /api/mcp (JSON-RPC 2.0)",
        subject_human: delegatedSession?.humanSubject ?? "usr_4b21d90e_dev",
        actor_claim: delegatedSession?.actor ?? {
          sub: "agent:choreo-integrator-bot",
          client_id: "choreo-mcp-agent-v1"
        },
        audience_binding: delegatedSession?.audience ?? config.mcpAudience,
        downscoped_scopes: delegatedSession?.grantedScopes ?? ["orders:read"],
        stripped_privileged_scopes: delegatedSession?.strippedScopes ?? [
          "admin:write",
          "refunds:execute"
        ],
        ttl_seconds: delegatedSession?.ttlSeconds ?? AGENT_TOKEN_MAX_TTL_SECONDS,
        lastMcpDecision: lastMcpResult
          ? {
              status: lastMcpResult.status,
              ok: lastMcpResult.ok,
              defenseTrace: lastMcpResult.defenseTrace ?? null
            }
          : "Trigger an MCP tools/call action below"
      },
      invariants: [
        "RFC 8693 Token Exchange binds the AI agent identity in act.sub while preserving human accountability in sub.",
        `Privilege attenuation strips high-risk scopes (admin:write, refunds:execute) and caps TTL to ${AGENT_TOKEN_MAX_TTL_SECONDS} seconds.`,
        "POST /api/mcp enforces JSON-RPC 2.0, RFC 9449 DPoP sender-constrained proofs, and CIBA step-up consent."
      ],
      telemetry: [
        {
          label: "Actor (act.sub)",
          value: delegatedSession?.actor.sub ?? "agent:choreo-integrator-bot"
        },
        {
          label: "Delegated Scope",
          value: delegatedSession?.grantedScopes.join(" ") ?? "orders:read"
        },
        {
          label: "Last MCP Guard",
          value: lastMcpResult
            ? `HTTP ${lastMcpResult.status} (${lastMcpResult.ok ? "Allowed" : "Denied"})`
            : "Ready for tools/call"
        }
      ]
    });
  }

  return baseStages;
}
