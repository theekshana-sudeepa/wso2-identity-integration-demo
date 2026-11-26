import { AGENT_TOKEN_MAX_TTL_SECONDS } from "../lib/agentPolicy";
import {
  memo,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent
} from "react";
import {
  Activity,
  Bot,
  CheckCircle2,
  Code2,
  Cpu,
  KeyRound,
  Pause,
  Play,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Workflow,
  Wrench
} from "lucide-react";
import type { ApiCallResult } from "../lib/apiClient";
import {
  IDP_PRESETS,
  type DelegatedAgentSession,
  type OidcConfig,
  type ParsedJwtClaims,
  type PkceTelemetry,
  type TokenSession
} from "../lib/pkce";
import {
  assertNever,
  MCP_TOOLS,
  type FaultEvaluation,
  type FaultState,
  type FlowMode,
  type FlowStageId,
  type McpToolName,
  type McpToolSpec
} from "../lib/securityLab";
import { AttackLabPanel } from "./AttackLabPanel";
import { JsonHighlighter } from "./JsonHighlighter";
import { TokenTtlBadge } from "./TokenTtlBadge";

export type { FlowStageId };

interface OidcFlowVisualizerProps {
  readonly config: OidcConfig;
  readonly flowMode: FlowMode;
  readonly selectedStage: FlowStageId;
  readonly session: TokenSession | null;
  readonly claims: ParsedJwtClaims | null;
  readonly delegatedSession: DelegatedAgentSession | null;
  readonly pkceTelemetry: PkceTelemetry | null;
  readonly lastApiResult: ApiCallResult | null;
  readonly lastMcpResult: ApiCallResult | null;
  readonly activeFault: FaultState;
  readonly faultEval: FaultEvaluation;
  readonly attackLabOpen: boolean;
  readonly mcpLoadingTool: McpToolName | null;
  readonly onSelectStage: (stage: FlowStageId) => void;
  readonly onChangeFault: (fault: FaultState) => void;
  readonly onToggleAttackLab: () => void;
  readonly onRegeneratePkce: () => Promise<void>;
  readonly onRefreshDelegatedToken: () => void;
  readonly onInvokeMcpTool: (tool: McpToolSpec) => Promise<void>;
  readonly onOpenCodeExporter: () => void;
}

type StageTone = "active" | "verified" | "ready" | "blocked" | "recovered";

interface StageDescriptor {
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

function truncateMiddle(value: string, lead = 12, tail = 8): string {
  if (value.length <= lead + tail + 3) return value;
  return `${value.slice(0, lead)}...${value.slice(-tail)}`;
}

interface SvgStageNodeProps {
  readonly stage: StageDescriptor;
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
  readonly isSelected: boolean;
  readonly isFaultTarget: boolean;
  readonly onSelect: (id: FlowStageId) => void;
  readonly onKeyNav: (e: KeyboardEvent<SVGGElement>, id: FlowStageId) => void;
  readonly registerNodeRef: (id: FlowStageId, el: SVGGElement | null) => void;
}

const SvgStageNode = memo(function SvgStageNode({
  stage,
  x,
  y,
  width,
  height,
  isSelected,
  isFaultTarget,
  onSelect,
  onKeyNav,
  registerNodeRef
}: SvgStageNodeProps) {
  const toneClass = `tone-${stage.stateTone}`;

  return (
    <g
      ref={(el) => registerNodeRef(stage.id, el)}
      transform={`translate(${x}, ${y})`}
      className={`svg-node ${isSelected ? "svg-node-selected" : ""} ${isFaultTarget ? "svg-node-fault" : ""} ${toneClass}`}
      role="button"
      tabIndex={0}
      aria-pressed={isSelected}
      aria-label={`Stage ${stage.step}: ${stage.title} — ${stage.stateLabel}. Use Left or Right Arrow keys to navigate stages.`}
      onClick={() => onSelect(stage.id)}
      onKeyDown={(e) => onKeyNav(e, stage.id)}
    >
      <rect
        x="-5"
        y="-5"
        width={width + 10}
        height={height + 10}
        rx="16"
        className="svg-node-focus-ring"
      />
      {(isSelected || isFaultTarget) && (
        <rect
          x="-4"
          y="-4"
          width={width + 8}
          height={height + 8}
          rx="15"
          className={`svg-node-glow ${stage.stateTone === "blocked" ? "svg-glow-blocked" : stage.stateTone === "recovered" ? "svg-glow-recovered" : ""}`}
        />
      )}
      <rect
        x="0"
        y="0"
        width={width}
        height={height}
        rx="12"
        className="svg-node-box"
      />

      <rect x="12" y="12" width="30" height="20" rx="6" className="svg-step-pill" />
      <text x="27" y="25.5" textAnchor="middle" className="svg-step-text">
        {stage.step}
      </text>

      <circle cx={width - 16} cy="22" r="4" className={`svg-status-dot ${toneClass}`} />

      <text x="12" y="55" className="svg-node-title">
        {stage.title}
      </text>
      <text x="12" y="73" className="svg-node-subtitle">
        {stage.subtitle}
      </text>

      <rect x="12" y="84" width={width - 24} height="18" rx="5" className="svg-state-bar" />
      <text x="19" y="96" className={`svg-state-text ${toneClass}`}>
        {stage.stateLabel}
      </text>
    </g>
  );
});

function renderStageIcon(id: FlowStageId) {
  switch (id) {
    case "spa":
      return <Cpu size={15} />;
    case "pkce":
      return <KeyRound size={15} />;
    case "idp":
      return <ShieldCheck size={15} />;
    case "jwks":
      return <Activity size={15} />;
    case "rbac":
      return <Server size={15} />;
    case "agent_mcp":
      return <Bot size={15} />;
    default:
      return assertNever(id);
  }
}

export const OidcFlowVisualizer = memo(function OidcFlowVisualizer({
  config,
  flowMode,
  selectedStage,
  session,
  claims,
  delegatedSession,
  pkceTelemetry,
  lastApiResult,
  lastMcpResult,
  activeFault,
  faultEval,
  attackLabOpen,
  mcpLoadingTool,
  onSelectStage,
  onChangeFault,
  onToggleAttackLab,
  onRegeneratePkce,
  onRefreshDelegatedToken,
  onInvokeMcpTool,
  onOpenCodeExporter
}: OidcFlowVisualizerProps) {
  const [isSimulating, setIsSimulating] = useState(false);
  const [isRefreshingPkce, setIsRefreshingPkce] = useState(false);
  const nodeRefs = useRef<Partial<Record<FlowStageId, SVGGElement | null>>>({});

  const stageOrder: readonly FlowStageId[] = useMemo(
    () =>
      flowMode === "agent"
        ? ["spa", "pkce", "idp", "jwks", "rbac", "agent_mcp"]
        : ["spa", "pkce", "idp", "jwks", "rbac"],
    [flowMode]
  );

  useEffect(() => {
    if (!isSimulating) return undefined;
    const timer = window.setInterval(() => {
      const currentIndex = stageOrder.indexOf(selectedStage);
      const nextIndex = (currentIndex + 1) % stageOrder.length;
      onSelectStage(stageOrder[nextIndex]);
    }, 1500);
    return () => window.clearInterval(timer);
  }, [isSimulating, stageOrder, selectedStage, onSelectStage]);

  const registerNodeRef = useCallback((id: FlowStageId, el: SVGGElement | null) => {
    nodeRefs.current[id] = el;
  }, []);

  const handleSelectNode = useCallback(
    (id: FlowStageId) => {
      setIsSimulating(false);
      onSelectStage(id);
    },
    [onSelectStage]
  );

  const handleNodeKeyDown = useCallback(
    (e: KeyboardEvent<SVGGElement>, id: FlowStageId) => {
      const idx = stageOrder.indexOf(id);
      if (e.key === "ArrowRight") {
        e.preventDefault();
        const nextId = stageOrder[(idx + 1) % stageOrder.length];
        setIsSimulating(false);
        onSelectStage(nextId);
        nodeRefs.current[nextId]?.focus();
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        const prevId = stageOrder[(idx - 1 + stageOrder.length) % stageOrder.length];
        setIsSimulating(false);
        onSelectStage(prevId);
        nodeRefs.current[prevId]?.focus();
      } else if (e.key === "Home") {
        e.preventDefault();
        const firstId = stageOrder[0];
        setIsSimulating(false);
        onSelectStage(firstId);
        nodeRefs.current[firstId]?.focus();
      } else if (e.key === "End") {
        e.preventDefault();
        const lastId = stageOrder[stageOrder.length - 1];
        setIsSimulating(false);
        onSelectStage(lastId);
        nodeRefs.current[lastId]?.focus();
      } else if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        setIsSimulating(false);
        onSelectStage(id);
      }
    },
    [stageOrder, onSelectStage]
  );

  const presetMeta = IDP_PRESETS[config.preset];

  const stages: readonly StageDescriptor[] = useMemo(() => {
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
      const mcpBlocked = Boolean(
        lastMcpResult && (lastMcpResult.status === 401 || lastMcpResult.status === 403)
      );
      const mcpOk = Boolean(lastMcpResult && lastMcpResult.ok);

      baseStages.push({
        id: "agent_mcp",
        step: "06",
        title: "AI Agent OBO -> MCP",
        subtitle: `RFC 8693 · act · ${AGENT_TOKEN_MAX_TTL_SECONDS}s TTL`,
        edgeLabel: "",
        rfcBadge: "RFC 8693 OBO · MCP Guard",
        stateTone: mcpBlocked ? "blocked" : mcpOk ? "verified" : "active",
        stateLabel: mcpBlocked
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
          endpoint: "POST /api/mcp/tools/call",
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
          "POST /api/mcp/tools/call enforces requireAgentDelegation() + scope-subset + human step-up consent."
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
  }, [
    config,
    presetMeta,
    flowMode,
    session,
    claims,
    delegatedSession,
    pkceTelemetry,
    lastApiResult,
    lastMcpResult,
    faultEval
  ]);

  const activeStage = stages.find((s) => s.id === selectedStage) ?? stages[0];
  const activeIndex = stageOrder.indexOf(activeStage.id);
  const faultIndex = faultEval.failingStage ? stageOrder.indexOf(faultEval.failingStage) : -1;

  const isSixStage = stages.length === 6;
  const nodeWidth = isSixStage ? 176 : 184;
  const nodeHeight = 112;
  const nodeGap = isSixStage ? 46 : 64;
  const startX = 16;
  const nodeY = 42;
  const svgWidth = startX * 2 + stages.length * nodeWidth + (stages.length - 1) * nodeGap;
  const svgHeight = 198;

  const handleRefreshPkce = useCallback(async () => {
    setIsRefreshingPkce(true);
    try {
      await onRegeneratePkce();
      onSelectStage("pkce");
    } finally {
      setIsRefreshingPkce(false);
    }
  }, [onRegeneratePkce, onSelectStage]);

  return (
    <section
      className="card flow-card"
      aria-label="Interactive OIDC PKCE, RS256 JWKS, and AI Agent OBO Flow Visualizer"
    >
      <div className="flow-header">
        <div>
          <div className="eyebrow-row">
            <span className="eyebrow-badge">
              <Workflow size={13} />
              {flowMode === "agent"
                ? "6-Stage AI Agent Delegation Pipeline"
                : "5-Stage CIAM Protocol Pipeline"}
            </span>
            <span className="eyebrow-meta">
              Click or use ← / → Arrow keys on nodes to inspect payloads &amp; RFC invariants
            </span>
          </div>
          <h2 className="flow-title">
            {flowMode === "agent"
              ? "OIDC PKCE (S256) · Stateless RS256 JWKS · RFC 8693 AI Agent & MCP Guard"
              : "OIDC PKCE (S256) & Stateless RS256 JWKS Flow Visualizer"}
          </h2>
        </div>

        <div className="flow-actions">
          <button
            type="button"
            className="btn btn-sm"
            onClick={handleRefreshPkce}
            disabled={isRefreshingPkce}
          >
            <RefreshCw size={14} className={isRefreshingPkce ? "spin" : ""} />
            Regenerate S256
          </button>
          <button
            type="button"
            className="btn btn-sm"
            onClick={onOpenCodeExporter}
          >
            <Code2 size={14} />
            Export Code
          </button>
          <button
            type="button"
            className={`btn btn-sm ${isSimulating ? "btn-primary" : ""}`}
            onClick={() => setIsSimulating((prev) => !prev)}
          >
            {isSimulating ? <Pause size={14} /> : <Play size={14} />}
            {isSimulating ? "Pause Walk" : "Simulate Flow"}
          </button>
        </div>
      </div>

      {/* Compact Toggleable Attack Lab Panel */}
      <AttackLabPanel
        isOpen={attackLabOpen}
        activeFault={activeFault}
        faultEval={faultEval}
        onToggleOpen={onToggleAttackLab}
        onChangeFault={onChangeFault}
      />

      {/* Interactive SVG Node Graph */}
      <div className="flow-canvas-wrap">
        <svg
          className="flow-svg"
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          role="group"
          aria-label={`${stages.length}-stage OAuth 2.0 PKCE, RS256 JWKS${flowMode === "agent" ? ", and AI Agent RFC 8693 MCP" : ""} flow diagram`}
        >
          <defs>
            <marker
              id="arrow-muted"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1.5 L 9 5 L 0 8.5 z" className="svg-arrow-muted" />
            </marker>
            <marker
              id="arrow-active"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1.5 L 9 5 L 0 8.5 z" className="svg-arrow-active" />
            </marker>
            <marker
              id="arrow-blocked"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1.5 L 9 5 L 0 8.5 z" className="svg-arrow-blocked" />
            </marker>
            <pattern id="dot-grid" width="20" height="20" patternUnits="userSpaceOnUse">
              <circle cx="2" cy="2" r="1" className="svg-grid-dot" />
            </pattern>
          </defs>

          <rect
            x="0"
            y="0"
            width={svgWidth}
            height={svgHeight}
            rx="12"
            fill="url(#dot-grid)"
            className="svg-bg-grid"
          />

          {/* Connectors */}
          {stages.slice(0, -1).map((stage, index) => {
            const x1 = startX + index * (nodeWidth + nodeGap) + nodeWidth;
            const x2 = x1 + nodeGap;
            const y = nodeY + nodeHeight / 2;
            const midX = (x1 + x2) / 2;

            const isBlockedEdge =
              faultEval.isBlocked && faultIndex > 0 && index === faultIndex - 1;
            const isHaltedDownstream =
              faultEval.isBlocked && faultIndex >= 0 && index >= faultIndex;
            const isHighlighted =
              !isHaltedDownstream &&
              (index < activeIndex ||
                (isSimulating && index === activeIndex) ||
                (faultEval.isBlocked && index < faultIndex - 1));

            const edgeClass = isBlockedEdge
              ? "svg-edge svg-edge-blocked"
              : isHaltedDownstream
                ? "svg-edge svg-edge-halted"
                : isHighlighted
                  ? "svg-edge svg-edge-active"
                  : "svg-edge";

            const markerEnd = isBlockedEdge
              ? "url(#arrow-blocked)"
              : isHighlighted
                ? "url(#arrow-active)"
                : "url(#arrow-muted)";

            const pillWidth = stage.edgeLabel.length > 5 ? 54 : 42;

            return (
              <g key={`edge-${stage.id}`}>
                <line
                  x1={x1 + 4}
                  y1={y}
                  x2={x2 - 6}
                  y2={y}
                  className={edgeClass}
                  markerEnd={markerEnd}
                />
                <rect
                  x={midX - pillWidth / 2}
                  y={y - 24}
                  width={pillWidth}
                  height="16"
                  rx="5"
                  className={`svg-edge-pill ${isBlockedEdge ? "svg-edge-pill-blocked" : ""}`}
                />
                <text
                  x={midX}
                  y={y - 13}
                  textAnchor="middle"
                  className={`svg-edge-label ${isBlockedEdge ? "svg-edge-label-blocked" : ""}`}
                >
                  {stage.edgeLabel}
                </text>
              </g>
            );
          })}

          {/* Memoized Focusable Nodes */}
          {stages.map((stage, index) => (
            <SvgStageNode
              key={stage.id}
              stage={stage}
              x={startX + index * (nodeWidth + nodeGap)}
              y={nodeY}
              width={nodeWidth}
              height={nodeHeight}
              isSelected={stage.id === activeStage.id}
              isFaultTarget={faultEval.failingStage === stage.id && faultEval.active}
              onSelect={handleSelectNode}
              onKeyNav={handleNodeKeyDown}
              registerNodeRef={registerNodeRef}
            />
          ))}
        </svg>
      </div>

      {/* Stage 6 AI Agent Delegation & Interactive MCP Tool Strip */}
      {flowMode === "agent" && delegatedSession && (
        <div className="mcp-delegation-strip" aria-label="RFC 8693 AI Agent Delegation and MCP Guard">
          <div className="mcp-strip-header">
            <div className="mcp-strip-title">
              <span className="stage-icon-chip stage-icon-agent">
                <Bot size={15} />
              </span>
              <div>
                <div className="mcp-title-row">
                  <h3>Stage 06 · AI Agent Identity &amp; MCP Tool Guard (RFC 8693 OBO)</h3>
                  <TokenTtlBadge expiresAtSec={delegatedSession.expiresAtSec} />
                </div>
                <p className="mcp-subtitle">
                  Actor <code>{delegatedSession.actor.sub}</code> acting on behalf of{" "}
                  <code>{delegatedSession.humanSubject}</code> · Down-scoped to{" "}
                  <code>{delegatedSession.grantedScopes.join(" ")}</code> (stripped:{" "}
                  <code>{delegatedSession.strippedScopes.slice(0, 3).join(", ")}</code>)
                </p>
              </div>
            </div>

            <button
              type="button"
              className="btn btn-xs"
              onClick={onRefreshDelegatedToken}
            >
              <RefreshCw size={12} />
              Re-Exchange OBO (60s)
            </button>
          </div>

          <div className="mcp-tools-grid">
            {MCP_TOOLS.map((tool) => {
              const isBusy = mcpLoadingTool === tool.name;
              const verdictTone =
                tool.name === "get_order_status" ? "mcp-expect-allow" : "mcp-expect-deny";
              return (
                <div key={tool.name} className="mcp-tool-card">
                  <div className="mcp-tool-head">
                    <span className="mcp-tool-cmd">
                      <Wrench size={12} />
                      {tool.commandLabel}
                    </span>
                    <span className={`mcp-expect-badge ${verdictTone}`}>
                      {tool.expectedVerdict}
                    </span>
                  </div>
                  <p className="mcp-tool-desc">{tool.description}</p>
                  <div className="mcp-tool-foot">
                    <span className="mcp-req-scope">
                      requires: <code>{tool.requiredScope}</code>
                    </span>
                    <button
                      type="button"
                      className="btn btn-xs"
                      disabled={mcpLoadingTool !== null}
                      onClick={() => onInvokeMcpTool(tool)}
                    >
                      <Play size={11} />
                      {isBusy ? "Calling..." : "Execute Tool"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Synchronized Stage Inspector */}
      <div className="flow-inspector">
        <div className="flow-inspector-banner">
          <div className="flow-inspector-heading">
            <span className="stage-icon-chip">{renderStageIcon(activeStage.id)}</span>
            <div>
              <div className="flow-inspector-title-row">
                <span className="mono-step">STAGE {activeStage.step}</span>
                <h3>{activeStage.title}</h3>
                <span className="rfc-chip">{activeStage.rfcBadge}</span>
              </div>
              <p className="flow-inspector-desc">{activeStage.payloadTitle}</p>
            </div>
          </div>

          <div className="stage-stepper">
            {stages.map((s) => (
              <button
                key={s.id}
                type="button"
                className={`stepper-dot ${s.id === activeStage.id ? "stepper-dot-active" : ""} ${
                  s.stateTone === "blocked" ? "stepper-dot-blocked" : ""
                }`}
                onClick={() => handleSelectNode(s.id)}
                aria-label={`Jump to stage ${s.step}: ${s.title}`}
              >
                {s.step}
              </button>
            ))}
          </div>
        </div>

        <div className="flow-inspector-grid">
          <div className="inspector-pane inspector-pane-payload">
            <div className="pane-label">Protocol Wire Payload</div>
            <JsonHighlighter
              data={activeStage.payload}
              maxHeight={220}
              copyLabel="Copy stage payload"
            />
          </div>

          <div className="inspector-pane">
            <div className="pane-label">Security Invariants</div>
            <ul className="invariant-list">
              {activeStage.invariants.map((item) => (
                <li key={item}>
                  <CheckCircle2 size={14} className="invariant-icon" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="inspector-pane">
            <div className="pane-label">Live Runtime State</div>
            <div className="telemetry-stack">
              {activeStage.telemetry.map((metric) => (
                <div key={metric.label} className="telemetry-row">
                  <span className="telemetry-label">{metric.label}</span>
                  <span className="telemetry-value">{metric.value}</span>
                </div>
              ))}
            </div>
            <div className={`state-callout tone-${activeStage.stateTone}`}>
              {activeStage.stateTone === "blocked" ? (
                <ShieldAlert size={14} />
              ) : (
                <ShieldCheck size={14} />
              )}
              <span>
                Status: <strong>{activeStage.stateLabel}</strong>
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
});
