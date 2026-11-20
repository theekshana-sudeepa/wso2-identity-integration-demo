import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  CheckCircle2,
  Cpu,
  KeyRound,
  Pause,
  Play,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Workflow
} from "lucide-react";
import type { ApiCallResult } from "../lib/apiClient";
import {
  IDP_PRESETS,
  type OidcConfig,
  type ParsedJwtClaims,
  type PkceTelemetry,
  type TokenSession
} from "../lib/pkce";
import { JsonHighlighter } from "./JsonHighlighter";

export type FlowStageId = "spa" | "pkce" | "idp" | "jwks" | "rbac";

interface OidcFlowVisualizerProps {
  readonly config: OidcConfig;
  readonly session: TokenSession | null;
  readonly claims: ParsedJwtClaims | null;
  readonly pkceTelemetry: PkceTelemetry | null;
  readonly lastApiResult: ApiCallResult | null;
  readonly onRegeneratePkce: () => Promise<void>;
}

interface StageDescriptor {
  readonly id: FlowStageId;
  readonly step: string;
  readonly title: string;
  readonly subtitle: string;
  readonly edgeLabel: string;
  readonly rfcBadge: string;
  readonly stateTone: "active" | "verified" | "ready" | "blocked";
  readonly stateLabel: string;
  readonly payloadTitle: string;
  readonly payload: Record<string, unknown>;
  readonly invariants: readonly string[];
  readonly telemetry: readonly { readonly label: string; readonly value: string; readonly tone?: string }[];
}

const NODE_WIDTH = 184;
const NODE_HEIGHT = 112;
const NODE_GAP = 64;
const START_X = 16;
const NODE_Y = 40;

function truncateMiddle(value: string, lead = 12, tail = 8): string {
  if (value.length <= lead + tail + 3) return value;
  return `${value.slice(0, lead)}...${value.slice(-tail)}`;
}

export function OidcFlowVisualizer({
  config,
  session,
  claims,
  pkceTelemetry,
  lastApiResult,
  onRegeneratePkce
}: OidcFlowVisualizerProps) {
  const [selectedStage, setSelectedStage] = useState<FlowStageId>("pkce");
  const [isSimulating, setIsSimulating] = useState(false);
  const [isRefreshingPkce, setIsRefreshingPkce] = useState(false);

  const stageOrder: readonly FlowStageId[] = useMemo(
    () => ["spa", "pkce", "idp", "jwks", "rbac"],
    []
  );

  useEffect(() => {
    if (!isSimulating) return undefined;
    const timer = window.setInterval(() => {
      setSelectedStage((current) => {
        const currentIndex = stageOrder.indexOf(current);
        const nextIndex = (currentIndex + 1) % stageOrder.length;
        return stageOrder[nextIndex];
      });
    }, 1500);
    return () => window.clearInterval(timer);
  }, [isSimulating, stageOrder]);

  const presetMeta = IDP_PRESETS[config.preset];

  const stages: readonly StageDescriptor[] = useMemo(() => {
    const hasSession = Boolean(session && claims);
    const apiBlocked = Boolean(lastApiResult && (lastApiResult.status === 401 || lastApiResult.status === 403));
    const apiOk = Boolean(lastApiResult && lastApiResult.ok);

    return [
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
          { label: "Session Mode", value: session ? (session.mode === "live" ? "Live OIDC" : "Demo Simulation") : "Unauthenticated" }
        ]
      },
      {
        id: "pkce",
        step: "02",
        title: "Web Crypto S256 PKCE",
        subtitle: "384-bit Verifier · CSRF State",
        edgeLabel: "AuthZ",
        rfcBadge: "RFC 7636 · S256",
        stateTone: pkceTelemetry ? "verified" : "ready",
        stateLabel: pkceTelemetry ? "CRYPTO READY" : "INITIALIZING",
        payloadTitle: "Live Web Crypto API PKCE Artifacts",
        payload: pkceTelemetry
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
          { label: "Verifier Kept In", value: "Browser Memory / Session" }
        ]
      },
      {
        id: "idp",
        step: "03",
        title: "Choreo Labs / WSO2 IS",
        subtitle: `${presetMeta.shortLabel} · OIDC & JWKS`,
        edgeLabel: "RS256",
        rfcBadge: "OIDC Core 1.0",
        stateTone: hasSession ? "verified" : "ready",
        stateLabel: hasSession ? "JWT MINTED" : "IDP STANDBY",
        payloadTitle: `${presetMeta.label} OIDC Contract`,
        payload: {
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
          { label: "Issuer (iss)", value: truncateMiddle(config.issuer, 20, 14) }
        ]
      },
      {
        id: "jwks",
        step: "04",
        title: "Stateless RS256 Verify",
        subtitle: "JWKS Cache · iss / aud / exp",
        edgeLabel: "RBAC",
        rfcBadge: "RFC 7519 · JWKS",
        stateTone:
          lastApiResult?.status === 401
            ? "blocked"
            : hasSession
              ? "verified"
              : "ready",
        stateLabel:
          lastApiResult?.status === 401
            ? "401 REJECTED"
            : hasSession
              ? "RS256 VALIDATED"
              : "AWAITING BEARER",
        payloadTitle: "Express authMiddleware Verification Policy",
        payload: {
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
          "Enforces strict issuer (iss), audience (aud), and expiration (exp) claim verification."
        ],
        telemetry: [
          { label: "Algorithm Pin", value: "RS256 Only" },
          { label: "JWKS Cache TTL", value: "10 min · 10 req/min" },
          {
            label: "Token Status",
            value:
              lastApiResult?.status === 401
                ? "Rejected (401 Invalid Sig)"
                : hasSession
                  ? "Claims Parsed"
                  : "No Token"
          }
        ]
      },
      {
        id: "rbac",
        step: "05",
        title: "RBAC Protected API",
        subtitle: "Groups & OAuth2 Scopes",
        edgeLabel: "",
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
            value: claims ? (claims.isAdmin ? "Granted (admin)" : "Denied (developer)") : "No Principal"
          },
          {
            label: "write:reports",
            value: claims ? (claims.hasWriteReports ? "Scope Present" : "Scope Missing") : "No Principal"
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
  }, [config, presetMeta, session, claims, pkceTelemetry, lastApiResult]);

  const activeStage = stages.find((s) => s.id === selectedStage) ?? stages[0];
  const activeIndex = stageOrder.indexOf(activeStage.id);

  async function handleRefreshPkce() {
    setIsRefreshingPkce(true);
    try {
      await onRegeneratePkce();
      setSelectedStage("pkce");
    } finally {
      setIsRefreshingPkce(false);
    }
  }

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
    }
  }

  return (
    <section className="card flow-card" aria-label="Interactive OIDC PKCE and RS256 JWKS Flow Visualizer">
      <div className="flow-header">
        <div>
          <div className="eyebrow-row">
            <span className="eyebrow-badge">
              <Workflow size={13} />
              Interactive Protocol Pipeline
            </span>
            <span className="eyebrow-meta">
              Choreo Labs (formerly WSO2) · Click any node to inspect wire payload &amp; invariants
            </span>
          </div>
          <h2 className="flow-title">OIDC PKCE (S256) &amp; Stateless RS256 JWKS Flow Visualizer</h2>
        </div>

        <div className="flow-actions">
          <button
            type="button"
            className="btn btn-sm"
            onClick={handleRefreshPkce}
            disabled={isRefreshingPkce}
          >
            <RefreshCw size={14} className={isRefreshingPkce ? "spin" : ""} />
            Regenerate S256 PKCE
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

      {/* Interactive SVG Node Graph */}
      <div className="flow-canvas-wrap">
        <svg
          className="flow-svg"
          viewBox="0 0 1208 196"
          role="group"
          aria-label="5-stage OAuth 2.0 PKCE and RS256 JWKS flow diagram"
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
            <pattern id="dot-grid" width="20" height="20" patternUnits="userSpaceOnUse">
              <circle cx="2" cy="2" r="1" className="svg-grid-dot" />
            </pattern>
          </defs>

          <rect x="0" y="0" width="1208" height="196" rx="12" fill="url(#dot-grid)" className="svg-bg-grid" />

          {/* Connectors */}
          {stages.slice(0, -1).map((stage, index) => {
            const x1 = START_X + index * (NODE_WIDTH + NODE_GAP) + NODE_WIDTH;
            const x2 = x1 + NODE_GAP;
            const y = NODE_Y + NODE_HEIGHT / 2;
            const isHighlighted = index < activeIndex || (isSimulating && index === activeIndex);
            const midX = (x1 + x2) / 2;

            return (
              <g key={`edge-${stage.id}`}>
                <line
                  x1={x1 + 4}
                  y1={y}
                  x2={x2 - 6}
                  y2={y}
                  className={`svg-edge ${isHighlighted ? "svg-edge-active" : ""}`}
                  markerEnd={isHighlighted ? "url(#arrow-active)" : "url(#arrow-muted)"}
                />
                <rect x={midX - 22} y={y - 24} width="44" height="16" rx="5" className="svg-edge-pill" />
                <text x={midX} y={y - 13} textAnchor="middle" className="svg-edge-label">
                  {stage.edgeLabel}
                </text>
              </g>
            );
          })}

          {/* Nodes */}
          {stages.map((stage, index) => {
            const x = START_X + index * (NODE_WIDTH + NODE_GAP);
            const isSelected = stage.id === activeStage.id;
            const toneClass = `tone-${stage.stateTone}`;

            return (
              <g
                key={stage.id}
                transform={`translate(${x}, ${NODE_Y})`}
                className={`svg-node ${isSelected ? "svg-node-selected" : ""} ${toneClass}`}
                role="button"
                tabIndex={0}
                aria-pressed={isSelected}
                aria-label={`Stage ${stage.step}: ${stage.title} — ${stage.stateLabel}`}
                onClick={() => {
                  setIsSimulating(false);
                  setSelectedStage(stage.id);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setIsSimulating(false);
                    setSelectedStage(stage.id);
                  }
                }}
              >
                {isSelected && (
                  <rect
                    x="-4"
                    y="-4"
                    width={NODE_WIDTH + 8}
                    height={NODE_HEIGHT + 8}
                    rx="15"
                    className="svg-node-glow"
                  />
                )}
                <rect
                  x="0"
                  y="0"
                  width={NODE_WIDTH}
                  height={NODE_HEIGHT}
                  rx="12"
                  className="svg-node-box"
                />

                {/* Step pill */}
                <rect x="12" y="12" width="30" height="20" rx="6" className="svg-step-pill" />
                <text x="27" y="25.5" textAnchor="middle" className="svg-step-text">
                  {stage.step}
                </text>

                {/* Status dot + label */}
                <circle cx={NODE_WIDTH - 16} cy="22" r="4" className={`svg-status-dot ${toneClass}`} />

                {/* Title & subtitle */}
                <text x="12" y="55" className="svg-node-title">
                  {stage.title}
                </text>
                <text x="12" y="73" className="svg-node-subtitle">
                  {stage.subtitle}
                </text>

                {/* Footer state tag */}
                <rect x="12" y="84" width={NODE_WIDTH - 24} height="18" rx="5" className="svg-state-bar" />
                <text x="20" y="96" className={`svg-state-text ${toneClass}`}>
                  {stage.stateLabel}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

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
                className={`stepper-dot ${s.id === activeStage.id ? "stepper-dot-active" : ""}`}
                onClick={() => {
                  setIsSimulating(false);
                  setSelectedStage(s.id);
                }}
              >
                {s.step}
              </button>
            ))}
          </div>
        </div>

        <div className="flow-inspector-grid">
          <div className="inspector-pane inspector-pane-payload">
            <div className="pane-label">Protocol Wire Payload</div>
            <JsonHighlighter data={activeStage.payload} maxHeight={220} copyLabel="Copy stage payload" />
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
}
