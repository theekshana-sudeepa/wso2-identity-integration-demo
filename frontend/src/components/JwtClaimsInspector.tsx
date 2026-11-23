import { memo, useMemo, useState } from "react";
import { Bot, CheckCircle2, FileCode2, Shield, Terminal, User, XCircle } from "lucide-react";
import { API_ENDPOINTS, evaluateEndpointAccess } from "../lib/apiClient";
import type { DecodedJwt, ParsedJwtClaims } from "../lib/pkce";
import { MCP_TOOLS, type FlowMode } from "../lib/securityLab";
import { JsonHighlighter } from "./JsonHighlighter";
import { TokenTtlBadge } from "./TokenTtlBadge";

type InspectorTab = "claims" | "json" | "raw";
type TokenViewTarget = "human" | "agent";

interface JwtClaimsInspectorProps {
  readonly flowMode: FlowMode;
  readonly decoded: DecodedJwt | null;
  readonly claims: ParsedJwtClaims | null;
  readonly delegatedDecoded: DecodedJwt | null;
  readonly delegatedClaims: ParsedJwtClaims | null;
}

export const JwtClaimsInspector = memo(function JwtClaimsInspector({
  flowMode,
  decoded,
  claims,
  delegatedDecoded,
  delegatedClaims
}: JwtClaimsInspectorProps) {
  const [activeTab, setActiveTab] = useState<InspectorTab>("claims");
  const [tokenView, setTokenView] = useState<TokenViewTarget>("agent");

  const showingAgentToken =
    flowMode === "agent" && tokenView === "agent" && Boolean(delegatedDecoded && delegatedClaims);

  const activeDecoded = showingAgentToken ? delegatedDecoded : decoded;
  const activeClaims = showingAgentToken ? delegatedClaims : claims;

  const endpointVerdicts = useMemo(() => {
    if (!activeClaims) return [];
    return API_ENDPOINTS.map((ep) => ({
      endpoint: ep,
      allowed: evaluateEndpointAccess(ep, activeClaims) === "allowed"
    }));
  }, [activeClaims]);

  const jsonViewData = useMemo(() => {
    if (!activeDecoded) return null;
    return { header: activeDecoded.header, payload: activeDecoded.payload };
  }, [activeDecoded]);

  return (
    <article className="card">
      <div className="card-header">
        <div className="card-title">
          <span className="icon-box">
            {showingAgentToken ? <Bot size={16} /> : <Terminal size={16} />}
          </span>
          <div>
            <h2>Live JWT Claims &amp; RBAC Inspector</h2>
            <p className="card-caption">
              {showingAgentToken
                ? "RFC 8693 OBO Delegated Agent JWT · sub + act + down-scoped TTL"
                : "Asymmetric RS256 header, identity claims & policy preview"}
            </p>
          </div>
        </div>

        <div className="segmented-tabs" role="tablist" aria-label="JWT inspector view">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "claims"}
            className={`seg-tab ${activeTab === "claims" ? "seg-tab-active" : ""}`}
            onClick={() => setActiveTab("claims")}
          >
            <Shield size={13} />
            Claims
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "json"}
            className={`seg-tab ${activeTab === "json" ? "seg-tab-active" : ""}`}
            onClick={() => setActiveTab("json")}
          >
            <FileCode2 size={13} />
            JSON
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "raw"}
            className={`seg-tab ${activeTab === "raw" ? "seg-tab-active" : ""}`}
            onClick={() => setActiveTab("raw")}
          >
            Raw
          </button>
        </div>
      </div>

      {/* Token Switcher when AI Agent Delegation mode is active */}
      {flowMode === "agent" && delegatedClaims && (
        <div className="inspector-token-switcher">
          <div className="segmented-tabs" role="tablist" aria-label="Select human or delegated agent token">
            <button
              type="button"
              role="tab"
              aria-selected={showingAgentToken}
              className={`seg-tab ${showingAgentToken ? "seg-tab-active" : ""}`}
              onClick={() => setTokenView("agent")}
            >
              <Bot size={13} />
              Delegated Agent JWT (OBO)
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={!showingAgentToken}
              className={`seg-tab ${!showingAgentToken ? "seg-tab-active" : ""}`}
              onClick={() => setTokenView("human")}
            >
              <User size={13} />
              Human Subject JWT
            </button>
          </div>

          <TokenTtlBadge expiresAtSec={activeClaims?.expiresAtSec ?? null} compact />
        </div>
      )}

      {!activeDecoded || !activeClaims ? (
        <div className="empty-inspector">
          <div className="empty-inspector-icon">
            <Shield size={22} />
          </div>
          <h3>No Active Bearer Token</h3>
          <p>
            Sign in via WSO2 Identity Server / Asgardeo or load a <strong>Demo Developer</strong>{" "}
            or <strong>Demo Admin</strong> session to inspect RS256 claims and live RBAC decisions.
          </p>
        </div>
      ) : activeTab === "claims" ? (
        <div className="claims-panel">
          <div className="identity-strip">
            <div className={`identity-avatar ${showingAgentToken ? "identity-avatar-agent" : ""}`}>
              {showingAgentToken ? <Bot size={16} /> : activeClaims.username.slice(0, 2).toUpperCase()}
            </div>
            <div className="identity-main">
              <div className="identity-name-row">
                <span className="identity-name">
                  {showingAgentToken && activeClaims.actor
                    ? activeClaims.actor.sub
                    : activeClaims.username}
                </span>
                <span
                  className={`role-pill ${
                    showingAgentToken
                      ? "role-pill-agent"
                      : activeClaims.isAdmin
                        ? "role-pill-admin"
                        : "role-pill-dev"
                  }`}
                >
                  {showingAgentToken
                    ? "RFC 8693 OBO AGENT"
                    : activeClaims.isAdmin
                      ? "ADMIN PRIVILEGE"
                      : "STANDARD USER"}
                </span>
              </div>
              <div className="identity-sub">
                sub: <code>{activeClaims.sub}</code> ·{" "}
                <TokenTtlBadge expiresAtSec={activeClaims.expiresAtSec} compact />
              </div>
            </div>
          </div>

          {/* Highlighted RFC 8693 Actor Claim Strip */}
          {activeClaims.actor && (
            <div className="actor-claim-callout">
              <div className="actor-callout-row">
                <span className="actor-key">act.sub</span>
                <code className="actor-val">{activeClaims.actor.sub}</code>
                <span className="actor-key">client_id</span>
                <code className="actor-val">{activeClaims.actor.client_id}</code>
              </div>
              <div className="actor-callout-sub">
                Delegated On-Behalf-Of human principal <code>{activeClaims.sub}</code> ·
                depth: <code>{activeClaims.delegationDepth ?? 1}</code>
              </div>
            </div>
          )}

          <div className="crypto-strip">
            <div className="crypto-cell">
              <span>Algorithm</span>
              <strong>{activeClaims.alg}</strong>
            </div>
            <div className="crypto-cell">
              <span>Key ID (kid)</span>
              <strong title={activeClaims.kid}>{activeClaims.kid}</strong>
            </div>
            <div className="crypto-cell">
              <span>Audience (aud)</span>
              <strong title={activeClaims.audience}>{activeClaims.audience}</strong>
            </div>
          </div>

          <div className="chip-group">
            <div className="chip-group-label">RBAC Groups</div>
            <div className="chip-row">
              {activeClaims.groups.map((group) => (
                <span
                  key={group}
                  className={`claim-chip ${group.toLowerCase() === "admin" ? "claim-chip-accent" : ""}`}
                >
                  {group}
                </span>
              ))}
            </div>
          </div>

          <div className="chip-group">
            <div className="chip-group-label">
              {showingAgentToken ? "Down-Scoped OAuth 2.0 Scopes" : "OAuth 2.0 Scopes"}
            </div>
            <div className="chip-row">
              {activeClaims.scopes.map((scope) => (
                <span
                  key={scope}
                  className={`claim-chip claim-chip-mono ${
                    scope === "write:reports" || scope === "orders:read"
                      ? "claim-chip-success"
                      : ""
                  }`}
                >
                  {scope}
                </span>
              ))}
              {showingAgentToken &&
                activeClaims.strippedScopes.map((stripped) => (
                  <span
                    key={`stripped-${stripped}`}
                    className="claim-chip claim-chip-mono claim-chip-stripped"
                    title="Intentionally stripped during RFC 8693 OBO down-scoping"
                  >
                    ✕ {stripped}
                  </span>
                ))}
            </div>
          </div>

          <div className="rbac-preview">
            <div className="chip-group-label">
              {showingAgentToken
                ? "Real-Time MCP Tool Policy Matrix"
                : "Real-Time Endpoint Policy Matrix"}
            </div>
            <div className="rbac-matrix">
              {showingAgentToken
                ? MCP_TOOLS.map((tool) => {
                    const allowed =
                      activeClaims.scopes.includes(tool.requiredScope) &&
                      (!tool.requiresHumanApproval || activeClaims.hasHumanApproval);
                    return (
                      <div key={tool.name} className="rbac-matrix-row">
                        <span className="rbac-route">{tool.commandLabel}</span>
                        <span
                          className={`rbac-verdict ${allowed ? "verdict-allow" : "verdict-deny"}`}
                        >
                          {allowed ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                          {allowed
                            ? "200 ALLOW"
                            : tool.requiresHumanApproval
                              ? "403 STEP-UP"
                              : "403 ESCALATION"}
                        </span>
                      </div>
                    );
                  })
                : endpointVerdicts.map(({ endpoint, allowed }) => (
                    <div key={endpoint.id} className="rbac-matrix-row">
                      <span className="rbac-route">{endpoint.path}</span>
                      <span
                        className={`rbac-verdict ${allowed ? "verdict-allow" : "verdict-deny"}`}
                      >
                        {allowed ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                        {allowed ? "ALLOW" : "403 DENY"}
                      </span>
                    </div>
                  ))}
            </div>
          </div>
        </div>
      ) : activeTab === "json" ? (
        <JsonHighlighter
          data={jsonViewData}
          maxHeight={340}
          copyLabel="Copy decoded JWT JSON"
        />
      ) : (
        <div className="raw-jwt-box">
          <div className="raw-jwt-legend">
            <span className="legend-dot legend-header">Header (alg / kid)</span>
            <span className="legend-dot legend-payload">Payload (claims)</span>
            <span className="legend-dot legend-sig">RS256 Signature</span>
          </div>
          <div className="raw-jwt-code">
            <span className="jwt-part-header">{activeDecoded.rawParts[0]}</span>
            <span className="jwt-dot">.</span>
            <span className="jwt-part-payload">{activeDecoded.rawParts[1]}</span>
            <span className="jwt-dot">.</span>
            <span className="jwt-part-sig">{activeDecoded.rawParts[2]}</span>
          </div>
        </div>
      )}
    </article>
  );
});
