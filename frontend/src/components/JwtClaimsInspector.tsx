import { useState } from "react";
import { CheckCircle2, FileCode2, Shield, Terminal, XCircle } from "lucide-react";
import { API_ENDPOINTS, evaluateEndpointAccess } from "../lib/apiClient";
import type { DecodedJwt, ParsedJwtClaims } from "../lib/pkce";
import { JsonHighlighter } from "./JsonHighlighter";

type InspectorTab = "claims" | "json" | "raw";

interface JwtClaimsInspectorProps {
  readonly decoded: DecodedJwt | null;
  readonly claims: ParsedJwtClaims | null;
}

function formatExpiryDelta(expiresAtSec: number | null): string {
  if (!expiresAtSec) return "—";
  const remainingSec = Math.max(0, expiresAtSec - Math.floor(Date.now() / 1000));
  const mins = Math.floor(remainingSec / 60);
  if (mins >= 60) {
    const hrs = Math.floor(mins / 60);
    const remMins = mins % 60;
    return `${hrs}h ${remMins}m remaining`;
  }
  return `${mins}m remaining`;
}

export function JwtClaimsInspector({ decoded, claims }: JwtClaimsInspectorProps) {
  const [activeTab, setActiveTab] = useState<InspectorTab>("claims");

  return (
    <article className="card">
      <div className="card-header">
        <div className="card-title">
          <span className="icon-box">
            <Terminal size={16} />
          </span>
          <div>
            <h2>Live JWT Claims &amp; RBAC Inspector</h2>
            <p className="card-caption">Asymmetric RS256 header, identity claims &amp; policy preview</p>
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

      {!decoded || !claims ? (
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
            <div className="identity-avatar">{claims.username.slice(0, 2).toUpperCase()}</div>
            <div className="identity-main">
              <div className="identity-name-row">
                <span className="identity-name">{claims.username}</span>
                <span className={`role-pill ${claims.isAdmin ? "role-pill-admin" : "role-pill-dev"}`}>
                  {claims.isAdmin ? "ADMIN PRIVILEGE" : "STANDARD USER"}
                </span>
              </div>
              <div className="identity-sub">
                sub: <code>{claims.sub}</code> · {formatExpiryDelta(claims.expiresAtSec)}
              </div>
            </div>
          </div>

          <div className="crypto-strip">
            <div className="crypto-cell">
              <span>Algorithm</span>
              <strong>{claims.alg}</strong>
            </div>
            <div className="crypto-cell">
              <span>Key ID (kid)</span>
              <strong title={claims.kid}>{claims.kid}</strong>
            </div>
            <div className="crypto-cell">
              <span>Audience</span>
              <strong>{claims.audience}</strong>
            </div>
          </div>

          <div className="chip-group">
            <div className="chip-group-label">RBAC Groups</div>
            <div className="chip-row">
              {claims.groups.map((group) => (
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
            <div className="chip-group-label">OAuth 2.0 Scopes</div>
            <div className="chip-row">
              {claims.scopes.map((scope) => (
                <span
                  key={scope}
                  className={`claim-chip claim-chip-mono ${scope === "write:reports" ? "claim-chip-success" : ""}`}
                >
                  {scope}
                </span>
              ))}
            </div>
          </div>

          <div className="rbac-preview">
            <div className="chip-group-label">Real-Time Endpoint Policy Matrix</div>
            <div className="rbac-matrix">
              {API_ENDPOINTS.map((ep) => {
                const verdict = evaluateEndpointAccess(ep, claims);
                const allowed = verdict === "allowed";
                return (
                  <div key={ep.id} className="rbac-matrix-row">
                    <span className="rbac-route">{ep.path}</span>
                    <span className={`rbac-verdict ${allowed ? "verdict-allow" : "verdict-deny"}`}>
                      {allowed ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                      {allowed ? "ALLOW" : "403 DENY"}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ) : activeTab === "json" ? (
        <JsonHighlighter
          data={{ header: decoded.header, payload: decoded.payload }}
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
            <span className="jwt-part-header">{decoded.rawParts[0]}</span>
            <span className="jwt-dot">.</span>
            <span className="jwt-part-payload">{decoded.rawParts[1]}</span>
            <span className="jwt-dot">.</span>
            <span className="jwt-part-sig">{decoded.rawParts[2]}</span>
          </div>
        </div>
      )}
    </article>
  );
}
