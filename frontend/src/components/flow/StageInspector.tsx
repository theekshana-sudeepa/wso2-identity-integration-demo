import { memo } from "react";
import {
  Activity,
  Bot,
  CheckCircle2,
  Cpu,
  KeyRound,
  Server,
  ShieldAlert,
  ShieldCheck
} from "lucide-react";
import type { VerificationMode } from "../../lib/apiClient";
import { assertNever, type FlowStageId } from "../../lib/securityLab";
import { JsonHighlighter } from "../JsonHighlighter";
import type { StageDescriptor } from "./stageDescriptors";

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

export interface StageInspectorProps {
  readonly stages: readonly StageDescriptor[];
  readonly activeStage: StageDescriptor;
  readonly verificationMode: VerificationMode;
  readonly tokenRevoked: boolean;
  readonly onSelectNode: (id: FlowStageId) => void;
  readonly onChangeVerificationMode?: (mode: VerificationMode) => void;
  readonly onRevokeToken?: () => void;
}

export const StageInspector = memo(function StageInspector({
  stages,
  activeStage,
  verificationMode,
  tokenRevoked,
  onSelectNode,
  onChangeVerificationMode,
  onRevokeToken
}: StageInspectorProps) {
  return (
    <div className="flow-inspector">
      {activeStage.id === "jwks" && (
        <div
          className="fault-subcontrols"
          style={{
            marginBottom: "0.75rem",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "0.6rem"
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
            <span className="subcontrol-label">
              Architectural Trade-Off (Stateless JWKS vs. RFC 7662 Introspection):
            </span>
            <div className="segmented-tabs">
              <button
                type="button"
                className={`seg-tab ${verificationMode === "jwks" ? "seg-tab-active" : ""}`}
                onClick={() => onChangeVerificationMode?.("jwks")}
              >
                Stateless JWKS (0 IdP Hops · ~0.4ms)
              </button>
              <button
                type="button"
                className={`seg-tab ${verificationMode === "introspect" ? "seg-tab-active" : ""}`}
                onClick={() => onChangeVerificationMode?.("introspect")}
              >
                RFC 7662 Introspection (+1 IdP Hop · Real-Time Revocation)
              </button>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            {tokenRevoked && (
              <span className="mcp-expect-badge mcp-expect-deny">
                Token Revoked (RFC 7009) — JWKS still accepts until exp!
              </span>
            )}
            <button
              type="button"
              className="btn btn-xs btn-danger"
              onClick={() => onRevokeToken?.()}
            >
              <ShieldAlert size={12} />
              {tokenRevoked ? "Token Revoked at IdP" : "Revoke Active Token (RFC 7009)"}
            </button>
          </div>
        </div>
      )}

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
              onClick={() => onSelectNode(s.id)}
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
  );
});
