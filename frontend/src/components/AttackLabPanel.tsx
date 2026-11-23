import { memo } from "react";
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Zap
} from "lucide-react";
import {
  FAULT_PRESETS,
  type FaultEvaluation,
  type FaultState
} from "../lib/securityLab";

interface AttackLabPanelProps {
  readonly isOpen: boolean;
  readonly activeFault: FaultState;
  readonly faultEval: FaultEvaluation;
  readonly onToggleOpen: () => void;
  readonly onChangeFault: (next: FaultState) => void;
}

export const AttackLabPanel = memo(function AttackLabPanel({
  isOpen,
  activeFault,
  faultEval,
  onToggleOpen,
  onChangeFault
}: AttackLabPanelProps) {
  const hasActiveFault = activeFault.id !== "none";

  return (
    <div className={`attack-lab ${hasActiveFault ? (faultEval.isBlocked ? "attack-lab-alert" : "attack-lab-recovered") : ""}`}>
      <div className="attack-lab-bar">
        <button
          type="button"
          className="attack-lab-toggle"
          onClick={onToggleOpen}
          aria-expanded={isOpen}
          aria-controls="attack-lab-body"
        >
          <span className={`lab-icon ${hasActiveFault ? (faultEval.isBlocked ? "lab-icon-danger" : "lab-icon-success") : ""}`}>
            {hasActiveFault ? <Zap size={14} /> : <AlertTriangle size={14} />}
          </span>
          <span className="attack-lab-title">
            Break-the-Flow Security &amp; Edge-Case Lab
          </span>
          <span
            className={`lab-status-pill ${
              !hasActiveFault
                ? "lab-pill-ok"
                : faultEval.isBlocked
                  ? "lab-pill-blocked"
                  : "lab-pill-recovered"
            }`}
          >
            {faultEval.statusBadge} · {faultEval.shortLabel}
          </span>
          <span className="lab-chevron">
            {isOpen ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
          </span>
        </button>

        {hasActiveFault && (
          <button
            type="button"
            className="btn btn-xs"
            onClick={() => onChangeFault({ id: "none" })}
          >
            <RotateCcw size={12} />
            Reset Baseline
          </button>
        )}
      </div>

      {isOpen && (
        <div id="attack-lab-body" className="attack-lab-body">
          <div className="fault-grid" role="radiogroup" aria-label="Security fault injection scenarios">
            {FAULT_PRESETS.map((preset) => {
              const selected = activeFault.id === preset.id;
              return (
                <button
                  key={preset.id}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  className={`fault-chip ${selected ? "fault-chip-active" : ""} ${
                    selected && preset.id !== "none" ? "fault-chip-danger" : ""
                  }`}
                  onClick={() => onChangeFault(preset.createDefaultState())}
                >
                  <div className="fault-chip-top">
                    <span className="fault-chip-name">{preset.label}</span>
                    <span className="fault-chip-rfc">{preset.rfc}</span>
                  </div>
                  <span className="fault-chip-stage">{preset.stageHint}</span>
                </button>
              );
            })}
          </div>

          {/* Parameterized sub-controls for interactive edge-case tuning */}
          {activeFault.id === "jwt_alg_downgrade" && (
            <div className="fault-subcontrols">
              <span className="subcontrol-label">Injected Header Algorithm:</span>
              <div className="segmented-tabs">
                <button
                  type="button"
                  className={`seg-tab ${activeFault.algorithm === "none" ? "seg-tab-active" : ""}`}
                  onClick={() => onChangeFault({ id: "jwt_alg_downgrade", algorithm: "none" })}
                >
                  alg: &quot;none&quot; (Unsigned)
                </button>
                <button
                  type="button"
                  className={`seg-tab ${activeFault.algorithm === "HS256" ? "seg-tab-active" : ""}`}
                  onClick={() => onChangeFault({ id: "jwt_alg_downgrade", algorithm: "HS256" })}
                >
                  alg: &quot;HS256&quot; (Key Confusion)
                </button>
              </div>
            </div>
          )}

          {activeFault.id === "jwks_kid_miss" && (
            <div className="fault-subcontrols">
              <span className="subcontrol-label">JWKS Cache-Miss Resolution Branch:</span>
              <div className="segmented-tabs">
                <button
                  type="button"
                  className={`seg-tab ${activeFault.resolution === "reject_unknown_kid" ? "seg-tab-active" : ""}`}
                  onClick={() =>
                    onChangeFault({ id: "jwks_kid_miss", resolution: "reject_unknown_kid" })
                  }
                >
                  Unknown kid (401 Fail-Closed)
                </button>
                <button
                  type="button"
                  className={`seg-tab ${activeFault.resolution === "recover_rotated_key" ? "seg-tab-active" : ""}`}
                  onClick={() =>
                    onChangeFault({ id: "jwks_kid_miss", resolution: "recover_rotated_key" })
                  }
                >
                  Rotated Key Refetch (200 Recover)
                </button>
              </div>
            </div>
          )}

          {activeFault.id === "aud_iss_spoof" && (
            <div className="fault-subcontrols">
              <span className="subcontrol-label">Spoofed Claim Target:</span>
              <div className="segmented-tabs">
                <button
                  type="button"
                  className={`seg-tab ${activeFault.spoofTarget === "aud" ? "seg-tab-active" : ""}`}
                  onClick={() => onChangeFault({ id: "aud_iss_spoof", spoofTarget: "aud" })}
                >
                  Audience (aud) Confusion
                </button>
                <button
                  type="button"
                  className={`seg-tab ${activeFault.spoofTarget === "iss" ? "seg-tab-active" : ""}`}
                  onClick={() => onChangeFault({ id: "aud_iss_spoof", spoofTarget: "iss" })}
                >
                  Issuer (iss) Cross-Tenant
                </button>
              </div>
            </div>
          )}

          {activeFault.id === "expired_token_skew" && (
            <div className="fault-subcontrols">
              <span className="subcontrol-label">Injected Expiry Delta (vs ±5s tolerance):</span>
              <div className="segmented-tabs">
                {[30, 185, 900].map((seconds) => (
                  <button
                    key={seconds}
                    type="button"
                    className={`seg-tab ${activeFault.skewSeconds === seconds ? "seg-tab-active" : ""}`}
                    onClick={() =>
                      onChangeFault({ id: "expired_token_skew", skewSeconds: seconds })
                    }
                  >
                    -{seconds}s past exp
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Structured Defense Trace */}
          <div
            className={`defense-trace-card ${
              faultEval.defenseTrace.outcome === "REJECTED"
                ? "trace-rejected"
                : faultEval.defenseTrace.outcome === "RECOVERED"
                  ? "trace-recovered"
                  : "trace-allowed"
            }`}
          >
            <div className="defense-trace-head">
              <div className="defense-trace-title">
                {faultEval.defenseTrace.outcome === "REJECTED" ? (
                  <ShieldAlert size={15} />
                ) : (
                  <ShieldCheck size={15} />
                )}
                <span>Defense Trace · {faultEval.defenseTrace.layer}</span>
                <span className="rfc-chip">{faultEval.defenseTrace.rfc}</span>
              </div>
              <span className={`trace-outcome-badge outcome-${faultEval.defenseTrace.outcome.toLowerCase()}`}>
                {faultEval.defenseTrace.outcome} · {faultEval.statusBadge}
              </span>
            </div>

            <p className="defense-trace-summary">{faultEval.summary}</p>

            <div className="defense-trace-grid">
              <div className="trace-kv">
                <span>Guard / Middleware</span>
                <code>{faultEval.defenseTrace.middleware}</code>
              </div>
              <div className="trace-kv">
                <span>Invariant Evaluated</span>
                <code>{faultEval.defenseTrace.check}</code>
              </div>
              <div className="trace-kv trace-kv-wide">
                <span>Enforcement Verdict</span>
                <p>{faultEval.defenseTrace.details}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
});
