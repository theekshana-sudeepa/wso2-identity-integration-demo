import { memo } from "react";
import {
  Activity,
  Bot,
  CheckCircle2,
  Play,
  RefreshCw,
  ShieldAlert,
  Wrench
} from "lucide-react";
import type { McpAuditEntry, PendingCibaRequest } from "../../lib/apiClient";
import type { DelegatedAgentSession } from "../../lib/pkce";
import {
  MCP_TOOLS,
  type McpToolName,
  type McpToolSpec
} from "../../lib/securityLab";
import { TokenTtlBadge } from "../TokenTtlBadge";

export interface McpToolStripProps {
  readonly delegatedSession: DelegatedAgentSession;
  readonly mcpLoadingTool: McpToolName | null;
  readonly mcpAuditEntries: readonly McpAuditEntry[];
  readonly pendingCibaRequest: PendingCibaRequest | null;
  readonly onRefreshDelegatedToken: () => void;
  readonly onInvokeMcpTool: (tool: McpToolSpec) => void | Promise<void>;
  readonly onDecisionCiba?: (decision: "APPROVED" | "DENIED") => void;
}

export const McpToolStrip = memo(function McpToolStrip({
  delegatedSession,
  mcpLoadingTool,
  mcpAuditEntries,
  pendingCibaRequest,
  onRefreshDelegatedToken,
  onInvokeMcpTool,
  onDecisionCiba
}: McpToolStripProps) {
  return (
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
              <code>{delegatedSession.grantedScopes.join(" ")}</code> · RFC 9449 DPoP{" "}
              <code>cnf.jkt: {delegatedSession.dpopJkt?.slice(0, 12) ?? "ES256"}...</code>
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
                  onClick={() => {
                    void onInvokeMcpTool(tool);
                  }}
                >
                  <Play size={11} />
                  {isBusy ? "Calling..." : "Execute Tool"}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {pendingCibaRequest && (
        <div
          className="defense-trace-card trace-rejected"
          role="region"
          aria-label="CIBA Step-Up Human Approval Request"
          style={{ marginTop: "0.75rem" }}
        >
          <div className="defense-trace-head">
            <div className="defense-trace-title">
              <ShieldAlert size={15} />
              <span>CIBA Step-Up Approval Request · Push Consent Required</span>
              <span className="rfc-chip">auth_req_id: {pendingCibaRequest.authReqId}</span>
            </div>
            <span className="trace-outcome-badge outcome-rejected">
              AWAITING HUMAN CONSENT ({pendingCibaRequest.expiresIn}s)
            </span>
          </div>
          <p className="defense-trace-summary">
            <strong>Binding Message:</strong> {pendingCibaRequest.bindingMessage} (Principal:{" "}
            <code>{pendingCibaRequest.sub}</code>)
          </p>
          <div className="btn-row" style={{ marginTop: "0.5rem" }}>
            <button
              type="button"
              className="btn btn-primary btn-xs"
              onClick={() => onDecisionCiba?.("APPROVED")}
            >
              <CheckCircle2 size={13} />
              Approve Step-Up Consent (Mint One-Time 120s Claim &amp; Retry)
            </button>
            <button
              type="button"
              className="btn btn-danger btn-xs"
              onClick={() => onDecisionCiba?.("DENIED")}
            >
              <ShieldAlert size={13} />
              Deny Request
            </button>
          </div>
        </div>
      )}

      {mcpAuditEntries.length > 0 && (
        <div className="mcp-audit-timeline" aria-label="Agent Activity Timeline">
          <div className="mcp-strip-header" style={{ marginTop: "0.75rem" }}>
            <div className="mcp-strip-title">
              <span className="stage-icon-chip">
                <Activity size={13} />
              </span>
              <div>
                <h4>Agent Activity Timeline · JSON-RPC 2.0 Audit Ring Buffer</h4>
              </div>
            </div>
            <span className="rfc-chip">{mcpAuditEntries.length} recorded</span>
          </div>
          <div
            className="trace-kv-grid"
            style={{ display: "grid", gap: "0.35rem", marginTop: "0.4rem" }}
          >
            {mcpAuditEntries.slice(0, 5).map((entry) => (
              <div
                key={entry.id}
                className="trace-kv"
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  gap: "0.75rem",
                  fontSize: "0.76rem",
                  padding: "0.35rem 0.6rem"
                }}
              >
                <span>
                  <strong>{entry.tool}</strong> · <code>{entry.actorSub}</code> on behalf of{" "}
                  <code>{entry.sub}</code> (tier: <code>{entry.riskTier}</code>
                  {entry.jti ? `, jti: ${entry.jti}` : ""})
                </span>
                <span
                  className={`mcp-expect-badge ${
                    entry.decision === "ALLOWED" ? "mcp-expect-allow" : "mcp-expect-deny"
                  }`}
                >
                  {entry.status} {entry.decision} · {entry.reason}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
});
