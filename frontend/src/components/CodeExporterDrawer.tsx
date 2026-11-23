import { memo, useMemo, useState } from "react";
import { Check, Code2, Copy, Eye, EyeOff, FileJson, Terminal, X } from "lucide-react";
import type { DelegatedAgentSession, OidcConfig } from "../lib/pkce";
import {
  generateCodeSnippets,
  type FaultEvaluation,
  type FlowMode,
  type FlowStageId
} from "../lib/securityLab";

type ExporterTab = "curl" | "typescript" | "oidc_json";

interface CodeExporterDrawerProps {
  readonly isOpen: boolean;
  readonly config: OidcConfig;
  readonly flowMode: FlowMode;
  readonly selectedStage: FlowStageId;
  readonly activeToken: string | null;
  readonly faultEval: FaultEvaluation;
  readonly delegatedSession: DelegatedAgentSession | null;
  readonly onClose: () => void;
  readonly onNotifyCopy: (message: string) => void;
}

export const CodeExporterDrawer = memo(function CodeExporterDrawer({
  isOpen,
  config,
  flowMode,
  selectedStage,
  activeToken,
  faultEval,
  delegatedSession,
  onClose,
  onNotifyCopy
}: CodeExporterDrawerProps) {
  const [activeTab, setActiveTab] = useState<ExporterTab>("curl");
  const [redactToken, setRedactToken] = useState(true);
  const [copied, setCopied] = useState(false);

  const snippets = useMemo(
    () =>
      generateCodeSnippets({
        config,
        flowMode,
        selectedStage,
        activeToken,
        faultEval,
        delegatedSession,
        redactToken
      }),
    [config, flowMode, selectedStage, activeToken, faultEval, delegatedSession, redactToken]
  );

  if (!isOpen) return null;

  const activeSnippet =
    activeTab === "curl"
      ? snippets.curl
      : activeTab === "typescript"
        ? snippets.typescript
        : snippets.oidcConfigJson;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(activeSnippet);
      setCopied(true);
      onNotifyCopy(
        activeTab === "curl"
          ? "Copied curl command to clipboard"
          : activeTab === "typescript"
            ? "Copied strict TypeScript fetch snippet"
            : "Copied WSO2 IS / Asgardeo OIDC JSON config"
      );
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      onNotifyCopy("Clipboard access unavailable in this browser context");
    }
  };

  return (
    <div
      className="drawer-backdrop"
      role="presentation"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <aside
        className="exporter-drawer"
        role="dialog"
        aria-modal="true"
        aria-label="Live Request and Code Exporter"
      >
        <div className="drawer-header">
          <div className="card-title">
            <span className="icon-box">
              <Code2 size={16} />
            </span>
            <div>
              <h2>Live Request &amp; Code Exporter</h2>
              <p className="card-caption">
                Synchronized with stage <code>{selectedStage}</code> ·{" "}
                {flowMode === "agent" ? "AI Agent RFC 8693 OBO" : "Human CIAM"}
              </p>
            </div>
          </div>

          <button
            type="button"
            className="btn btn-xs"
            onClick={onClose}
            aria-label="Close code exporter"
          >
            <X size={14} />
          </button>
        </div>

        <div className="drawer-context-strip">
          <span className="rfc-chip">Target: {snippets.targetEndpoint}</span>
          <span className={`rfc-chip ${faultEval.isBlocked ? "chip-fault-warn" : ""}`}>
            Fault: {faultEval.shortLabel}
          </span>
        </div>

        <div className="drawer-toolbar">
          <div className="segmented-tabs" role="tablist" aria-label="Export snippet format">
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === "curl"}
              className={`seg-tab ${activeTab === "curl" ? "seg-tab-active" : ""}`}
              onClick={() => setActiveTab("curl")}
            >
              <Terminal size={13} />
              curl
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === "typescript"}
              className={`seg-tab ${activeTab === "typescript" ? "seg-tab-active" : ""}`}
              onClick={() => setActiveTab("typescript")}
            >
              <Code2 size={13} />
              TypeScript fetch
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === "oidc_json"}
              className={`seg-tab ${activeTab === "oidc_json" ? "seg-tab-active" : ""}`}
              onClick={() => setActiveTab("oidc_json")}
            >
              <FileJson size={13} />
              OIDC JSON
            </button>
          </div>

          <div className="drawer-actions">
            {activeTab === "curl" && (
              <button
                type="button"
                className="btn btn-xs"
                onClick={() => setRedactToken((prev) => !prev)}
                title={redactToken ? "Reveal full Bearer JWT" : "Redact Bearer JWT"}
              >
                {redactToken ? <Eye size={13} /> : <EyeOff size={13} />}
                {redactToken ? "Reveal Token" : "Redact Token"}
              </button>
            )}
            <button type="button" className="btn btn-xs btn-primary" onClick={handleCopy}>
              {copied ? <Check size={13} /> : <Copy size={13} />}
              {copied ? "Copied" : "Copy Snippet"}
            </button>
          </div>
        </div>

        <pre className="code-block exporter-code">{activeSnippet}</pre>
      </aside>
    </div>
  );
});
