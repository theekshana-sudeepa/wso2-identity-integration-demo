import {
  memo,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent
} from "react";
import { Code2, Pause, Play, RefreshCw, Workflow } from "lucide-react";
import type {
  ApiCallResult,
  McpAuditEntry,
  PendingCibaRequest,
  VerificationMode
} from "../lib/apiClient";
import type {
  DelegatedAgentSession,
  OidcConfig,
  ParsedJwtClaims,
  PkceTelemetry,
  TokenSession
} from "../lib/pkce";
import type {
  FaultEvaluation,
  FaultState,
  FlowMode,
  FlowStageId,
  McpToolName,
  McpToolSpec
} from "../lib/securityLab";
import { AttackLabPanel } from "./AttackLabPanel";
import { FlowCanvas } from "./flow/FlowCanvas";
import { McpToolStrip } from "./flow/McpToolStrip";
import { StageInspector } from "./flow/StageInspector";
import { buildStageDescriptors, getStageOrder } from "./flow/stageDescriptors";

export type { FlowStageId };

export interface OidcFlowVisualizerProps {
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
  readonly mcpAuditEntries?: readonly McpAuditEntry[];
  readonly pendingCibaRequest?: PendingCibaRequest | null;
  readonly verificationMode?: VerificationMode;
  readonly tokenRevoked?: boolean;
  readonly onSelectStage: (stage: FlowStageId) => void;
  readonly onChangeFault: (fault: FaultState) => void;
  readonly onToggleAttackLab: () => void;
  readonly onRegeneratePkce: () => Promise<void>;
  readonly onRefreshDelegatedToken: () => void;
  readonly onInvokeMcpTool: (tool: McpToolSpec) => void | Promise<void>;
  readonly onDecisionCiba?: (decision: "APPROVED" | "DENIED") => void;
  readonly onChangeVerificationMode?: (mode: VerificationMode) => void;
  readonly onRevokeToken?: () => void;
  readonly onOpenCodeExporter: () => void;
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
  mcpAuditEntries = [],
  pendingCibaRequest = null,
  verificationMode = "jwks",
  tokenRevoked = false,
  onSelectStage,
  onChangeFault,
  onToggleAttackLab,
  onRegeneratePkce,
  onRefreshDelegatedToken,
  onInvokeMcpTool,
  onDecisionCiba,
  onChangeVerificationMode,
  onRevokeToken,
  onOpenCodeExporter
}: OidcFlowVisualizerProps) {
  const [isSimulating, setIsSimulating] = useState(false);
  const [isRefreshingPkce, setIsRefreshingPkce] = useState(false);
  const nodeRefs = useRef<Partial<Record<FlowStageId, SVGGElement | null>>>({});

  const stageOrder = useMemo(() => getStageOrder(flowMode), [flowMode]);

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

  const stages = useMemo(
    () =>
      buildStageDescriptors({
        config,
        flowMode,
        session,
        claims,
        delegatedSession,
        pkceTelemetry,
        lastApiResult,
        lastMcpResult,
        faultEval
      }),
    [
      config,
      flowMode,
      session,
      claims,
      delegatedSession,
      pkceTelemetry,
      lastApiResult,
      lastMcpResult,
      faultEval
    ]
  );

  const activeStage = stages.find((s) => s.id === selectedStage) ?? stages[0];
  const activeIndex = stageOrder.indexOf(activeStage.id);
  const faultIndex = faultEval.failingStage ? stageOrder.indexOf(faultEval.failingStage) : -1;

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

      <AttackLabPanel
        isOpen={attackLabOpen}
        activeFault={activeFault}
        faultEval={faultEval}
        onToggleOpen={onToggleAttackLab}
        onChangeFault={onChangeFault}
      />

      <FlowCanvas
        stages={stages}
        activeStage={activeStage}
        activeIndex={activeIndex}
        faultIndex={faultIndex}
        flowMode={flowMode}
        faultEval={faultEval}
        isSimulating={isSimulating}
        onSelectNode={handleSelectNode}
        onKeyNav={handleNodeKeyDown}
        registerNodeRef={registerNodeRef}
      />

      {flowMode === "agent" && delegatedSession && (
        <McpToolStrip
          delegatedSession={delegatedSession}
          mcpLoadingTool={mcpLoadingTool}
          mcpAuditEntries={mcpAuditEntries}
          pendingCibaRequest={pendingCibaRequest}
          onRefreshDelegatedToken={onRefreshDelegatedToken}
          onInvokeMcpTool={onInvokeMcpTool}
          onDecisionCiba={onDecisionCiba}
        />
      )}

      <StageInspector
        stages={stages}
        activeStage={activeStage}
        verificationMode={verificationMode}
        tokenRevoked={tokenRevoked}
        onSelectNode={handleSelectNode}
        onChangeVerificationMode={onChangeVerificationMode}
        onRevokeToken={onRevokeToken}
      />
    </section>
  );
});
