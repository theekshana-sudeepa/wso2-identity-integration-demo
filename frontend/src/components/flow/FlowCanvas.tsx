import { memo, type KeyboardEvent } from "react";
import type {
  FaultEvaluation,
  FlowMode,
  FlowStageId
} from "../../lib/securityLab";
import { SvgStageNode } from "./StageNode";
import type { StageDescriptor } from "./stageDescriptors";

export interface FlowCanvasProps {
  readonly stages: readonly StageDescriptor[];
  readonly activeStage: StageDescriptor;
  readonly activeIndex: number;
  readonly faultIndex: number;
  readonly flowMode: FlowMode;
  readonly faultEval: FaultEvaluation;
  readonly isSimulating: boolean;
  readonly onSelectNode: (id: FlowStageId) => void;
  readonly onKeyNav: (e: KeyboardEvent<SVGGElement>, id: FlowStageId) => void;
  readonly registerNodeRef: (id: FlowStageId, el: SVGGElement | null) => void;
}

export const FlowCanvas = memo(function FlowCanvas({
  stages,
  activeStage,
  activeIndex,
  faultIndex,
  flowMode,
  faultEval,
  isSimulating,
  onSelectNode,
  onKeyNav,
  registerNodeRef
}: FlowCanvasProps) {
  const isSixStage = stages.length === 6;
  const nodeWidth = isSixStage ? 176 : 184;
  const nodeHeight = 112;
  const nodeGap = isSixStage ? 46 : 64;
  const startX = 16;
  const nodeY = 42;
  const svgWidth = startX * 2 + stages.length * nodeWidth + (stages.length - 1) * nodeGap;
  const svgHeight = 198;

  return (
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
            onSelect={onSelectNode}
            onKeyNav={onKeyNav}
            registerNodeRef={registerNodeRef}
          />
        ))}
      </svg>
    </div>
  );
});
