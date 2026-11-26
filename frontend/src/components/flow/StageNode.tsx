import { memo, type KeyboardEvent } from "react";
import type { FlowStageId } from "../../lib/securityLab";
import type { StageDescriptor } from "./stageDescriptors";

export interface SvgStageNodeProps {
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

export const SvgStageNode = memo(function SvgStageNode({
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
