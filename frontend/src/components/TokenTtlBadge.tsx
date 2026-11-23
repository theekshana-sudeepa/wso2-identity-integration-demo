import { memo, useEffect, useState } from "react";
import { Clock } from "lucide-react";

interface TokenTtlBadgeProps {
  readonly expiresAtSec: number | null;
  readonly compact?: boolean;
}

function formatTtl(remainingSec: number): string {
  if (remainingSec <= 0) return "EXPIRED";
  if (remainingSec < 120) return `${remainingSec}s TTL`;
  const mins = Math.floor(remainingSec / 60);
  if (mins >= 60) {
    const hrs = Math.floor(mins / 60);
    const remMins = mins % 60;
    return `${hrs}h ${remMins}m left`;
  }
  return `${mins}m ${remainingSec % 60}s left`;
}

export const TokenTtlBadge = memo(function TokenTtlBadge({
  expiresAtSec,
  compact = false
}: TokenTtlBadgeProps) {
  const [nowSec, setNowSec] = useState<number>(() => Math.floor(Date.now() / 1000));

  useEffect(() => {
    if (expiresAtSec === null) return undefined;
    const tick = window.setInterval(() => {
      setNowSec(Math.floor(Date.now() / 1000));
    }, 1000);
    return () => window.clearInterval(tick);
  }, [expiresAtSec]);

  if (expiresAtSec === null) {
    return <span className="ttl-badge ttl-neutral">—</span>;
  }

  const remainingSec = expiresAtSec - nowSec;
  const toneClass =
    remainingSec <= 0
      ? "ttl-expired"
      : remainingSec <= 15
        ? "ttl-warn"
        : "ttl-ok";

  return (
    <span className={`ttl-badge ${toneClass} ${compact ? "ttl-compact" : ""}`}>
      <Clock size={compact ? 11 : 12} />
      <span>{formatTtl(remainingSec)}</span>
    </span>
  );
});
