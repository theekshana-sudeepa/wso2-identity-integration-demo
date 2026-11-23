import { memo, useMemo, useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";

interface JsonHighlighterProps {
  readonly data: unknown;
  readonly emptyMessage?: string;
  readonly maxHeight?: number;
  readonly copyLabel?: string;
}

const JSON_TOKEN_REGEX =
  /("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(?:\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g;

function highlightJsonLine(line: string, lineIndex: number): ReactNode[] {
  const nodes: ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  JSON_TOKEN_REGEX.lastIndex = 0;
  while ((match = JSON_TOKEN_REGEX.exec(line)) !== null) {
    const token = match[0];
    if (match.index > lastIndex) {
      nodes.push(line.slice(lastIndex, match.index));
    }

    let className = "json-number";
    if (token.startsWith('"')) {
      className = token.endsWith(":") ? "json-key" : "json-string";
    } else if (token === "true" || token === "false") {
      className = "json-boolean";
    } else if (token === "null") {
      className = "json-null";
    }

    nodes.push(
      <span key={`${lineIndex}-${match.index}`} className={className}>
        {token}
      </span>
    );
    lastIndex = match.index + token.length;
  }

  if (lastIndex < line.length) {
    nodes.push(line.slice(lastIndex));
  }

  return nodes;
}

export const JsonHighlighter = memo(function JsonHighlighter({
  data,
  emptyMessage = "// Waiting for live protocol payload...",
  maxHeight = 320,
  copyLabel = "Copy JSON"
}: JsonHighlighterProps) {
  const [copied, setCopied] = useState(false);

  const formatted = useMemo(
    () => (data !== null && data !== undefined ? JSON.stringify(data, null, 2) : null),
    [data]
  );

  const highlightedLines = useMemo(() => {
    if (!formatted) return null;
    return formatted.split("\n").map((line, index) => (
      <span key={index} className="code-line">
        {highlightJsonLine(line, index)}
        {"\n"}
      </span>
    ));
  }, [formatted]);

  async function handleCopy() {
    if (!formatted) return;
    try {
      await navigator.clipboard.writeText(formatted);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="code-frame">
      {formatted && (
        <button
          type="button"
          className="code-copy-btn"
          onClick={handleCopy}
          aria-label={copyLabel}
          title={copyLabel}
        >
          {copied ? <Check size={13} /> : <Copy size={13} />}
          <span>{copied ? "Copied" : "Copy"}</span>
        </button>
      )}
      <pre className="code-block" style={{ maxHeight: `${maxHeight}px` }}>
        {highlightedLines ?? <span className="code-muted">{emptyMessage}</span>}
      </pre>
    </div>
  );
});
