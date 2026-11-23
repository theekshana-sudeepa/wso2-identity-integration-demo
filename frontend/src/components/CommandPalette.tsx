import { memo, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { Search, X } from "lucide-react";

export interface CommandPaletteAction {
  readonly id: string;
  readonly group: "Navigation" | "Attack Lab" | "Mode & Personas" | "Developer Tools";
  readonly label: string;
  readonly hint: string;
  readonly keywords: string;
  readonly run: () => void;
}

interface CommandPaletteProps {
  readonly isOpen: boolean;
  readonly actions: readonly CommandPaletteAction[];
  readonly onClose: () => void;
}

export const CommandPalette = memo(function CommandPalette({
  isOpen,
  actions,
  onClose
}: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    setQuery("");
    setSelectedIndex(0);
    const frame = window.requestAnimationFrame(() => {
      inputRef.current?.focus();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [isOpen]);

  const filtered = useMemo(() => {
    const trimmed = query.trim().toLowerCase();
    if (!trimmed) return actions;
    return actions.filter(
      (action) =>
        action.label.toLowerCase().includes(trimmed) ||
        action.hint.toLowerCase().includes(trimmed) ||
        action.group.toLowerCase().includes(trimmed) ||
        action.keywords.toLowerCase().includes(trimmed)
    );
  }, [actions, query]);

  const safeIndex = filtered.length > 0 ? Math.min(selectedIndex, filtered.length - 1) : 0;

  if (!isOpen) return null;

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (filtered.length > 0) {
        setSelectedIndex((prev) => (prev + 1) % filtered.length);
      }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (filtered.length > 0) {
        setSelectedIndex((prev) => (prev - 1 + filtered.length) % filtered.length);
      }
    } else if (e.key === "Enter") {
      e.preventDefault();
      const target = filtered[safeIndex];
      if (target) {
        target.run();
        onClose();
      }
    }
  };

  return (
    <div
      className="palette-backdrop"
      role="presentation"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="palette-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Command Palette"
        onKeyDown={handleKeyDown}
      >
        <div className="palette-input-row">
          <Search size={16} className="palette-search-icon" />
          <input
            ref={inputRef}
            type="text"
            className="palette-input"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            placeholder="Jump to stage, inject Attack Lab fault, toggle AI Agent mode, copy curl..."
            aria-label="Filter console commands"
          />
          <button
            type="button"
            className="palette-close"
            onClick={onClose}
            aria-label="Close command palette"
          >
            <X size={15} />
          </button>
        </div>

        <div className="palette-list" role="listbox" aria-label="Console commands">
          {filtered.length === 0 ? (
            <div className="palette-empty">No matching commands for &quot;{query}&quot;</div>
          ) : (
            filtered.map((action, idx) => {
              const active = idx === safeIndex;
              return (
                <button
                  key={action.id}
                  type="button"
                  role="option"
                  aria-selected={active}
                  className={`palette-item ${active ? "palette-item-active" : ""}`}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  onClick={() => {
                    action.run();
                    onClose();
                  }}
                >
                  <div className="palette-item-left">
                    <span className="palette-group-tag">{action.group}</span>
                    <span className="palette-item-label">{action.label}</span>
                  </div>
                  <span className="palette-item-hint">{action.hint}</span>
                </button>
              );
            })
          )}
        </div>

        <div className="palette-footer">
          <span>↑↓ Navigate</span>
          <span>↵ Execute</span>
          <span>ESC Close</span>
        </div>
      </div>
    </div>
  );
});
