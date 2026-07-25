import React, { useState } from "react";
import { Clock3, Trash2 } from "lucide-react";

export function SearchHistoryMenu({ history, onSelect, onClear }) {
  const [open, setOpen] = useState(false);
  const hasHistory = history.length > 0;

  function handleSelect(entry) {
    onSelect(entry);
    setOpen(false);
  }

  return (
    <div className="history-menu">
      <button
        className="history-trigger"
        type="button"
        onClick={() => setOpen((value) => !value)}
        disabled={!hasHistory}
        aria-expanded={open}
      >
        <Clock3 size={16} />
        <span>History {history.length}</span>
      </button>

      {open && hasHistory && (
        <div className="history-popover">
          <div className="history-head">
            <strong>Recent checks</strong>
            <button type="button" onClick={onClear} aria-label="Clear history">
              <Trash2 size={14} />
            </button>
          </div>
          <div className="history-list">
            {history.map((entry) => (
              <button className="history-item" type="button" key={entry.id} onClick={() => handleSelect(entry)}>
                <span>
                  <strong>{entry.label}</strong>
                  <small>{formatTime(entry.createdAt)}</small>
                </span>
                <em className={entry.result.tier_level}>{entry.result.score}</em>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function formatTime(value) {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(new Date(value));
}
