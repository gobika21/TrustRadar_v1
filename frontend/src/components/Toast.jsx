import React from "react";
import { AlertTriangle, X } from "lucide-react";

export function Toast({ message, onDismiss }) {
  if (!message) return null;

  return (
    <div className="error-modal-backdrop" role="presentation">
      <section className="error-modal" role="alertdialog" aria-modal="true" aria-labelledby="error-modal-title">
        <button className="error-modal-close" type="button" onClick={onDismiss} aria-label="Close error">
          <X size={16} />
        </button>
        <div className="error-modal-icon">
          <AlertTriangle size={22} />
        </div>
        <div>
          <h2 id="error-modal-title">Unable to review this link</h2>
          <p>{message}</p>
        </div>
        <button className="error-modal-action" type="button" onClick={onDismiss}>
          Try another input
        </button>
      </section>
    </div>
  );
}
