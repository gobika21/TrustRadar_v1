import React from "react";
import { AlertTriangle, X } from "lucide-react";

export function Toast({ error, message, onDismiss }) {
  const normalizedError = normalizeError(error || message);
  if (!normalizedError.message) return null;

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
          <h2 id="error-modal-title">{normalizedError.title}</h2>
          <p>{normalizedError.message}</p>
        </div>
        <button className="error-modal-action" type="button" onClick={onDismiss}>
          {normalizedError.action}
        </button>
      </section>
    </div>
  );
}

function normalizeError(error) {
  if (!error) return { title: "", message: "", action: "Close" };
  if (typeof error === "string") {
    return {
      title: "Unable to review this input",
      message: error,
      action: "Try again",
    };
  }
  return {
    title: error.title || "Unable to review this input",
    message: error.message || "",
    action: error.action || "Try again",
  };
}
