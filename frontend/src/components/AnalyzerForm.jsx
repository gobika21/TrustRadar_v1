import React from "react";
import {
  Info,
  Link2,
  Loader2,
  Radar,
  Upload,
} from "lucide-react";

export function AnalyzerForm({
  text,
  setText,
  linkUrl,
  setLinkUrl,
  files,
  setFiles,
  hasInput,
  loading,
  progress,
  onAnalyze,
}) {
  return (
    <form className="input-panel" onSubmit={onAnalyze}>
      <div className="panel-heading">
        <div>
          <h2>Review a job before you apply</h2>
        </div>
      </div>

      <label className="field large-field">
        <span>Paste the job post or recruiter message</span>
        <textarea
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder="Add the job description, recruiter email, DM, or screenshot text."
        />
      </label>

      <div className="evidence-row">
        <label className="field">
          <span><Link2 size={15} /> Job, recruiter, or company link</span>
          <input value={linkUrl} onChange={(event) => setLinkUrl(event.target.value)} placeholder="Paste any relevant URL" />
        </label>

        <label className="upload-box">
          <Upload size={20} />
          <span>{files.length ? `${files.length} file attached` : "Attach screenshots or files"}</span>
          <input
            type="file"
            multiple
            accept="image/*,.pdf,.txt"
            onChange={(event) => setFiles(Array.from(event.target.files || []))}
          />
        </label>
      </div>

      <p className="privacy-note">
        <Info size={14} />
        Avoid uploading passports, IDs, bank details, OTPs, or private offer documents.
      </p>

      <button className={`analyze-button${loading ? " is-loading" : ""}`} type="submit" disabled={!hasInput || loading}>
        {loading ? (
          <>
            <Loader2 className="spin" size={18} />
            <span>Analyzing</span>
            <strong>{progress}%</strong>
          </>
        ) : (
          <>
            <Radar size={17} />
            <span>Analyze job</span>
          </>
        )}
      </button>
    </form>
  );
}
