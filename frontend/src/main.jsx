import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { AnalyzerForm } from "./components/AnalyzerForm";
import { AppHeader } from "./components/AppHeader";
import { HistoryPanel } from "./components/HistoryPanel";
import { ResultPanel } from "./components/ResultPanel";
import { Toast } from "./components/Toast";
import { API_URL, HISTORY_URL } from "./config/api";
import { ThemeProvider } from "./context/ThemeProvider";
import "./styles.css";

function App() {
  const [text, setText] = useState("");
  const [linkUrl, setLinkUrl] = useState("");
  const [files, setFiles] = useState([]);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [searchHistory, setSearchHistory] = useState([]);

  const hasInput = useMemo(
    () => text.trim() || linkUrl.trim() || files.length,
    [text, linkUrl, files],
  );

  useEffect(() => {
    if (!loading) {
      setProgress(0);
      return undefined;
    }

    setProgress(8);
    const intervalId = window.setInterval(() => {
      setProgress((currentProgress) => {
        if (currentProgress >= 92) return currentProgress;
        return Math.min(92, currentProgress + Math.ceil((94 - currentProgress) / 8));
      });
    }, 360);

    return () => window.clearInterval(intervalId);
  }, [loading]);

  useEffect(() => {
    loadHistory();
  }, []);

  async function loadHistory() {
    try {
      const response = await fetch(HISTORY_URL);
      if (!response.ok) throw new Error(`History returned HTTP ${response.status}`);
      setSearchHistory(await response.json());
    } catch {
      // History is helpful but not required for running a new analysis.
    }
  }

  async function analyze(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);

    const body = new FormData();
    body.append("text", text);
    body.append("job_url", linkUrl);
    body.append("recruiter_url", "");
    body.append("company_url", "");
    files.forEach((file) => body.append("files", file));

    try {
      const response = await fetch(API_URL, { method: "POST", body });
      if (!response.ok) {
        let message = `Analyzer returned HTTP ${response.status}`;
        try {
          const errorPayload = await response.json();
          if (errorPayload.detail) message = errorPayload.detail;
        } catch {
          // Keep the HTTP status fallback when the server does not return JSON.
        }
        throw new Error(message);
      }
      const analysisResult = await response.json();
      setResult(analysisResult);
      await loadHistory();
      clearInputs();
    } catch (err) {
      setError(err.message || "Analysis failed");
      clearInputs();
    } finally {
      setLoading(false);
    }
  }

  function clearInputs() {
    setText("");
    setLinkUrl("");
    setFiles([]);
  }

  async function selectHistory(entry) {
    let selectedEntry = entry;
    try {
      const response = await fetch(`${HISTORY_URL}/${entry.id}`);
      if (response.ok) selectedEntry = await response.json();
    } catch {
      // Fall back to the list item payload if the detail fetch fails.
    }
    setText(selectedEntry.input.text);
    setLinkUrl(selectedEntry.input.linkUrl || selectedEntry.input.jobUrl || selectedEntry.input.companyUrl || selectedEntry.input.recruiterUrl || "");
    setFiles([]);
    setResult(selectedEntry.result);
    setError("");
  }

  async function clearHistory() {
    try {
      await fetch(HISTORY_URL, { method: "DELETE" });
    } finally {
      setSearchHistory([]);
    }
  }

  return (
    <main className="shell">
      <AppHeader />
      <Toast message={error} onDismiss={() => setError("")} />

      <section className="workspace">
        <section className="left-stack">
          <AnalyzerForm
            text={text}
            setText={setText}
            linkUrl={linkUrl}
            setLinkUrl={setLinkUrl}
            files={files}
            setFiles={setFiles}
            hasInput={hasInput}
            loading={loading}
            progress={progress}
            onAnalyze={analyze}
          />
          <HistoryPanel history={searchHistory} onSelect={selectHistory} onClear={clearHistory} />
        </section>

        <ResultPanel result={result} loading={loading} progress={progress} />
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")).render(
  <ThemeProvider>
    <App />
  </ThemeProvider>,
);
