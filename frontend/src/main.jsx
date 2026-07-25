import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { AnalyzerForm } from "./components/AnalyzerForm";
import { AppHeader } from "./components/AppHeader";
import { HistoryPanel } from "./components/HistoryPanel";
import { ResultPanel } from "./components/ResultPanel";
import { Toast } from "./components/Toast";
import { API_URL } from "./config/api";
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
      setSearchHistory((currentHistory) => [
        buildHistoryEntry({ text, linkUrl, files }, analysisResult),
        ...currentHistory,
      ].slice(0, 8));
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

  function selectHistory(entry) {
    setText(entry.input.text);
    setLinkUrl(entry.input.linkUrl || entry.input.jobUrl || entry.input.companyUrl || entry.input.recruiterUrl || "");
    setFiles(entry.input.files);
    setResult(entry.result);
    setError("");
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
          <HistoryPanel history={searchHistory} onSelect={selectHistory} onClear={() => setSearchHistory([])} />
        </section>

        <ResultPanel result={result} loading={loading} progress={progress} />
      </section>
    </main>
  );
}

function buildHistoryEntry(input, result) {
  return {
    id: createHistoryId(),
    createdAt: new Date().toISOString(),
    label: getHistoryLabel(input),
    input,
    result,
  };
}

function createHistoryId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function getHistoryLabel({ text, linkUrl, files }) {
  if (linkUrl) {
    try {
      return new URL(linkUrl).hostname.replace(/^www\./, "");
    } catch {
      return trimLabel(linkUrl);
    }
  }

  if (text.trim()) return trimLabel(text.trim());
  if (files.length) return `${files.length} uploaded file${files.length > 1 ? "s" : ""}`;
  return "Untitled check";
}

function trimLabel(value) {
  return value.length > 44 ? `${value.slice(0, 44)}...` : value;
}

createRoot(document.getElementById("root")).render(
  <ThemeProvider>
    <App />
  </ThemeProvider>,
);
