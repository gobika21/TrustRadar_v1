import React from "react";
import { Activity, AlertTriangle, CheckCircle2, ExternalLink, Globe, Loader2, Radar, ShieldCheck, Sparkles, Terminal } from "lucide-react";
import { severityLabel, tierClass } from "../utils/risk";

const terminalSteps = [
  { at: 8, command: "intake.read()", detail: "Reading submitted job evidence" },
  { at: 24, command: "patterns.scan()", detail: "Checking scam language and recruiter signals" },
  { at: 44, command: "links.verify()", detail: "Resolving URLs, DNS, and domain records" },
  { at: 66, command: "web.review()", detail: "Searching public complaint and fake-job signals" },
  { at: 84, command: "report.compose()", detail: "Preparing recommendation and evidence summary" },
];

export function ResultPanel({ result, loading, progress = 0 }) {
  if (loading) return <LoadingPanel progress={progress} />;
  if (!result) return <EmptyPanel />;

  const redFlags = getRedFlags(result);
  const trustReasons = getTrustReasons(result);
  const recommendation = result.recommendation || fallbackRecommendation(result);

  return (
    <aside className="result-panel verdict-panel">
      <section className={`verdict-hero ${tierClass(result.tier_level)}`}>
        <div>
          <p className="eyebrow">Recommendation</p>
          <h2>{recommendation.label}</h2>
          <p>{recommendation.detail}</p>
        </div>
        <div className="score-orbit">
          <strong>{result.score}</strong>
          <span>/100</span>
        </div>
      </section>

      <section className="insight-grid">
        <VerdictList
          title={redFlags.length ? "Signals to investigate" : "No major warning signals"}
          items={redFlags.length ? redFlags : ["The message does not match common scam-language patterns.", "Live checks did not return a strong public warning signal."]}
          tone={redFlags.length ? "danger" : "safe"}
        />
        <VerdictList
          title="Trust signals"
          items={trustReasons}
          tone="safe"
        />
      </section>

      <AgentWorkflow steps={result.agent_workflow || []} usage={result.usage} />
      <LiveVerification evidence={result.live_evidence} />
    </aside>
  );
}

function EmptyPanel() {
  return (
    <aside className="result-panel intro-panel">
      <div className="intro-icon"><Radar size={34} /></div>
      <h2>Know before you apply.</h2>
      <p>
        Paste a job post, recruiter message, or link. TrustRadar checks scam patterns,
        employer signals, domains, and public web results, then gives a clear recommendation.
      </p>
      <div className="trust-cards">
        <span><ShieldCheck size={16} /> Scam patterns</span>
        <span><Globe size={16} /> Employer proof</span>
        <span><Sparkles size={16} /> Apply guidance</span>
      </div>
    </aside>
  );
}

function LoadingPanel({ progress }) {
  const activeIndex = terminalSteps.reduce((latestIndex, step, index) => (progress >= step.at ? index : latestIndex), -1);
  const visibleSteps = terminalSteps.slice(0, Math.max(2, activeIndex + 2));

  return (
    <aside className="result-panel loading-panel">
      <section className="terminal-card">
        <div className="terminal-topbar">
          <span />
          <span />
          <span />
          <strong><Terminal size={15} /> TrustRadar agent</strong>
        </div>

        <div className="terminal-body">
          <p className="eyebrow">Review in progress</p>
          <h2>Checking the posting</h2>
          <p className="terminal-copy">The agent is reading the evidence, validating live signals, and building a recommendation.</p>

          <div className="terminal-progress" aria-label={`Analysis ${progress}% complete`}>
            <span style={{ width: `${progress}%` }} />
            <strong>{progress}%</strong>
          </div>

          <div className="terminal-lines">
            {visibleSteps.map((step, index) => {
              const isDone = progress >= terminalSteps[index + 1]?.at;
              const isActive = index === activeIndex || (!isDone && index === visibleSteps.length - 1);
              return (
                <div className={isActive ? "terminal-line active" : "terminal-line"} key={step.command}>
                  <span className="terminal-prompt">$</span>
                  <code>{step.command}</code>
                  <small>{isDone ? "done" : isActive ? "running" : "queued"}</small>
                  <p>{step.detail}</p>
                </div>
              );
            })}
            <div className="terminal-line cursor-line">
              <span className="terminal-prompt">$</span>
              <code>await result</code>
              <Loader2 className="spin" size={13} />
            </div>
          </div>
        </div>
      </section>
    </aside>
  );
}

function VerdictList({ title, items, tone }) {
  return (
    <section className={`verdict-list ${tone}`}>
      <h3>{tone === "danger" ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />} {title}</h3>
      <ul>
        {items.slice(0, 4).map((item) => <li key={item}>{item}</li>)}
      </ul>
    </section>
  );
}

function AgentWorkflow({ steps, usage }) {
  if (!steps.length && !usage) return null;
  const usageItems = usage ? [
    ["URL fetches", usage.url_fetches],
    ["DNS checks", usage.dns_lookups],
    ["Domain checks", usage.rdap_lookups],
    ["Web searches", usage.web_searches],
  ] : [];

  return (
    <section className="agent-workflow">
      <div className="workflow-heading">
        <h3><Activity size={16} /> Agent workflow</h3>
        {usage ? <span>{usageItems.reduce((sum, [, value]) => sum + value, 0)} live calls</span> : null}
      </div>
      <div className="workflow-list">
        {steps.slice(0, 5).map((item) => (
          <article className="workflow-step" key={item.step}>
            <CheckCircle2 size={15} />
            <div>
              <strong>{item.step}</strong>
              <p>{item.detail}</p>
            </div>
          </article>
        ))}
      </div>
      {usageItems.length ? (
        <div className="usage-grid">
          {usageItems.map(([label, value]) => (
            <span key={label}><strong>{value}</strong>{label}</span>
          ))}
        </div>
      ) : null}
    </section>
  );
}

function LiveVerification({ evidence }) {
  const reviewedEvidence = evidence || [];

  return (
    <section className="report-section compact-live">
      <h3>Evidence reviewed</h3>
      <div className="evidence-list">
        {reviewedEvidence.length ? reviewedEvidence.map((item, index) => (
          <article className="evidence" key={`${item.label}-${index}`}>
            <Globe size={16} />
            <div>
              <div className="evidence-title">
                <strong>{item.label}</strong>
                <span className={item.severity}>{severityLabel(item.severity)}</span>
              </div>
              <p>{item.detail}</p>
              {item.links?.length ? (
                <div className="evidence-links">
                  {item.links.slice(0, 3).map((link) => (
                    <a href={link.url} target="_blank" rel="noreferrer" key={`${item.label}-${link.url}`}>
                      {link.label} <ExternalLink size={12} />
                    </a>
                  ))}
                </div>
              ) : null}
            </div>
          </article>
        )) : (
          <article className="evidence">
            <Globe size={16} />
            <div>
              <div className="evidence-title">
                <strong>No live evidence found</strong>
                <span className="medium">Review</span>
              </div>
              <p>Paste a public job link or company site if you want TrustRadar to verify domains and web signals.</p>
            </div>
          </article>
        )}
      </div>
    </section>
  );
}

function fallbackRecommendation(result) {
  if (["critical", "high"].includes(result.tier_level)) {
    return {
      label: "Do not engage yet",
      detail: result.summary,
    };
  }
  if (result.tier_level === "medium") {
    return {
      label: "Apply with caution",
      detail: result.summary,
    };
  }
  return {
    label: "Likely safe to apply",
    detail: "No strong scam indicators were found. Confirm the employer identity before sharing personal information.",
  };
}

function getRedFlags(result) {
  const patternFlags = (result.pattern_findings || [])
    .filter((item) => ["critical", "high", "medium"].includes(item.severity))
    .map((item) => item.label);
  const evidenceFlags = (result.live_evidence || [])
    .filter((item) => ["critical", "high", "medium"].includes(item.severity))
    .map((item) => `${item.label}: ${summarizeEvidence(item.detail)}`);
  return [...patternFlags, ...evidenceFlags].slice(0, 4);
}

function getTrustReasons(result) {
  const reasons = (result.live_evidence || [])
    .filter((item) => item.severity === "info")
    .map((item) => `${item.label}: ${summarizeEvidence(item.detail)}`);
  if (!(result.pattern_findings || []).length) reasons.unshift("The message does not match common scam-language patterns.");
  return reasons.length ? reasons.slice(0, 4) : ["The evidence was reviewed, but it does not provide enough positive signals to classify the posting as low risk."];
}

function summarizeEvidence(detail) {
  return detail
    .replace(/\s*\([^)]{45,}\)/g, "")
    .replace(/\s*\|\s*/g, " · ")
    .slice(0, 180);
}
