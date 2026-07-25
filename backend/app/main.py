from __future__ import annotations

from time import perf_counter
from typing import Any

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.analysis import (
    assert_job_url_accessible,
    build_agent_workflow,
    build_recommendation,
    evidence_to_payload,
)
from app.metrics import METRICS, build_usage_snapshot, metrics_payload
from app.models import Evidence
from app.scoring import evidence_score, pattern_check, score_to_tier
from app.text_utils import extract_emails, extract_urls
from app.verification import build_search_query, rdap_lookup, search_result_severity, verify_live


app = FastAPI(title="TrustRadar API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/metrics")
async def metrics() -> dict[str, Any]:
    return metrics_payload()


@app.post("/api/analyze")
async def analyze(
    text: str = Form(""),
    job_url: str = Form(""),
    recruiter_url: str = Form(""),
    company_url: str = Form(""),
    files: list[UploadFile] = File(default=[]),
) -> dict[str, Any]:
    started_at = perf_counter()
    METRICS["analyze_requests"] += 1
    usage_before = METRICS.copy()
    submitted_urls = [url.strip() for url in [job_url, recruiter_url, company_url] if url.strip()]
    uploaded_files = [
        {
            "name": file.filename,
            "content_type": file.content_type,
            "note": "Upload accepted. OCR is not enabled in this local v1, so include screenshot text when possible.",
        }
        for file in files
        if file.filename
    ]
    METRICS["uploaded_files"] += len(uploaded_files)

    try:
        pattern_score, findings = pattern_check(text)
        live_evidence = await verify_live(text, submitted_urls)
        assert_job_url_accessible(job_url, live_evidence)
        total_score = min(100, pattern_score + evidence_score(live_evidence))
        tier, tier_level = score_to_tier(total_score)
    except Exception:
        METRICS["analysis_errors"] += 1
        raise
    finally:
        METRICS["total_analysis_ms"] += (perf_counter() - started_at) * 1000

    summary = "No strong scam indicators were found in the available evidence. Verify the employer before sharing personal information."
    if tier_level in {"critical", "high"}:
        summary = "Multiple risk signals need independent verification before you reply, pay, or share identity documents."
    elif tier_level == "medium":
        summary = "Some signals require follow-up before you trust the posting or recruiter."

    return {
        "tier": tier,
        "tier_level": tier_level,
        "score": total_score,
        "summary": summary,
        "recommendation": build_recommendation(tier_level),
        "agent_workflow": build_agent_workflow(text, submitted_urls, findings, live_evidence),
        "usage": build_usage_snapshot(usage_before),
        "pattern_findings": findings,
        "live_evidence": [evidence_to_payload(item) for item in live_evidence],
        "uploaded_files": uploaded_files,
        "extracted": {
            "urls": extract_urls(text) + submitted_urls,
            "emails": extract_emails(text),
        },
        "recommendations": [
            "Do not pay fees or deposits for interviews, visas, training, or equipment.",
            "Confirm the recruiter through the company website or an official company email domain.",
            "Search the company and recruiter name with terms such as scam, fraud, complaint, and fake job.",
            "Do not share passport, Emirates ID, bank details, or OTPs until the employer is verified.",
        ],
    }
