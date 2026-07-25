from __future__ import annotations

import asyncio
import datetime as dt
import re
import socket
from dataclasses import dataclass
from html import unescape
from time import perf_counter
from typing import Any
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(title="TrustRadar API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

METRICS = {
    "analyze_requests": 0,
    "url_fetches": 0,
    "dns_lookups": 0,
    "rdap_lookups": 0,
    "web_searches": 0,
    "uploaded_files": 0,
    "analysis_errors": 0,
    "total_analysis_ms": 0.0,
}


SCAM_PATTERNS = [
    {
        "id": "upfront_fee",
        "label": "Upfront fee request",
        "severity": "critical",
        "score": 30,
        "regex": r"\b(upfront|advance|registration|processing|training|equipment|visa|security)\s+(fee|payment|charge|deposit)\b|\bpay\b.{0,40}\b(before|prior to|to start|to proceed)\b",
        "explain": "Legitimate employers rarely require candidates to pay before hiring.",
    },
    {
        "id": "urgency",
        "label": "High-pressure urgency",
        "severity": "high",
        "score": 14,
        "regex": r"\b(urgent|immediate joining|act fast|limited slots|final notice|today only|reply now|asap)\b",
        "explain": "Scams often pressure candidates into skipping normal verification.",
    },
    {
        "id": "messaging_app",
        "label": "Off-platform interview channel",
        "severity": "medium",
        "score": 10,
        "regex": r"\b(whatsapp|telegram|signal)\b.{0,60}\b(interview|hr|recruiter|offer|shortlisted)\b|\b(interview|shortlisted)\b.{0,60}\b(whatsapp|telegram|signal)\b",
        "explain": "Moving directly to messaging apps can make impersonation harder to trace.",
    },
    {
        "id": "sensitive_info",
        "label": "Early sensitive information request",
        "severity": "high",
        "score": 16,
        "regex": r"\b(passport|emirates id|national id|bank account|iban|credit card|otp|one-time password)\b",
        "explain": "Requests for identity or banking details before verified hiring are risky.",
    },
    {
        "id": "too_good",
        "label": "Unusually generous offer language",
        "severity": "medium",
        "score": 10,
        "regex": r"\b(no experience required|work from home)\b.{0,80}\b(high salary|huge salary|guaranteed income|weekly pay)\b|\b(high salary|huge salary|guaranteed income|weekly pay)\b.{0,80}\b(no experience required|work from home)\b",
        "explain": "Overly broad, high-reward promises are common in fake postings.",
    },
    {
        "id": "generic_contact",
        "label": "Generic email contact",
        "severity": "medium",
        "score": 8,
        "regex": r"\b[\w.+-]+@(gmail|yahoo|outlook|hotmail|proton|icloud)\.(com|co|ae|in|net)\b",
        "explain": "Recruiting for established companies should usually use a company domain.",
    },
    {
        "id": "generic_signature",
        "label": "Generic recruiter signature",
        "severity": "medium",
        "score": 8,
        "regex": r"\b(regards|thanks|thank you),?\s*\n\s*(coordination team|recruitment team|hiring team|hr team)\b",
        "explain": "Legitimate interview invitations usually identify a recruiter, company, and role clearly.",
    },
    {
        "id": "website_instead_of_meeting_link",
        "label": "Website provided instead of meeting link",
        "severity": "high",
        "score": 18,
        "regex": r"\b(interview|discussion)\s+information\s+is\s+available\s+at\b",
        "explain": "A vague website link in place of a named recruiter or meeting link is a common fake-interview pattern.",
    },
]

KNOWN_ATS_DOMAINS = {
    "ashbyhq.com",
    "greenhouse.io",
    "lever.co",
    "myworkdayjobs.com",
    "workdayjobs.com",
}

CONTEXTUAL_PATTERNS = [
    {
        "id": "date_missing_year",
        "label": "Interview date missing year",
        "severity": "medium",
        "score": 8,
        "explain": "A formal interview invite should include a complete date, especially when the month/day may already be stale.",
    },
    {
        "id": "missing_role",
        "label": "No job role identified",
        "severity": "medium",
        "score": 10,
        "explain": "Interview messages that omit the job title or requisition are harder to verify and often appear in mass outreach.",
    },
]


@dataclass
class Evidence:
    label: str
    status: str
    detail: str
    source: str
    severity: str = "info"


def extract_urls(text: str) -> list[str]:
    urls = re.findall(r"https?://[^\s<>)\"']+", text)
    bare_domains = re.findall(
        r"(?<!@)\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|ae|sa|qa|kw|bh|om|co|io|ai|jobs)\b",
        text,
    )
    normalized = [url.rstrip(".,;") for url in urls]
    for domain in bare_domains:
        candidate = f"https://{domain.rstrip('.,;')}"
        if candidate not in normalized and not any(domain in url for url in normalized):
            normalized.append(candidate)
    return normalized


def extract_emails(text: str) -> list[str]:
    return sorted(set(re.findall(r"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b", text)))


def domain_from_url(url: str) -> str | None:
    parsed = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")
    host = parsed.netloc.lower().split("@")[-1].split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host or None


def registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_part_suffixes = {"co.uk", "com.au", "co.in", "co.ae", "com.sa", "com.qa", "com.kw"}
    suffix = ".".join(parts[-2:])
    if suffix in two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_known_ats_domain(domain: str) -> bool:
    root = registered_domain(domain)
    return root in KNOWN_ATS_DOMAINS


def score_to_tier(score: int) -> tuple[str, str]:
    if score >= 70:
        return "Likely scam", "critical"
    if score >= 45:
        return "High risk", "high"
    if score >= 24:
        return "Needs verification", "medium"
    return "Lower risk", "low"


def pattern_check(text: str) -> tuple[int, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    score = 0
    for pattern in SCAM_PATTERNS:
        matches = re.findall(pattern["regex"], text, re.IGNORECASE | re.DOTALL)
        if matches:
            score += pattern["score"]
            findings.append(
                {
                    "id": pattern["id"],
                    "label": pattern["label"],
                    "severity": pattern["severity"],
                    "score": pattern["score"],
                    "explanation": pattern["explain"],
                    "matches": len(matches),
                }
            )
    contextual_score, contextual_findings = contextual_check(text)
    return score + contextual_score, findings + contextual_findings


def contextual_check(text: str) -> tuple[int, list[dict[str, Any]]]:
    normalized = re.sub(r"\s+", " ", text.strip())
    lowered = normalized.lower()
    findings: list[dict[str, Any]] = []
    score = 0

    if re.search(r"\bdate:\s*\d{1,2}\s+[a-zA-Z]{3,9}\b", text, re.IGNORECASE) and not re.search(
        r"\bdate:\s*\d{1,2}\s+[a-zA-Z]{3,9}\s+\d{4}\b",
        text,
        re.IGNORECASE,
    ):
        pattern = CONTEXTUAL_PATTERNS[0]
        score += pattern["score"]
        findings.append(
            {
                "id": pattern["id"],
                "label": pattern["label"],
                "severity": pattern["severity"],
                "score": pattern["score"],
                "explanation": pattern["explain"],
                "matches": 1,
            }
        )

    mentions_interview = any(term in lowered for term in ["interview", "discussion", "shortlisted"])
    role_terms = [
        "position",
        "role",
        "job title",
        "vacancy",
        "requisition",
        "developer",
        "engineer",
        "analyst",
        "manager",
        "designer",
        "accountant",
        "assistant",
        "coordinator",
    ]
    if mentions_interview and not any(term in lowered for term in role_terms):
        pattern = CONTEXTUAL_PATTERNS[1]
        score += pattern["score"]
        findings.append(
            {
                "id": pattern["id"],
                "label": pattern["label"],
                "severity": pattern["severity"],
                "score": pattern["score"],
                "explanation": pattern["explain"],
                "matches": 1,
            }
        )

    return score, findings


async def resolve_dns(domain: str) -> Evidence:
    METRICS["dns_lookups"] += 1
    try:
        addresses = await asyncio.to_thread(socket.getaddrinfo, domain, None)
        ips = sorted({item[4][0] for item in addresses})[:4]
        return Evidence("DNS resolution", "found", f"{domain} resolves to {', '.join(ips)}", domain, "info")
    except socket.gaierror:
        return Evidence("DNS resolution", "not_found", f"{domain} does not resolve in DNS.", domain, "high")


async def fetch_url(client: httpx.AsyncClient, url: str) -> Evidence:
    METRICS["url_fetches"] += 1
    try:
        response = await client.get(url, follow_redirects=True)
        title = ""
        if "text/html" in response.headers.get("content-type", ""):
            soup = BeautifulSoup(response.text[:100_000], "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else ""
        final_domain = domain_from_url(str(response.url)) or "unknown domain"
        detail = f"HTTP {response.status_code} from {final_domain}"
        if title:
            detail += f"; title: {title[:120]}"
        severity = "info" if response.status_code < 400 else "medium"
        title_lower = title.lower()
        if any(term in title_lower for term in ["access denied", "just a moment", "captcha", "verify you are human", "blocked"]):
            severity = "medium"
            return Evidence("URL reachability", "blocked", f"{detail}; page appears blocked or requires browser verification", url, severity)
        if any(term in title_lower for term in ["gulf jobs", "salary", "visa guide", "jobs 2026"]):
            severity = "medium"
            detail += "; page title looks like a generic jobs/visa-content site, not an interview page"
        return Evidence("URL reachability", "checked", detail, url, severity)
    except httpx.HTTPError as exc:
        return Evidence("URL reachability", "failed", f"Could not fetch URL: {exc.__class__.__name__}", url, "medium")


async def rdap_lookup(client: httpx.AsyncClient, domain: str) -> Evidence:
    METRICS["rdap_lookups"] += 1
    root = registered_domain(domain)
    if is_known_ats_domain(root):
        return Evidence(
            "ATS platform",
            "recognized",
            f"{root} is a recognized applicant-tracking platform; assess the employer/posting content separately.",
            root,
            "info",
        )
    suffix = root.rsplit(".", 1)[-1].lower()
    endpoints = [f"https://rdap.org/domain/{root}"]
    if suffix in {"com", "net"}:
        endpoints.append(f"https://rdap.verisign.com/{suffix}/v1/domain/{root.upper()}")
    try:
        data = None
        last_status = None
        for endpoint in endpoints:
            response = await client.get(endpoint)
            last_status = response.status_code
            if response.status_code >= 400:
                continue
            try:
                data = response.json()
                break
            except ValueError:
                continue
        if data is None:
            return Evidence("Domain registration", "not_found", f"No parseable RDAP record found for {root}; last HTTP status was {last_status}.", root, "high")
        events = data.get("events", [])
        registration_date = None
        for event in events:
            if event.get("eventAction") in {"registration", "registered"}:
                registration_date = event.get("eventDate")
                break
        if not registration_date:
            return Evidence("Domain registration", "checked", f"RDAP record exists for {root}, but no registration date was exposed.", root)
        created = dt.datetime.fromisoformat(registration_date.replace("Z", "+00:00"))
        age_days = (dt.datetime.now(dt.timezone.utc) - created).days
        severity = "high" if age_days < 90 else "medium" if age_days < 365 else "info"
        return Evidence(
            "Domain age",
            "checked",
            f"{root} appears about {age_days} days old; registered {created.date().isoformat()}.",
            root,
            severity,
        )
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return Evidence("Domain registration", "failed", f"RDAP lookup failed: {exc.__class__.__name__}", root, "medium")


def decode_ddg_href(href: str) -> str:
    parsed = urlparse(href)
    if parsed.netloc.endswith("duckduckgo.com") and parsed.path == "/l/":
        uddg = parse_qs(parsed.query).get("uddg", [""])[0]
        return unquote(uddg) if uddg else href
    return href


def domain_tokens(query: str) -> set[str]:
    lowered = query.lower()
    company_match = re.search(r"\b([a-z0-9][a-z0-9-]{2,})\s+company\s+recruitment\s+scam\b", lowered)
    query_tokens = {company_match.group(1).replace("-", "")} if company_match else set()
    host_match = re.search(r"\b([a-z0-9-]+\.[a-z]{2,})\b", lowered)
    if not host_match:
        return {token for token in query_tokens if len(token) >= 4}
    stem = host_match.group(1).split(".", 1)[0]
    tokens = {stem, *query_tokens}
    if stem.endswith("llc"):
        tokens.add(stem[:-3])
    if stem.startswith("al") and len(stem) > 4:
        tokens.add(stem[2:])
    if stem.startswith("al") and stem.endswith("llc") and len(stem) > 7:
        tokens.add(stem[2:-3])
    return {token for token in tokens if len(token) >= 4}


def search_result_severity(query: str, result_text: str) -> str:
    lowered = result_text.lower()
    negative_terms = [
        "job scam alert",
        "job scam",
        "scam using ai",
        "dangerous scam",
        "fake recruiting",
        "fake recruiter",
        "fake job",
        "fake company",
        "fraud",
        "phishing",
        "deception",
        "recruitment trap",
        "personal data theft",
        "data theft warning",
        "identity theft",
        "beware of",
        "are a scam",
    ]
    reputation_page_terms = ["scam or legit", "trustpilot", "scam-detector"]
    has_negative_signal = any(term in lowered for term in negative_terms)
    has_reputation_page = any(term in lowered for term in reputation_page_terms)
    has_target_signal = any(token in lowered for token in domain_tokens(query))
    if has_negative_signal and has_target_signal:
        return "high"
    if any(term in lowered for term in ["job scam alert", "job scam", "fake recruiting", "fake job offers", "personal data theft"]):
        return "medium"
    if has_reputation_page and has_target_signal:
        return "medium"
    return "info"


async def web_search(client: httpx.AsyncClient, query: str) -> Evidence:
    METRICS["web_searches"] += 1
    if not query.strip():
        return Evidence("Web search", "skipped", "No company or domain query was available.", "search")
    try:
        url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        response = await client.get(url, follow_redirects=True)
        if response.status_code >= 400:
            return Evidence("Web search", "failed", f"Search returned HTTP {response.status_code}.", query, "medium")
        soup = BeautifulSoup(response.text, "html.parser")
        results = []
        for anchor in soup.select(".result__a")[:3]:
            title = unescape(anchor.get_text(" ", strip=True))
            href = decode_ddg_href(anchor.get("href", ""))
            results.append(f"{title} ({href})")
        if results:
            detail = "Top results: " + " | ".join(results)
            return Evidence("Web search", "found", detail, query, search_result_severity(query, detail))
        return Evidence("Web search", "not_found", "No search results were parsed for this query.", query, "medium")
    except httpx.HTTPError as exc:
        return Evidence("Web search", "failed", f"Search failed: {exc.__class__.__name__}", query, "medium")


def build_search_query(text: str, urls: list[str], emails: list[str]) -> str:
    employer_from_ats = employer_slug_from_ats_url(urls)
    if employer_from_ats:
        return f"{employer_from_ats} company recruitment scam"
    domains = [domain_from_url(url) for url in urls]
    domains = [domain for domain in domains if domain and not is_known_ats_domain(domain)]
    email_domains = [email.split("@", 1)[1] for email in emails]
    candidates = domains + email_domains
    if candidates:
        return f"{registered_domain(candidates[0])} company recruitment scam"
    company_match = re.search(r"(?:company|employer|client|organization|organisation)[:\s-]+([A-Z][A-Za-z0-9 &.,-]{2,60})", text)
    if company_match:
        return f"{company_match.group(1).strip()} recruitment scam"
    words = re.findall(r"\b[A-Z][A-Za-z0-9&.-]{2,}\b", text)
    return " ".join(words[:4] + ["recruitment", "scam"]) if words else ""


def employer_slug_from_ats_url(urls: list[str]) -> str | None:
    for url in urls:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        path_parts = [part for part in parsed.path.split("/") if part]
        if host.endswith("jobs.lever.co") and path_parts:
            return path_parts[0].replace("-", " ")
        if host.endswith("boards.greenhouse.io"):
            company = parse_qs(parsed.query).get("for", [""])[0]
            if company:
                return company.replace("-", " ")
            if path_parts:
                return path_parts[0].replace("-", " ")
        if host.endswith("jobs.ashbyhq.com") and path_parts:
            return path_parts[0].replace("-", " ")
    return None


async def verify_live(text: str, submitted_urls: list[str]) -> list[Evidence]:
    urls = list(dict.fromkeys(submitted_urls + extract_urls(text)))
    emails = extract_emails(text)
    domains = sorted({domain_from_url(url) for url in urls if domain_from_url(url)})
    domains.extend(email.split("@", 1)[1].lower() for email in emails)
    domains = sorted({registered_domain(domain) for domain in domains})

    timeout = httpx.Timeout(8.0, connect=4.0)
    headers = {"User-Agent": "TrustRadar/0.1 (+https://local)"}
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        tasks = []
        for url in urls[:4]:
            tasks.append(fetch_url(client, url))
        for domain in domains[:4]:
            tasks.append(resolve_dns(domain))
            tasks.append(rdap_lookup(client, domain))
        tasks.append(web_search(client, build_search_query(text, urls, emails)))
        if not tasks:
            return [Evidence("Live verification", "skipped", "No URLs, domains, emails, or company name were found to verify.", "input", "medium")]
        return list(await asyncio.gather(*tasks))


def evidence_score(evidence: list[Evidence]) -> int:
    score = 0
    for item in evidence:
        if item.severity == "critical":
            score += 20
        elif item.severity == "high":
            score += 30 if item.label == "Web search" else 16
        elif item.severity == "medium":
            score += 24 if item.label == "URL reachability" else 8
    return score


def assert_job_url_accessible(job_url: str, evidence: list[Evidence]) -> None:
    if not job_url.strip():
        return

    normalized_job_url = job_url.strip()
    for item in evidence:
        if item.label != "URL reachability" or item.source != normalized_job_url:
            continue
        status_match = re.search(r"HTTP\s+(\d{3})", item.detail)
        status_code = int(status_match.group(1)) if status_match else None
        is_inaccessible_status = status_code is not None and status_code >= 400
        if item.status in {"failed", "blocked"} or is_inaccessible_status:
            raise HTTPException(
                status_code=422,
                detail=(
                    "TrustRadar could not access the job posting URL, so this link cannot be assessed reliably. "
                    "Open the page in your browser and paste the visible job description, or try a public posting URL."
                ),
            )
        return


def evidence_to_payload(item: Evidence) -> dict[str, Any]:
    return {
        **item.__dict__,
        "links": extract_evidence_links(item),
    }


def extract_evidence_links(item: Evidence) -> list[dict[str, str]]:
    links: list[dict[str, str]] = []
    if item.source.startswith(("http://", "https://")):
        links.append({"label": item.label, "url": item.source})
    if item.label == "Web search":
        for title, url in re.findall(r"([^|()]+?)\s*\((https?://[^)]+)\)", item.detail):
            links.append({"label": title.strip()[:90], "url": url.strip()})
    return links[:4]


def build_recommendation(tier_level: str) -> dict[str, str]:
    if tier_level in {"critical", "high"}:
        return {
            "label": "Do not engage yet",
            "tone": "danger",
            "detail": "Verify the employer through an official channel before replying, paying, or sharing documents.",
        }
    if tier_level == "medium":
        return {
            "label": "Apply with caution",
            "tone": "review",
            "detail": "There are signals that need follow-up. Confirm the company, recruiter, and role before continuing.",
        }
    return {
        "label": "Likely safe to apply",
        "tone": "safe",
        "detail": "No strong scam indicators were found, but still confirm the employer identity before sharing personal data.",
    }


def build_agent_workflow(
    text: str,
    submitted_urls: list[str],
    findings: list[dict[str, Any]],
    live_evidence: list[Evidence],
) -> list[dict[str, str]]:
    live_labels = {item.label for item in live_evidence}
    web_search_done = any(item.label == "Web search" and item.status != "skipped" for item in live_evidence)
    urls_found = len(set(submitted_urls + extract_urls(text)))
    domains_checked = len({item.source for item in live_evidence if item.label in {"DNS resolution", "Domain age", "Domain registration", "ATS platform"}})

    return [
        {
            "step": "Evidence intake",
            "status": "complete",
            "detail": f"Reviewed submitted text plus {urls_found} link{'s' if urls_found != 1 else ''}.",
        },
        {
            "step": "Pattern review",
            "status": "complete",
            "detail": f"Found {len(findings)} scam-language signal{'s' if len(findings) != 1 else ''}.",
        },
        {
            "step": "Link and domain checks",
            "status": "complete" if {"URL reachability", "DNS resolution"} & live_labels else "skipped",
            "detail": f"Checked reachability, DNS, and registration data for {domains_checked} domain{'s' if domains_checked != 1 else ''}.",
        },
        {
            "step": "Public web review",
            "status": "complete" if web_search_done else "skipped",
            "detail": (
                "Searched public web results for scam, fraud, complaint, and fake-job signals."
                if web_search_done
                else "Skipped public web search because no company, domain, email, or recognizable employer name was available."
            ),
        },
        {
            "step": "Recommendation",
            "status": "complete",
            "detail": "Combined pattern and live-verification evidence into an apply recommendation.",
        },
    ]


def build_usage_snapshot(before: dict[str, Any]) -> dict[str, int]:
    return {
        "url_fetches": METRICS["url_fetches"] - before["url_fetches"],
        "dns_lookups": METRICS["dns_lookups"] - before["dns_lookups"],
        "rdap_lookups": METRICS["rdap_lookups"] - before["rdap_lookups"],
        "web_searches": METRICS["web_searches"] - before["web_searches"],
    }


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/metrics")
async def metrics() -> dict[str, Any]:
    average_ms = 0.0
    if METRICS["analyze_requests"]:
        average_ms = METRICS["total_analysis_ms"] / METRICS["analyze_requests"]
    return {
        **METRICS,
        "average_analysis_ms": round(average_ms, 2),
        "total_analysis_ms": round(METRICS["total_analysis_ms"], 2),
        "note": "In-memory local counters. They reset when the backend process restarts.",
    }


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
