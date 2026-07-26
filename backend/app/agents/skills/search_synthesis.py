from __future__ import annotations

import json
import re

from app.agents.client import SEARCH_SYNTHESIS_MODEL, get_client
from app.agents.safety import wrap_untrusted

SYSTEM_PROMPT = """You judge whether web search results indicate that a SPECIFIC company or \
domain has been reported as a scam, versus generic or unrelated content (listicles about job \
scams in general, reviews of a different company, etc). Respond with ONLY a JSON object, no \
prose, no markdown fences:
{"severity": "high|medium|info", "reasoning": "One sentence."}
Use "high" only if a result specifically names or clearly refers to the target company or \
domain in a scam-warning context. Use "medium" for plausible but vague relevance. Use "info" \
if the results are generic or unrelated to the specific target."""


async def judge_search_relevance(query: str, result_text: str) -> dict[str, str] | None:
    client = get_client()
    if client is None or not result_text.strip():
        return None

    prompt = f"Search query (target company/domain): {query}\n\n{wrap_untrusted('web search results', result_text[:3000])}"

    try:
        response = await client.messages.create(
            model=SEARCH_SYNTHESIS_MODEL,
            max_tokens=200,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text if response.content else "{}"
        match = re.search(r"\{.*\}", raw.strip(), re.DOTALL)
        if not match:
            return None
        payload = json.loads(match.group(0))
        severity = payload.get("severity")
        if severity not in {"high", "medium", "info"}:
            return None
        return {"severity": severity, "reasoning": str(payload.get("reasoning", ""))[:200]}
    except Exception:
        return None
