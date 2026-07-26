from __future__ import annotations

import json
import re
from typing import Any

from app.agents.client import CLASSIFIER_MODEL, get_client
from app.agents.safety import redact_pii

SYSTEM_PROMPT = """You determine whether a piece of text is a genuine job posting, job \
offer, or recruiter/employer message worth analyzing for scam risk -- versus text with no \
real job-related substance (random test strings, unrelated chat, empty filler). Respond with \
ONLY a JSON object, no prose, no markdown fences:
{"is_relevant": true|false, "reason": "One short sentence."}
Mark is_relevant as true if the text describes, offers, discusses, or requests something \
related to a job, position, interview, hiring process, or employment -- even if brief, vague, \
or suspicious-sounding. A short message mentioning a job offer, a payment request tied to \
employment, or any hiring-adjacent detail counts as relevant. Mark it false only when the \
text has no discernible connection to a job or employment context at all."""


async def classify_relevance(text: str) -> dict[str, Any] | None:
    client = get_client()
    if client is None or not text.strip():
        return None

    safe_text = redact_pii(text)[:4000]

    try:
        response = await client.messages.create(
            model=CLASSIFIER_MODEL,
            max_tokens=200,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Text to classify:\n\n{safe_text}"}],
        )
        raw = response.content[0].text if response.content else "{}"
        match = re.search(r"\{.*\}", raw.strip(), re.DOTALL)
        if not match:
            return None
        payload = json.loads(match.group(0))
        if "is_relevant" not in payload:
            return None
        return {
            "is_relevant": bool(payload["is_relevant"]),
            "reason": str(payload.get("reason", ""))[:200],
        }
    except Exception:
        return None
