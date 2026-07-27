from __future__ import annotations

import json
import re
from typing import Any

from app.agents.client import CLASSIFIER_MODEL, get_client
from app.agents.safety import redact_pii

SYSTEM_PROMPT = """You judge whether a piece of text contains enough real job-description \
substance to be worth analyzing for scam risk, or whether it is too vague/generic to review. \
Respond with ONLY a JSON object, no prose, no markdown fences:
{"is_valid_jd": true|false, "missing": ["company", "role", "requirements"], "reason": "One short sentence."}

A message is a valid JD (is_valid_jd: true) only if it includes at least one concrete, \
verifiable detail such as:
- a company or employer name
- a job title or role
- skills, responsibilities, or requirements
- a specific salary, location, or application process

A message is NOT a valid JD (is_valid_jd: false) if it is a vague notification, greeting, or \
generic statement with none of the above -- for example "you're invited for an interview \
tomorrow" or "we'd like to offer you the role" with no company name, job title, or any other \
identifying detail. Mentioning words like "interview", "offer", "job", or "position" alone, \
with nothing else concrete attached, is NOT enough to pass.

The "missing" field should list which of company/role/requirements are absent, for messages \
that fail. Set is_valid_jd to true whenever at least one concrete detail above is present, \
even if the message also contains suspicious or scam-like content -- that risk gets assessed \
separately once the message passes this check."""


async def analyze_jd(text: str) -> dict[str, Any] | None:
    client = get_client()
    if client is None or not text.strip():
        return None

    safe_text = redact_pii(text)[:4000]

    try:
        response = await client.messages.create(
            model=CLASSIFIER_MODEL,
            max_tokens=250,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Text to review:\n\n{safe_text}"}],
        )
        raw = response.content[0].text if response.content else "{}"
        match = re.search(r"\{.*\}", raw.strip(), re.DOTALL)
        if not match:
            return None
        payload = json.loads(match.group(0))
        if "is_valid_jd" not in payload:
            return None
        missing = payload.get("missing", [])
        return {
            "is_valid_jd": bool(payload["is_valid_jd"]),
            "missing": [str(item) for item in missing][:5] if isinstance(missing, list) else [],
            "reason": str(payload.get("reason", ""))[:200],
        }
    except Exception:
        return None
