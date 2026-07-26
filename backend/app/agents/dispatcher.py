from __future__ import annotations

from typing import Any

from app.agents.client import agents_enabled
from app.agents.skills.classifier import classify_scam_intent
from app.agents.skills.relevance_classifier import classify_relevance


async def dispatch_text_classification(text: str) -> list[dict[str, Any]]:
    if not agents_enabled() or not text.strip():
        return []
    return await classify_scam_intent(text)


async def dispatch_relevance_check(text: str) -> dict[str, Any] | None:
    if not agents_enabled() or not text.strip():
        return None
    return await classify_relevance(text)
