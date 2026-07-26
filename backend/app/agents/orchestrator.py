from __future__ import annotations

from typing import Any

from app.agents.dispatcher import dispatch_text_classification


async def run_agentic_analysis(text: str) -> list[dict[str, Any]]:
    """Entry point for the agentic layer, called once per analyze request.

    This is a thin pass-through to the dispatcher today. The seam exists so a
    future session/follow-up context (e.g. "why was this flagged?") can be
    added here later without changing what callers pass in.
    """
    return await dispatch_text_classification(text)
