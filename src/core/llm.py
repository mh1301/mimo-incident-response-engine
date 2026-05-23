"""MiMo LLM client for reasoning and analysis."""
import requests
import json
import logging
from ..config import MIMO_API, MIMO_MODEL

logger = logging.getLogger("ir.llm")


async def query_mimo(prompt: str, system: str = "You are a security analyst.", max_tokens: int = 4000) -> str:
    """Query MiMo LLM for analysis."""
    try:
        resp = requests.post(
            MIMO_API,
            json={
                "model": MIMO_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.3,
                "stream": False,
            },
            timeout=120,
        )
        data = resp.json()
        if "choices" in data and len(data["choices"]) > 0:
            return data["choices"][0]["message"]["content"]
        return "LLM analysis unavailable."
    except Exception as e:
        logger.error(f"MiMo API error: {e}")
        return f"LLM analysis error: {str(e)}"


def query_mimo_sync(prompt: str, system: str = "You are a security analyst.", max_tokens: int = 4000) -> str:
    """Synchronous MiMo query."""
    try:
        resp = requests.post(
            MIMO_API,
            json={
                "model": MIMO_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.3,
                "stream": False,
            },
            timeout=120,
        )
        data = resp.json()
        if "choices" in data and len(data["choices"]) > 0:
            return data["choices"][0]["message"]["content"]
        return "LLM analysis unavailable."
    except Exception as e:
        logger.error(f"MiMo API error: {e}")
        return f"LLM analysis error: {str(e)}"
