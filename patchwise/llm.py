"""Thin client for Nebius Token Factory (OpenAI-compatible) with token + cost accounting."""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field

from .config import PRICES, TOKEN_FACTORY_BASE_URL, Settings


@dataclass
class Usage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    by_model: dict = field(default_factory=dict)

    def add(self, model: str, inp: int, out: int) -> None:
        pin, pout = PRICES.get(model, (0.0, 0.0))
        cost = inp / 1e6 * pin + out / 1e6 * pout
        self.calls += 1
        self.input_tokens += inp
        self.output_tokens += out
        self.cost_usd += cost
        m = self.by_model.setdefault(model, {"calls": 0, "in": 0, "out": 0, "cost_usd": 0.0})
        m["calls"] += 1
        m["in"] += inp
        m["out"] += out
        m["cost_usd"] += cost


class LLMError(RuntimeError):
    pass


_JSON_BLOCK = re.compile(r"\{.*\}", re.S)


def _strip_reasoning(text: str) -> str:
    # Nemotron reasoning models may emit <think>...</think>; drop it.
    return re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()


def parse_json(text: str) -> dict:
    text = _strip_reasoning(text)
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidate = fence.group(1) if fence else None
    if candidate is None:
        m = _JSON_BLOCK.search(text)
        candidate = m.group(0) if m else text
    try:
        return json.loads(candidate)
    except json.JSONDecodeError as e:
        raise LLMError(f"model did not return valid JSON: {e}: {text[:300]}") from e


class LLM:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.usage = Usage()
        self._lock = threading.Lock()
        self._client = None
        if settings.llm_available:
            from openai import OpenAI

            self._client = OpenAI(base_url=TOKEN_FACTORY_BASE_URL, api_key=settings.nebius_api_key)

    @property
    def online(self) -> bool:
        return self._client is not None

    def model(self, tier: str) -> str:
        return self.settings.models[tier]

    def chat(self, tier: str, system: str, user: str, *, max_tokens: int = 2048,
             temperature: float = 0.2, retries: int = 3) -> str:
        if not self.online:
            raise LLMError("No NEBIUS_API_KEY set (or offline mode); LLM unavailable")
        model = self.model(tier)
        last = None
        for attempt in range(retries):
            try:
                resp = self._client.chat.completions.create(
                    model=model,
                    messages=[{"role": "system", "content": system},
                              {"role": "user", "content": user}],
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                u = resp.usage
                with self._lock:
                    self.usage.add(model, getattr(u, "prompt_tokens", 0) or 0,
                                   getattr(u, "completion_tokens", 0) or 0)
                return _strip_reasoning(resp.choices[0].message.content or "")
            except Exception as e:  # network/rate-limit: back off and retry
                last = e
                time.sleep(1.5 * (attempt + 1))
        raise LLMError(f"Token Factory call failed for {model}: {last}")

    def chat_json(self, tier: str, system: str, user: str, **kw) -> dict:
        sys = system + "\nRespond with a single JSON object only. No prose outside JSON."
        text = self.chat(tier, sys, user, **kw)
        try:
            return parse_json(text)
        except LLMError:
            # one repair attempt on the cheap model
            fixed = self.chat("fast", "Convert the following into one valid JSON object. Output JSON only.",
                              text[:6000], max_tokens=1500)
            return parse_json(fixed)
