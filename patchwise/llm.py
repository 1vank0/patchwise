"""Thin client for Nebius Token Factory (OpenAI-compatible) with token + cost accounting.

Robustness features (all exercised against live Nemotron models):
- reasoning control per tier: Nemotron models think by default and their reasoning tokens
  count against max_tokens; extraction calls turn thinking off, judgment calls keep it on;
- reasoning that leaks into `content` (<think> blocks, "Here's a thinking process: ...")
  is tolerated: we pick the last JSON object that parses, and fall back to reasoning_content;
- truncated output (finish_reason=length) is retried once with a larger token budget;
- retries with exponential backoff + jitter for rate limits, timeouts, connection errors and
  5xx, honoring Retry-After; non-retryable 4xx errors fail fast;
- a hard per-run budget guard and an optional JSONL spend ledger (token counts only).
"""
from __future__ import annotations

import ast
import json
import os
import random
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
    retries: int = 0
    by_model: dict = field(default_factory=dict)

    def add(self, model: str, inp: int, out: int) -> float:
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
        return cost


class LLMError(RuntimeError):
    pass


class BudgetExceeded(LLMError):
    pass


def _strip_reasoning(text: str) -> str:
    # Nemotron reasoning models may emit <think>...</think> (or an unterminated <think>).
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S)
    if "<think>" in text:
        text = text.split("<think>")[0]
    if "</think>" in text:  # opening tag consumed by the template, closing one leaked
        text = text.rsplit("</think>", 1)[1]
    return text.strip()


def _loads_lenient(s: str):
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    fixed = re.sub(r",\s*([}\]])", r"\1", s)  # trailing commas
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        pass
    try:  # python-literal style: single quotes, True/False/None
        v = ast.literal_eval(fixed)
        return v if isinstance(v, (dict, list)) else None
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return None


def _balanced_objects(text: str):
    """Yield every top-level-balanced {...} substring (string-aware)."""
    i, n = 0, len(text)
    while i < n:
        start = text.find("{", i)
        if start < 0:
            return
        depth, j, in_str, esc, quote = 0, start, False, False, ""
        while j < n:
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == quote:
                    in_str = False
            elif c in "\"'" and quote_ok(text, j):
                in_str, quote = True, c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    yield text[start:j + 1]
                    break
            j += 1
        i = start + 1 if depth else j + 1


def quote_ok(text: str, j: int) -> bool:
    # apostrophes inside prose ("don't") must not open a string; JSON uses double quotes,
    # python-literal output puts single quotes right after { , : [ or whitespace.
    if text[j] == '"':
        return True
    prev = text[j - 1] if j else " "
    return prev in "{[,: \n\t"


def parse_json(text: str, want: tuple[str, ...] = ()) -> dict:
    """Extract the JSON object a model meant to return. Prefers fenced blocks, then the last
    balanced object that parses (reasoning usually precedes the answer), and prefers objects
    containing the expected keys."""
    raw = text or ""
    text = _strip_reasoning(raw) or raw
    cands: list[dict] = []
    for block in re.findall(r"```(?:json)?\s*(.*?)```", text, re.S):
        v = _loads_lenient(block.strip())
        if isinstance(v, dict):
            cands.append(v)
    if not cands:
        for s in _balanced_objects(text):
            v = _loads_lenient(s)
            if isinstance(v, dict):
                cands.append(v)
    if not cands:
        raise LLMError(f"model did not return valid JSON: {text[:300]!r}")
    if want:
        good = [c for c in cands if any(k in c for k in want)]
        if good:
            return good[-1]
    # outermost objects come out of _balanced_objects first; prefer the last *largest*
    return max(reversed(cands), key=lambda c: len(json.dumps(c)))


def _retryable(e: Exception) -> tuple[bool, float | None]:
    try:
        import openai
    except ImportError:  # pragma: no cover
        return True, None
    if isinstance(e, (openai.APITimeoutError, openai.APIConnectionError)):
        return True, None
    if isinstance(e, openai.APIStatusError):
        ra = None
        try:
            ra = float(e.response.headers.get("retry-after"))
        except (TypeError, ValueError, AttributeError):
            pass
        return e.status_code in (408, 409, 425, 429) or e.status_code >= 500, ra
    return False, None


class LLM:
    # Per-tier defaults. Thinking off for high-volume extraction; on for judgment/repair.
    THINKING = {"fast": False, "reason": True, "deep": True}

    def __init__(self, settings: Settings):
        self.settings = settings
        self.usage = Usage()
        self._lock = threading.Lock()
        self._client = None
        self._sleep = time.sleep
        if settings.llm_available:
            from openai import OpenAI

            self._client = OpenAI(base_url=TOKEN_FACTORY_BASE_URL, api_key=settings.nebius_api_key,
                                  timeout=settings.llm_timeout, max_retries=0)

    @property
    def online(self) -> bool:
        return self._client is not None

    def model(self, tier: str) -> str:
        return self.settings.models[tier]

    def _ledger(self, model: str, inp: int, out: int, cost: float, tag: str) -> None:
        path = os.environ.get("PATCHWISE_SPEND_LOG")
        if not path:
            return
        with open(path, "a") as fh:
            fh.write(json.dumps({"t": round(time.time(), 1), "model": model, "in": inp, "out": out,
                                 "cost_usd": round(cost, 6), "tag": tag}) + "\n")

    def _create(self, model: str, messages: list, max_tokens: int, temperature: float, thinking: bool):
        return self._client.chat.completions.create(
            model=model, messages=messages, max_tokens=max_tokens, temperature=temperature,
            extra_body={"chat_template_kwargs": {"enable_thinking": thinking}})

    def chat(self, tier: str, system: str, user: str, *, max_tokens: int = 2048,
             temperature: float = 0.2, retries: int | None = None, thinking: bool | None = None,
             tag: str = "") -> str:
        if not self.online:
            raise LLMError("No NEBIUS_API_KEY set (or offline mode); LLM unavailable")
        model = self.model(tier)
        thinking = self.THINKING.get(tier, True) if thinking is None else thinking
        retries = self.settings.llm_retries if retries is None else retries
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        last: Exception | None = None
        grown = False
        attempt = 0
        while attempt <= retries:
            if self.usage.cost_usd >= self.settings.max_cost_usd:
                raise BudgetExceeded(f"run budget ${self.settings.max_cost_usd:.2f} exhausted")
            try:
                resp = self._create(model, messages, max_tokens, temperature, thinking)
            except Exception as e:
                ok, ra = _retryable(e)
                last = e
                if not ok or attempt == retries:
                    break
                delay = ra if ra is not None else min(30.0, 1.5 * 2 ** attempt) * (0.75 + random.random() / 2)
                with self._lock:
                    self.usage.retries += 1
                self._sleep(delay)
                attempt += 1
                continue
            u = resp.usage
            inp = getattr(u, "prompt_tokens", 0) or 0
            out = getattr(u, "completion_tokens", 0) or 0
            with self._lock:
                cost = self.usage.add(model, inp, out)
            self._ledger(model, inp, out, cost, tag)
            choice = resp.choices[0]
            msg = choice.message
            content = msg.content or ""
            extra = getattr(msg, "model_extra", None) or {}
            reasoning = extra.get("reasoning_content") or extra.get("reasoning") or ""
            stripped = _strip_reasoning(content)
            if choice.finish_reason == "length" and not grown and "{" not in stripped:
                # reasoning ate the budget before the answer. Doubling the budget invites a
                # runaway (seen live: 12k then 24k tokens of thought, no answer), so retry once
                # with thinking off; if thinking was already off, retry once with more room.
                grown = True
                with self._lock:
                    self.usage.retries += 1
                if thinking:
                    thinking = False
                else:
                    max_tokens = min(max_tokens * 2, 16000)
                continue
            if not stripped and reasoning:
                return str(reasoning)  # last resort: answer may be inside the reasoning
            return stripped or content
        raise LLMError(f"Token Factory call failed for {model}: {type(last).__name__}: {str(last)[:300]}")

    def chat_json(self, tier: str, system: str, user: str, *, want: tuple[str, ...] = (), **kw) -> dict:
        sys = system + "\nRespond with a single JSON object only. No prose or markdown outside the JSON."
        text = self.chat(tier, sys, user, **kw)
        try:
            return parse_json(text, want)
        except LLMError:
            # one repair attempt on the cheap model
            fixed = self.chat("fast", "Convert the following into one valid JSON object. Output JSON only.",
                              text[-8000:], max_tokens=3000, thinking=False, tag="json-repair")
            return parse_json(fixed, want)
