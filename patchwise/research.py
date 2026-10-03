"""Live advisory research: Tavily search/extract + Nemotron extraction of *what code is
actually vulnerable* (symbols, trigger conditions), which OSV data usually lacks."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

import httpx

from .config import Settings
from .llm import LLM, LLMError
from .scan import Finding, Vuln

TAVILY = "https://api.tavily.com"


@dataclass
class Intel:
    vuln_id: str
    vulnerable_symbols: list[str] = field(default_factory=list)  # e.g. ["yaml.load", "FullLoader"]
    trigger_conditions: str = ""
    attack_vector: str = ""        # network / local / requires untrusted input X
    public_exploit: bool | None = None
    fix_notes: str = ""
    sources: list[str] = field(default_factory=list)
    method: str = "llm"            # "llm" | "heuristic"
    platforms: list[str] = field(default_factory=list)  # OSes the flaw is limited to; [] = any

    def to_dict(self):
        return asdict(self)


class Tavily:
    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.s = settings
        self.client = client or httpx.Client(timeout=40)
        self.calls = 0

    @property
    def enabled(self) -> bool:
        return bool(self.s.tavily_api_key) or self.s.tavily_keyless

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.s.tavily_api_key:
            h["Authorization"] = f"Bearer {self.s.tavily_api_key}"
        else:
            h["X-Tavily-Access-Mode"] = "keyless"
        return h

    def search(self, query: str, max_results: int = 5, include_domains: list[str] | None = None) -> list[dict]:
        body = {"query": query, "max_results": max_results, "search_depth": "advanced"}
        if include_domains:
            body["include_domains"] = include_domains
        r = self.client.post(f"{TAVILY}/search", json=body, headers=self._headers())
        self.calls += 1
        r.raise_for_status()
        return r.json().get("results", [])

    def extract(self, urls: list[str]) -> list[dict]:
        if not urls:
            return []
        r = self.client.post(f"{TAVILY}/extract", json={"urls": urls[:3]}, headers=self._headers())
        self.calls += 1
        r.raise_for_status()
        return r.json().get("results", [])


SYSTEM = """You are an application-security analyst. From advisory text and web sources,
identify precisely WHICH code in the vulnerable package must be used for the vulnerability
to be exploitable. Be concrete: fully-qualified functions, classes, methods, options or
config flags (e.g. "yaml.load without SafeLoader", "jinja2.sandbox.SandboxedEnvironment",
"requests.Session with verify=False"). If the flaw is reachable through any normal use of
the package, say so with symbol "*". Never invent symbols not supported by the sources."""

USER_TMPL = """Package: {pkg} {ver} ({eco})
Advisory {vid} (aliases: {aliases}) severity={sev}
Summary: {summary}
Details:
{details}

Web sources:
{sources}

Return JSON:
{{"vulnerable_symbols": [str], "trigger_conditions": str, "attack_vector": str,
  "public_exploit": true|false|null, "fix_notes": str, "sources_used": [url],
  "platforms": [str]}}
"platforms": operating systems the flaw is LIMITED to ("windows", "macos", "linux"); [] when it
is not OS-specific (most flaws)."""


OS_WORDS = {"windows": r"windows", "macos": r"mac ?os|os x|darwin", "linux": r"linux"}
_ONLY = re.compile(r"\b(on|only on|only affects?|specific to|special device names? on)\s+(windows|mac ?os|os x)\b"
                   r"|\bwindows[- ]only\b|\bwindows (special )?device names?\b|\bnot safe on windows\b", re.I)


def platform_limits(text: str, claimed: list | None = None) -> list[str]:
    """OSes an advisory is restricted to. A model claim counts only if the advisory text itself
    names that OS (guards against hallucination); otherwise fall back to explicit phrasing such
    as 'on Windows' / 'Windows device names'."""
    t = text.lower()
    out = [o for o in (claimed or []) if isinstance(o, str) and o.lower() in OS_WORDS
           and re.search(OS_WORDS[o.lower()], t)]
    if not out and _ONLY.search(text):
        m = _ONLY.search(text).group(0).lower()
        out = ["macos"] if re.search(OS_WORDS["macos"], m) else ["windows"]
    return sorted({o.lower() for o in out})


_TICK = re.compile(r"`([A-Za-z_][\w.]*(?:\(\))?)`")


def heuristic_intel(f: Finding, v: Vuln) -> Intel:
    syms = []
    for m in _TICK.findall(v.summary + "\n" + v.details):
        s = m.rstrip("()")
        if s not in syms and len(s) > 2:
            syms.append(s)
    return Intel(v.id, vulnerable_symbols=syms[:8] or ["*"],
                 trigger_conditions=v.summary, fix_notes=f"Upgrade to {f.min_fix}" if f.min_fix else "",
                 sources=v.references[:3], method="heuristic",
                 platforms=platform_limits(v.summary + "\n" + v.details))


def research(f: Finding, v: Vuln, llm: LLM, tavily: Tavily | None) -> Intel:
    web_chunks: list[str] = []
    urls: list[str] = []
    if tavily and tavily.enabled:
        try:
            q = f"{v.id} {' '.join(v.aliases[:2])} {f.dep.name} vulnerable function affected code fix commit"
            for res in tavily.search(q, max_results=5):
                urls.append(res["url"])
                web_chunks.append(f"- {res['url']}\n  {res.get('content', '')[:1500]}")
            # Pull the fix commit / PR if one is referenced: it names the patched code exactly.
            fix_urls = [u for u in v.references if re.search(r"github\.com/.+/(commit|pull)/", u)][:2]
            for ex in tavily.extract(fix_urls):
                urls.append(ex["url"])
                web_chunks.append(f"- {ex['url']} (extracted)\n  {ex.get('raw_content', '')[:3000]}")
        except httpx.HTTPError as e:
            web_chunks.append(f"(web research unavailable: {e})")
    if not llm.online:
        intel = heuristic_intel(f, v)
        intel.sources = (urls or intel.sources)[:5]
        return intel
    user = USER_TMPL.format(pkg=f.dep.name, ver=f.dep.version, eco=f.dep.ecosystem, vid=v.id,
                            aliases=", ".join(v.aliases) or "-", sev=v.severity, summary=v.summary,
                            details=v.details[:3000], sources="\n".join(web_chunks)[:9000] or "(none)")
    try:
        d = llm.chat_json("fast", SYSTEM, user, max_tokens=1500, want=("vulnerable_symbols",), tag="research")
    except LLMError:
        return heuristic_intel(f, v)
    return Intel(v.id,
                 vulnerable_symbols=[str(s) for s in d.get("vulnerable_symbols") or []][:12] or ["*"],
                 trigger_conditions=str(d.get("trigger_conditions") or ""),
                 attack_vector=str(d.get("attack_vector") or ""),
                 public_exploit=d.get("public_exploit"),
                 fix_notes=str(d.get("fix_notes") or ""),
                 sources=[u for u in (d.get("sources_used") or urls) if isinstance(u, str)][:6],
                 platforms=platform_limits(v.summary + "\n" + v.details, d.get("platforms")))
