"""Reachability: does THIS codebase actually exercise the vulnerable code?
Static evidence gathering (AST import/call-site index) + Nemotron judgment with citations."""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .llm import LLM, LLMError
from .research import Intel
from .scan import Finding

# distribution name -> importable top-level module(s), for common mismatches
IMPORT_NAMES = {
    "pyyaml": ["yaml"], "pillow": ["PIL"], "beautifulsoup4": ["bs4"], "scikit-learn": ["sklearn"],
    "python-dateutil": ["dateutil"], "pyjwt": ["jwt"], "python-jose": ["jose"],
    "opencv-python": ["cv2"], "protobuf": ["google.protobuf"], "pycryptodome": ["Crypto"],
    "markupsafe": ["markupsafe"], "werkzeug": ["werkzeug"], "jinja2": ["jinja2"],
    "python-multipart": ["multipart"], "msgpack-python": ["msgpack"], "lxml": ["lxml"],
}
SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".patchwise", "site-packages"}


@dataclass
class Evidence:
    file: str
    line: int
    snippet: str
    kind: str  # import | call | attr


@dataclass
class Reachability:
    vuln_id: str
    verdict: str          # reachable | not_reachable | uncertain
    confidence: float
    rationale: str
    evidence: list[Evidence] = field(default_factory=list)
    method: str = "llm"

    def to_dict(self):
        d = asdict(self)
        return d


def module_names(dist: str) -> list[str]:
    return IMPORT_NAMES.get(dist, [dist.replace("-", "_")])


@dataclass
class PyIndex:
    root: Path
    imports: dict = field(default_factory=lambda: defaultdict(list))  # top module -> [(file, line, alias, full)]
    calls: list = field(default_factory=list)  # (file, line, dotted_name)
    sources: dict = field(default_factory=dict)

    @classmethod
    def build(cls, root: Path) -> "PyIndex":
        idx = cls(root)
        for p in root.rglob("*.py"):
            rel = p.relative_to(root)
            if any(part in SKIP for part in rel.parts):
                continue
            try:
                src = p.read_text(errors="ignore")
                tree = ast.parse(src)
            except (SyntaxError, ValueError):
                continue
            idx.sources[str(rel)] = src.splitlines()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        idx.imports[a.name.split(".")[0]].append((str(rel), node.lineno, a.asname or a.name, a.name))
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    for a in node.names:
                        idx.imports[node.module.split(".")[0]].append(
                            (str(rel), node.lineno, a.asname or a.name, f"{node.module}.{a.name}"))
                elif isinstance(node, ast.Call):
                    name = _dotted(node.func)
                    if name:
                        kw = ",".join(k.arg or "**" for k in node.keywords)
                        idx.calls.append((str(rel), node.lineno, name + (f"[{kw}]" if kw else "")))
        return idx

    def snippet(self, file: str, line: int, ctx: int = 2) -> str:
        lines = self.sources.get(file, [])
        lo, hi = max(0, line - 1 - ctx), min(len(lines), line + ctx)
        return "\n".join(f"{i + 1:>4}| {lines[i]}" for i in range(lo, hi))

    def third_party_imports(self) -> list[str]:
        local = {Path(f).parts[0].removesuffix(".py") for f in self.sources}
        return sorted(m for m in self.imports if m not in local)


def _dotted(node) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def gather(idx: PyIndex, f: Finding, intel: Intel) -> list[Evidence]:
    ev: list[Evidence] = []
    mods = module_names(f.dep.name)
    aliases = set()
    for m in mods:
        for file, line, alias, full in idx.imports.get(m.split(".")[0], []):
            aliases.add(alias)
            ev.append(Evidence(file, line, idx.snippet(file, line, 0), "import"))
    tails = {s.rstrip("()").split(".")[-1] for s in intel.vulnerable_symbols if s != "*"}
    tails = {t for t in tails if re.match(r"^[A-Za-z_]\w+$", t)}
    for file, line, name in idx.calls:
        base = name.split("[")[0]
        head, last = base.split(".")[0], base.split(".")[-1]
        if head in aliases or last in tails:
            ev.append(Evidence(file, line, idx.snippet(file, line), "call"))
    return ev[:40]


SYSTEM = """You are a senior application-security engineer doing reachability analysis.
Decide whether the given codebase can actually trigger a known vulnerability in one of its
dependencies. Use ONLY the evidence given. Rules:
- reachable: there is a concrete code path that uses the vulnerable symbol/feature in the
  vulnerable way (cite file:line), or the flaw triggers on any normal use and the package
  is used (directly, or clearly indirectly via a package that wraps it).
- not_reachable: the vulnerable symbol/feature is never used, or only used in a safe way
  (e.g. yaml.safe_load), or the package is not imported and no imported package wraps it.
- uncertain: evidence is insufficient (dynamic dispatch, indirect use you cannot rule out).
Prefer 'uncertain' over guessing. Keep rationale under 80 words."""

USER_TMPL = """Vulnerability {vid} in {pkg} {ver}
Vulnerable symbols/features: {syms}
Trigger conditions: {trig}
Attack vector: {vector}

Third-party modules imported by the codebase: {imports}

Static evidence (imports and candidate call sites):
{evidence}

Return JSON: {{"verdict": "reachable"|"not_reachable"|"uncertain", "confidence": 0.0-1.0,
 "rationale": str, "cited": ["file:line", ...]}}"""


def heuristic(idx: PyIndex, f: Finding, intel: Intel, ev: list[Evidence]) -> Reachability:
    imports = [e for e in ev if e.kind == "import"]
    calls = [e for e in ev if e.kind == "call"]
    if not imports:
        return Reachability(intel.vuln_id, "uncertain" if f.dep.ecosystem == "npm" else "not_reachable",
                            0.5, "Package is never imported directly; it may still be used transitively.",
                            ev, "heuristic")
    if "*" in intel.vulnerable_symbols:
        return Reachability(intel.vuln_id, "reachable", 0.6, "Package is imported and the flaw "
                            "affects general use.", ev, "heuristic")
    if calls:
        return Reachability(intel.vuln_id, "uncertain", 0.5, "Candidate call sites match "
                            "vulnerable symbol names; needs model review.", ev, "heuristic")
    return Reachability(intel.vuln_id, "not_reachable", 0.55, "Package imported but no call "
                        "site matches the vulnerable symbols.", ev, "heuristic")


def analyze(idx: PyIndex, f: Finding, intel: Intel, llm: LLM) -> Reachability:
    ev = gather(idx, f, intel)
    if not llm.online:
        return heuristic(idx, f, intel, ev)
    evtext = "\n".join(f"[{e.kind}] {e.file}:{e.line}\n{e.snippet}" for e in ev) or "(none found)"
    user = USER_TMPL.format(vid=intel.vuln_id, pkg=f.dep.name, ver=f.dep.version,
                            syms=", ".join(intel.vulnerable_symbols), trig=intel.trigger_conditions[:800],
                            vector=intel.attack_vector[:300], imports=", ".join(idx.third_party_imports()[:60]),
                            evidence=evtext[:10000])
    try:
        d = llm.chat_json("reason", SYSTEM, user, max_tokens=1500)
    except LLMError:
        return heuristic(idx, f, intel, ev)
    verdict = d.get("verdict") if d.get("verdict") in {"reachable", "not_reachable", "uncertain"} else "uncertain"
    cited = set(d.get("cited") or [])
    if cited:  # keep cited evidence first so reports show the proof
        ev.sort(key=lambda e: f"{e.file}:{e.line}" not in cited)
    try:
        conf = float(d.get("confidence", 0.5))
    except (TypeError, ValueError):
        conf = 0.5
    return Reachability(intel.vuln_id, verdict, max(0.0, min(1.0, conf)),
                        str(d.get("rationale") or ""), ev)
