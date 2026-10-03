"""Reachability: does THIS codebase actually exercise the vulnerable code?
Static evidence gathering (AST import/call-site index) + Nemotron judgment with citations."""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from functools import lru_cache
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
    cited: list[str] = field(default_factory=list)
    group: list[str] = field(default_factory=list)  # sibling advisories judged together with this one
    dev_only: str = ""      # non-empty reason when the package is used only by tests/dev tooling

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
    templates: dict = field(default_factory=dict)  # template file -> lines
    filters: dict = field(default_factory=lambda: defaultdict(list))  # jinja filter -> [(file, line)]

    @classmethod
    def build(cls, root: Path) -> "PyIndex":
        import warnings
        idx = cls(root)
        tmpl_re = re.compile(r"\|\s*([A-Za-z_]\w*)")
        for p in root.rglob("*"):
            if p.suffix not in (".html", ".htm", ".j2", ".jinja", ".jinja2", ".xml", ".txt") or not p.is_file():
                continue
            rel = p.relative_to(root)
            if any(part in SKIP for part in rel.parts) or p.stat().st_size > 300_000:
                continue
            try:
                lines = p.read_text(errors="ignore").splitlines()
            except OSError:
                continue
            if not any("{{" in ln or "{%" in ln for ln in lines[:400]):
                continue
            idx.templates[str(rel)] = lines
            for i, ln in enumerate(lines, 1):
                for expr in re.findall(r"\{\{.*?\}\}|\{%.*?%\}", ln):
                    for name in tmpl_re.findall(expr):
                        idx.filters[name].append((str(rel), i))
        for p in root.rglob("*.py"):
            rel = p.relative_to(root)
            if any(part in SKIP for part in rel.parts):
                continue
            try:
                src = p.read_text(errors="ignore")
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
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
        lines = self.sources.get(file) or self.templates.get(file, [])
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


# Method names too generic to count as evidence on their own (dict.get, bytes.decode, …).
GENERIC = {"get", "post", "put", "delete", "request", "decode", "encode", "read", "write", "open",
           "close", "load", "loads", "dump", "dumps", "parse", "run", "call", "send", "update",
           "format", "join", "split", "copy", "keys", "items", "values", "append", "init", "new"}


@lru_cache(maxsize=1024)
def requires(dist: str, version: str | None, extras: bool = False) -> frozenset:
    """Normalized names of the requirements of dist==version (latest if None) from PyPI
    metadata; with extras=True, optional (extra-gated) requirements are included."""
    import httpx
    from packaging.requirements import InvalidRequirement, Requirement
    url = f"https://pypi.org/pypi/{dist}/{version}/json" if version else f"https://pypi.org/pypi/{dist}/json"
    try:
        info = httpx.get(url, timeout=20).json()["info"]
    except Exception:
        return frozenset()
    out = set()
    for spec in info.get("requires_dist") or []:
        try:
            r = Requirement(spec)
        except InvalidRequirement:
            continue
        if r.marker and "extra" in str(r.marker) and not extras:
            continue
        out.add(re.sub(r"[-_.]+", "-", r.name).lower())
    return frozenset(out)


# Packages a wrapper uses automatically at runtime whenever they are installed, even though
# they are only an optional extra (or an implicit companion) of the wrapper.
AUTO_USED = {
    ("urllib3", "brotli"): "urllib3 decodes 'Content-Encoding: br' responses with brotli automatically whenever it is installed",
    ("urllib3", "brotlicffi"): "urllib3 decodes 'Content-Encoding: br' responses with brotlicffi automatically whenever it is installed",
    ("urllib3", "zstandard"): "urllib3 decodes 'Content-Encoding: zstd' responses automatically whenever zstandard is installed",
    ("requests", "brotli"): "requests (via urllib3) decodes brotli-compressed responses automatically whenever brotli is installed",
    ("requests", "chardet"): "requests uses chardet to guess response encodings (r.text) when it is installed",
    ("requests", "charset-normalizer"): "requests uses charset-normalizer to guess response encodings (r.text)",
    ("requests", "idna"): "requests/urllib3 IDNA-encode every non-ASCII hostname",
    ("requests", "certifi"): "requests verifies every HTTPS connection against certifi's CA bundle",
    ("httpx", "brotli"): "httpx decodes brotli-compressed responses automatically whenever brotli is installed",
    ("aiohttp", "brotli"): "aiohttp decodes brotli-compressed responses automatically whenever brotli is installed",
    ("flask", "werkzeug"): ("Flask runs every request through Werkzeug: routing, headers and cookies always; "
                            "the form/multipart parser whenever a view, Flask-WTF/WTForms form or extension "
                            "reads request.form/request.files (every form POST)"),
    ("flask-wtf", "werkzeug"): "Flask-WTF forms read request.form/request.files on every POST, running Werkzeug's form/multipart parser",
    ("flask-wtf", "flask"): "Flask-WTF forms read request.form/request.files on every POST, running Werkzeug's form/multipart parser",
    ("flask", "jinja2"): "Flask renders templates with Jinja2",
    ("flask", "itsdangerous"): "Flask signs session cookies with itsdangerous",
    ("jinja2", "markupsafe"): "Jinja2 autoescaping runs through markupsafe",
}


def auto_note(chain: str, pkg: str) -> str:
    hops = [h.split(" (")[0].strip() for h in chain.split(">")] + [pkg]
    for a, b in zip(hops, hops[1:]):
        if (a, b) in AUTO_USED:
            return AUTO_USED[(a, b)]
    return ""


TEST_DIRS = {"tests", "test", "testing", "docs", "doc", "examples", "example", "benchmarks", "bench"}


def is_test_path(path: str) -> bool:
    parts = Path(path).parts
    name = parts[-1] if parts else ""
    return (any(p.lower() in TEST_DIRS for p in parts[:-1]) or name.startswith("test_")
            or name.endswith(("_test.py", "_tests.py")) or name in ("conftest.py", "testing.py", "noxfile.py",
                                                                    "tasks.py", "fabfile.py"))


def dev_only(idx: "PyIndex", f: Finding, wrappers: list[str]) -> str:
    """Reason string when the package matters only to tests/dev tooling, else ''."""
    from .scan import is_dev_manifest
    if f.dep.ecosystem == "PyPI" and all(is_dev_manifest(m) for m in f.dep.manifests):
        return f"pinned only in dev/test requirements ({', '.join(f.dep.manifests)})"
    files = [file for m in module_names(f.dep.name) for file, *_ in idx.imports.get(m.split(".")[0], [])]
    for w in wrappers:
        files += [file for m in module_names(w.split(" ")[0]) for file, *_ in idx.imports.get(m.split(".")[0], [])]
    if files and all(is_test_path(x) for x in files):
        return "imported only from test/dev code (" + ", ".join(sorted(set(files))[:3]) + ")"
    return ""


def wrappers_for(idx: "PyIndex", f: Finding, deps: list) -> list[str]:
    """Directly-imported pinned deps through which f's package is used, up to two levels deep,
    including optional extras (requests -> urllib3; requests -> urllib3 -> brotli, which
    urllib3 uses automatically whenever it is installed). Returns chains like
    'requests', 'requests > urllib3 (optional extra)'."""
    pinned = {d.name: d.version for d in deps if d.ecosystem == "PyPI"}
    out = []
    for d in deps:
        if d.name == f.dep.name or d.ecosystem != "PyPI":
            continue
        if not any(idx.imports.get(m.split(".")[0]) for m in module_names(d.name)):
            continue
        direct = requires(d.name, d.version)
        if f.dep.name in direct:
            out.append(d.name)
            continue
        if f.dep.name in requires(d.name, d.version, True):
            out.append(f"{d.name} (optional extra)")
            continue
        for mid in sorted(direct):
            if f.dep.name in requires(mid, pinned.get(mid), True):
                opt = "" if f.dep.name in requires(mid, pinned.get(mid)) else " (optional extra)"
                out.append(f"{d.name} > {mid}{opt}")
                break
    return [w + (f" [auto-used: {n}]" if (n := auto_note(w, f.dep.name)) else "") for w in out[:6]]


def gather(idx: PyIndex, f: Finding, intel: Intel, wrappers: list[str] | None = None) -> list[Evidence]:
    ev: list[Evidence] = []
    aliases = set()
    for kind, dists in (("import", [f.dep.name]), ("import-via", [w.split(" ")[0] for w in wrappers or []])):
        for dist in dists:
            for m in module_names(dist):
                for file, line, alias, full in idx.imports.get(m.split(".")[0], []):
                    aliases.add(alias)
                    ev.append(Evidence(file, line, idx.snippet(file, line, 0), kind))
    tails = {s.rstrip("()").split(".")[-1] for s in intel.vulnerable_symbols if s != "*"}
    tails = {t for t in tails if re.match(r"^[A-Za-z_]\w+$", t) and t.lower() not in GENERIC}
    seen = set()
    for file, line, name in idx.calls:
        base = name.split("[")[0]
        head, last = base.split(".")[0], base.split(".")[-1]
        if (head in aliases or last in tails) and (file, line) not in seen:
            seen.add((file, line))
            ev.append(Evidence(file, line, idx.snippet(file, line), "call"))
    for t in tails:  # Jinja filters named by the advisory (xmlattr, urlize, attr, …)
        for file, line in idx.filters.get(t, [])[:5]:
            ev.append(Evidence(file, line, idx.snippet(file, line, 0), "template"))
    return ev[:40]


def template_summary(idx: PyIndex) -> str:
    if not idx.templates:
        return "no Jinja templates found"
    names = sorted(idx.filters, key=lambda n: -len(idx.filters[n]))
    return (f"{len(idx.templates)} Jinja templates; filters used in them: "
            + (", ".join(names[:60]) or "none"))


def context_sources(idx: PyIndex, ev: list[Evidence], budget: int = 9000) -> str:
    """Full (numbered) source of the files that hold evidence, smallest first, within budget.
    Lets the model see things a call site alone hides: where arguments come from, constants
    such as a hard-coded secret, wrappers around the call."""
    files = sorted({e.file for e in ev if e.file in idx.sources}, key=lambda f: len(idx.sources.get(f, [])))
    out, used = [], 0
    for f in files:
        lines = idx.sources.get(f, [])
        if len(lines) > 400:
            continue
        body = "\n".join(f"{i + 1:>4}| {t}" for i, t in enumerate(lines))
        if used + len(body) > budget:
            continue
        out.append(f"### {f}\n{body}")
        used += len(body)
    return "\n\n".join(out)


SYSTEM = """You are a senior application-security engineer doing reachability analysis.
Decide whether the given codebase can actually trigger a known vulnerability in one of its
dependencies. Use ONLY the evidence given. Rules:
- reachable: there is a concrete code path that uses the vulnerable symbol/feature in the
  vulnerable way (cite the exact file:line of that call), or the flaw triggers on any normal
  use and the package is used (directly, or indirectly through an imported package that
  wraps it, e.g. requests -> urllib3; then cite the wrapper's call site).
- not_reachable: the vulnerable symbol/feature/option is never used, or only used in a safe
  way (e.g. yaml.safe_load; jwt.decode with an explicit algorithms list that rules out the
  confused algorithm), or the package is neither imported nor wrapped by an imported package.
- uncertain: evidence is genuinely insufficient (dynamic dispatch, config you cannot see).
Judge the code as written: a precondition you can see is absent (no proxy configured, no
sandbox used, no such filter in any template) means not_reachable, not uncertain. Consider
where inputs come from (module docstrings and comments describe data sources).
A package can be imported directly for one thing (e.g. werkzeug.security) and ALSO be driven by
a framework that wraps it: a web framework (Flask -> Werkzeug, Django, Starlette) runs request
parsing (forms, multipart, cookies, headers, routing) for every incoming request, whether or not
the app touches that API, so parser flaws are reachable from the network in any app that serves
HTTP with it. Debug-only features (Werkzeug debugger) count only if enabled in production config.
For indirect use, reason about how the wrapper calls the vulnerable package internally, not
only the arguments visible at the call site (e.g. requests always reads response bodies
through urllib3's streaming API and follows redirects by default, even without stream=True).
A dependency marked [auto-used: …] is exercised on normal use of the wrapper that loads it
(e.g. urllib3 decompresses brotli responses from any server the app fetches): judge it as if the
wrapper's call sites called it directly.
Several advisories may be given together because they share the vulnerable feature and
preconditions: give ONE verdict that holds for all of them.
Deployment platform: {deploy_os}. Flaws limited to another OS are not_reachable.
Cite only file:line locations that appear in the evidence or sources. Rationale under 80 words."""

USER_TMPL = """{head}
Vulnerable symbols/features: {syms}
Trigger conditions:
{trig}
Attack vector: {vector}

Third-party modules imported by the codebase: {imports}
How {pkg} is reached when not imported directly (pinned deps that depend on it): {wrappers}
Templates: {templates}

Static evidence (imports, imports of packages that wrap {pkg}, candidate call sites):
{evidence}

Full source of the files above:
{sources}

Return JSON: {{"verdict": "reachable"|"not_reachable"|"uncertain", "confidence": 0.0-1.0,
 "rationale": str, "cited": ["file:line", ...]}}"""


def heuristic(idx: PyIndex, f: Finding, intel: Intel, ev: list[Evidence]) -> Reachability:
    imports = [e for e in ev if e.kind in ("import", "import-via")]
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


def analyze(idx: PyIndex, f: Finding, intel: Intel, llm: LLM, deps: list | None = None,
            deploy_os: str = "linux") -> Reachability:
    return analyze_group(idx, f, [intel], llm, deps, deploy_os)[0]


def _platform_skip(intel: Intel, deploy_os: str) -> str:
    if intel.platforms and deploy_os.lower() not in intel.platforms:
        return (f"Only affects {'/'.join(p.capitalize() for p in intel.platforms)}; this project deploys on "
                f"{deploy_os.capitalize()} (change with --deploy-os).")
    return ""


def analyze_group(idx: PyIndex, f: Finding, intels: list[Intel], llm: LLM, deps: list | None = None,
                  deploy_os: str = "linux") -> list[Reachability]:
    """One verdict for advisories of the same package that share the vulnerable feature and
    preconditions, so near-duplicates can't get contradictory answers."""
    wrappers = wrappers_for(idx, f, deps or [])
    dev = dev_only(idx, f, wrappers)
    lead = intels[0]
    merged = Intel(lead.vuln_id, vulnerable_symbols=list(dict.fromkeys(s for i in intels for s in i.vulnerable_symbols)))
    ev = gather(idx, f, merged, wrappers)
    ids = [i.vuln_id for i in intels]

    def fan(base: Reachability) -> list[Reachability]:
        out = []
        for i in intels:
            r = Reachability(i.vuln_id, base.verdict, base.confidence, base.rationale, list(base.evidence),
                             base.method, list(base.cited), [x for x in ids if x != i.vuln_id], dev)
            out.append(r)
        return out

    skip = _platform_skip(lead, deploy_os)
    if skip and all(_platform_skip(i, deploy_os) for i in intels):
        return fan(Reachability(lead.vuln_id, "not_reachable", 0.9, skip, ev, "platform"))
    if not llm.online:
        return fan(heuristic(idx, f, merged, ev))
    evtext = "\n".join(f"[{e.kind}] {e.file}:{e.line}\n{e.snippet}" for e in ev) or "(none found)"
    if len(intels) == 1:
        head = f"Vulnerability {lead.vuln_id} in {f.dep.name} {f.dep.version}"
        trig = lead.trigger_conditions[:800]
        vector = lead.attack_vector[:300]
    else:
        summ = {v.id: v.summary for v in f.vulns}
        head = (f"{len(intels)} related advisories in {f.dep.name} {f.dep.version} (same vulnerable feature, "
                "judge together):\n" + "\n".join(f"- {i.vuln_id}: {summ.get(i.vuln_id, '')}" for i in intels))
        trig = "\n".join(f"- {i.vuln_id}: {i.trigger_conditions[:500]}" for i in intels)
        vector = "; ".join(dict.fromkeys(i.attack_vector[:200] for i in intels if i.attack_vector))
    if dev:
        evtext = f"NOTE: {f.dep.name} is {dev}.\n" + evtext
    user = USER_TMPL.format(head=head, pkg=f.dep.name,
                            syms=", ".join(merged.vulnerable_symbols[:20]), trig=trig, vector=vector,
                            imports=", ".join(idx.third_party_imports()[:60]),
                            wrappers=(("imported directly; " if any(e.kind == "import" for e in ev) else "")
                                      + (("also used through: " + ", ".join(wrappers)) if wrappers
                                         else "no imported pinned dependency wraps it")),
                            templates=template_summary(idx),
                            evidence=evtext[:8000], sources=context_sources(idx, ev) or "(none)")
    try:
        d = llm.chat_json("reason", SYSTEM.format(deploy_os=deploy_os.capitalize()), user, max_tokens=6000,
                          want=("verdict",), tag="reach", temperature=0.0)
    except LLMError:
        return fan(heuristic(idx, f, merged, ev))
    verdict = d.get("verdict") if d.get("verdict") in {"reachable", "not_reachable", "uncertain"} else "uncertain"
    cited = [c for c in (d.get("cited") or []) if isinstance(c, str)]
    valid = [c for c in cited if _cite_ok(idx, c)]
    known = {(e.file, e.line) for e in ev}
    for c in valid:  # a cited line outside the gathered evidence becomes evidence itself
        file, line = c.rsplit(":", 1)
        if (file, int(line)) not in known:
            ev.append(Evidence(file, int(line), idx.snippet(file, int(line)), "cited"))
    order = {c: i for i, c in enumerate(valid)}
    ev.sort(key=lambda e: order.get(f"{e.file}:{e.line}", len(order)))
    try:
        conf = float(d.get("confidence", 0.5))
    except (TypeError, ValueError):
        conf = 0.5
    r = Reachability(lead.vuln_id, verdict, max(0.0, min(1.0, conf)), str(d.get("rationale") or ""), ev)
    r.cited = valid
    if verdict == "reachable" and not valid:
        r.confidence = min(r.confidence, 0.6)  # an uncited "reachable" is weaker evidence
    return fan(r)


GROUP_SYSTEM = """You cluster security advisories of ONE package. Put advisories in the same
group only when the same code would be affected by all of them or by none: same vulnerable
function/feature AND same preconditions (e.g. several CVEs for 'safe_join on Windows', or several
root-certificate removals from a CA bundle). Advisories for different functions, or for the same
function under different conditions (e.g. JWT algorithm confusion vs. unknown 'crit' headers),
must be in different groups. Different flaws that merely live in the same module or class are
NOT siblings (e.g. requests .netrc leak vs. Proxy-Authorization leak vs. temp-file reuse). When
unsure, keep them apart; most advisories are singletons."""


_STOP = {"a", "an", "the", "in", "of", "to", "via", "and", "or", "for", "with", "when", "on", "is", "can",
         "be", "by", "vulnerable", "vulnerability", "allows", "possible", "may", "does", "not", "its", "has"}


def _tokens(text: str, pkg: str) -> set:
    return {t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in _STOP and t not in pkg.split("-")}


def _syms(i: Intel) -> set:
    """Distinctive symbol tails (SandboxedEnvironment, safe_join …); generic ones (decode) dropped."""
    tails = {re.split(r"[./ ]", s.strip().rstrip("()"))[-1].lower() for s in i.vulnerable_symbols if s != "*"}
    return {t for t in tails if t and t not in GENERIC}


def _overlap(a: set, b: set) -> float:
    return len(a & b) / min(len(a), len(b)) if a and b else 0.0


def compatible(a: Intel, b: Intel, summ: dict, pkg: str) -> bool:
    """Deterministic guard on model grouping: siblings must share their distinctive vulnerable
    symbols or most of their summary wording."""
    ta, tb = _tokens(summ.get(a.vuln_id, ""), pkg), _tokens(summ.get(b.vuln_id, ""), pkg)
    return _overlap(_syms(a), _syms(b)) >= 0.6 or (len(ta & tb) >= 2 and _overlap(ta, tb) >= 0.5)


def group_advisories(f: Finding, intels: list[Intel], llm: LLM) -> list[list[Intel]]:
    """Cluster one package's advisories into sibling groups (one Lightning call per package)."""
    if len(intels) < 2:
        return [[i] for i in intels]
    by_id = {i.vuln_id: i for i in intels}
    summ = {v.id: v.summary for v in f.vulns}
    groups: list[list[str]] = []
    if llm.online:
        listing = "\n".join(f"- {i.vuln_id}: {summ.get(i.vuln_id, '')} | symbols: {', '.join(i.vulnerable_symbols[:6])}"
                            f" | trigger: {i.trigger_conditions[:250]}" for i in intels)
        try:
            d = llm.chat_json("reason", GROUP_SYSTEM, f"Package {f.dep.name} {f.dep.version}\n{listing}\n\n"
                              'Return JSON: {"groups": [["ADVISORY-ID", ...], ...]}', max_tokens=4000,
                              want=("groups",), tag="group", temperature=0.0)
            for g in d.get("groups") or []:
                if isinstance(g, list):
                    groups.append([x for x in g if isinstance(x, str)])
        except LLMError:
            groups = []
    else:  # offline: identical normalized summaries only
        seen: dict = {}
        for i in intels:
            key = re.sub(r"\W+", " ", summ.get(i.vuln_id, i.vuln_id).lower()).strip()
            seen.setdefault(key, []).append(i.vuln_id)
        groups = list(seen.values())
    used, out = set(), []
    for g in groups:
        ids = [x for x in dict.fromkeys(g) if x in by_id and x not in used]
        # split into clusters whose members are pairwise compatible and share a platform scope
        clusters: list[list[str]] = []
        for x in ids:
            for c in clusters:
                if all(by_id[x].platforms == by_id[y].platforms and compatible(by_id[x], by_id[y], summ, f.dep.name)
                       for y in c):
                    c.append(x)
                    break
            else:
                clusters.append([x])
        for c in clusters:
            used.update(c)
            out.append([by_id[x] for x in c])
    out += [[i] for i in intels if i.vuln_id not in used]
    return out


def _cite_ok(idx: PyIndex, c: str) -> bool:
    m = re.match(r"^(.+):(\d+)$", c.strip())
    if not m:
        return False
    lines = idx.sources.get(m.group(1)) or idx.templates.get(m.group(1))
    return bool(lines) and 1 <= int(m.group(2)) <= len(lines)
