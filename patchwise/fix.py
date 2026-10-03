"""Verified fixes: bump vulnerable pins to the minimal safe version in a sandboxed copy,
run the project's tests, and if something breaks, let Nemotron Ultra repair the code
(with Tavily-sourced migration notes) until tests pass or the budget is exhausted."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings
from .llm import LLM, LLMError
from .research import Tavily
from .scan import Finding, norm

IGNORE = shutil.ignore_patterns(".git", ".venv", "venv", "node_modules", "__pycache__", ".patchwise",
                                "*.pyc", ".pytest_cache")


@dataclass
class TestRun:
    ok: bool
    summary: str
    output: str


@dataclass
class FixResult:
    upgrades: dict = field(default_factory=dict)      # pkg -> (old, new)  security fixes
    compat_bumps: dict = field(default_factory=dict)  # pkg -> (old, new)  needed to stay installable
    baseline: TestRun | None = None
    final: TestRun | None = None
    repairs: list = field(default_factory=list)       # [{iteration, files, rationale, tests_ok}]
    diff: str = ""
    status: str = "not_run"   # verified | verified_with_code_changes | tests_fail | no_tests | skipped
    notes: list = field(default_factory=list)


def _run(cmd: str, cwd: Path, env: dict | None = None, timeout: int = 900) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, **(env or {})})
    out = p.stdout + "\n" + p.stderr
    if len(out) > 14000:
        out = out[:3000] + "\n…[truncated]…\n" + out[-11000:]
    return p.returncode, out


def next_release(pkg: str, after: str) -> str | None:
    """Next non-prerelease version on PyPI strictly above `after` (used when a minimal fix
    version can't be built on this Python)."""
    import httpx
    from packaging.version import InvalidVersion, Version
    try:
        rel = httpx.get(f"https://pypi.org/pypi/{pkg}/json", timeout=20).json().get("releases", {})
    except Exception:
        return None
    cur, best = Version(after), None
    for v, files in rel.items():
        try:
            pv = Version(v)
        except InvalidVersion:
            continue
        if pv.is_prerelease or pv <= cur or not files or all(f.get("yanked") for f in files):
            continue
        if best is None or pv < best:
            best = pv
    return str(best) if best else None


_BUILD_FAIL = re.compile(r"Failed to (?:download and )?build `([A-Za-z0-9_.\-]+)==([^`]+)`")


def _summ(out: str) -> str:
    m = re.findall(r"=+ (.*(?:passed|failed|error).*?) =+", out)
    return m[-1] if m else out.strip().splitlines()[-1][:200] if out.strip() else ""


class Sandbox:
    def __init__(self, repo: Path, work: Path, settings: Settings):
        self.repo, self.work, self.s = repo, work, settings
        if work.exists():
            shutil.rmtree(work)
        shutil.copytree(repo, work, ignore=IGNORE)
        self.venv = work / ".venv"

    def reqs(self) -> list[Path]:
        return sorted(p for p in self.work.rglob("requirements*.txt") if ".venv" not in p.parts)

    def install(self) -> tuple[bool, str]:
        if self.venv.exists():
            shutil.rmtree(self.venv)
        pyv = self.work / ".python-version"
        py = f" --python {pyv.read_text().strip()}" if pyv.exists() else ""
        code, out = _run(f"uv venv -q{py} {self.venv}", self.work)
        if code:
            return False, out
        args = " ".join(f"-r {p}" for p in self.reqs())
        code, out = _run(f"uv pip install -q --python {self.venv}/bin/python {args} pytest", self.work)
        return code == 0, out

    def test(self) -> TestRun:
        ok, out = self.install()
        if not ok:
            return TestRun(False, "dependency install failed", out)
        cmd = self.s.test_command or f"{self.venv}/bin/python -m pytest -q --no-header -p no:cacheprovider"
        code, out = _run(cmd, self.work, env={"VIRTUAL_ENV": str(self.venv)})
        if code == 5:  # pytest: no tests collected
            return TestRun(True, "no tests collected", out)
        return TestRun(code == 0, _summ(out), out)

    def set_pins(self, pins: dict[str, str]) -> None:
        pat = re.compile(r"^(\s*)([A-Za-z0-9_.\-\[\]]+)(\s*==\s*)([^\s#;]+)(.*)$")
        for p in self.reqs():
            lines = p.read_text().splitlines()
            for i, line in enumerate(lines):
                m = pat.match(line)
                if m and norm(m.group(2)) in pins:
                    lines[i] = f"{m.group(1)}{m.group(2)}{m.group(3)}{pins[norm(m.group(2))]}{m.group(5)}"
            p.write_text("\n".join(lines) + "\n")

    def current_pins(self) -> dict[str, str]:
        pins = {}
        for p in self.reqs():
            for line in p.read_text().splitlines():
                m = re.match(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([^\s#;]+)", line)
                if m:
                    pins[norm(m.group(1))] = m.group(2)
        return pins

    def compatible_bumps(self, security: dict[str, str]) -> tuple[dict[str, str], str]:
        """Security pins are fixed; every other direct pin may move *up* by the smallest amount
        needed to stay installable (uv resolver, lowest-direct strategy)."""
        cur = self.current_pins()
        lines = [f"{k}=={v}" if k in security else f"{k}>={v}" for k, v in cur.items()]
        tmp = self.work / ".patchwise-resolve.in"
        tmp.write_text("\n".join(lines) + "\n")
        pyv = self.work / ".python-version"
        py = f" --python-version {pyv.read_text().strip()}" if pyv.exists() else ""
        code, out = _run(f"uv pip compile -q --no-header --resolution lowest-direct{py} {tmp.name}", self.work)
        tmp.unlink(missing_ok=True)
        if code:
            return {}, out
        resolved = {}
        for line in out.splitlines():
            m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s]+)", line.strip())
            if m:
                resolved[norm(m.group(1))] = m.group(2)
        return {k: resolved[k] for k in cur if k not in security and k in resolved and resolved[k] != cur[k]}, ""

    def diff(self) -> str:
        code, out = _run(f"git diff --no-index --no-color -- {self.repo} {self.work} || true", self.work)
        out = out.replace(str(self.repo) + "/", "").replace(str(self.work) + "/", "")
        # drop venv/cache noise
        chunks = re.split(r"(?=^diff --git )", out, flags=re.M)
        keep = [c for c in chunks if c.startswith("diff --git") and ".venv" not in c.splitlines()[0]
                and "__pycache__" not in c.splitlines()[0] and ".pytest_cache" not in c.splitlines()[0]]
        return "".join(keep)

    def apply_edits(self, edits: list[dict]) -> list[str]:
        changed = []
        for e in edits:
            rel = str(e.get("file", ""))
            target = (self.work / rel).resolve()
            if not str(target).startswith(str(self.work.resolve())) or ".venv" in target.parts:
                continue  # never write outside the sandbox
            if not target.exists() or "requirements" in target.name:
                continue
            src = target.read_text()
            search, replace = e.get("search", ""), e.get("replace", "")
            if search and search in src:
                target.write_text(src.replace(search, replace, 1))
                changed.append(rel)
        return changed


REPAIR_SYSTEM = """You are an expert Python engineer performing a security dependency upgrade.
The dependency pins were raised to patched versions and the test suite now fails. Modify the
APPLICATION code (never tests, never requirements, never weaken security) so it works with the
new versions. Make minimal, idiomatic changes. Each edit is an exact search/replace on a file;
'search' must be copied verbatim from the file and be unique."""

REPAIR_TMPL = """Upgrades applied: {upgrades}

Migration notes from the web:
{notes}

Failing test output (tail):
{output}

Relevant source files:
{files}

Return JSON: {{"rationale": str, "edits": [{{"file": str, "search": str, "replace": str}}]}}"""


def _relevant_files(sb: Sandbox, output: str, limit: int = 6) -> dict[str, str]:
    names = []
    for m in re.findall(r"([\w./\-]+\.py):\d+", output):
        rel = m.replace(str(sb.work) + "/", "")
        if ".venv" in rel or rel.startswith("/") or rel in names:
            continue
        if (sb.work / rel).exists():
            names.append(rel)
    if not names:
        names = [str(p.relative_to(sb.work)) for p in sb.work.rglob("*.py") if ".venv" not in p.parts][:limit]
    return {n: (sb.work / n).read_text()[:6000] for n in names[:limit]}


def migration_notes(tavily: Tavily | None, upgrades: dict) -> str:
    if not tavily or not tavily.enabled:
        return "(none)"
    out = []
    for pkg, (old, new) in list(upgrades.items())[:3]:
        try:
            for r in tavily.search(f"{pkg} {old} to {new} breaking changes migration guide changelog", 3):
                out.append(f"- {r['url']}: {r.get('content', '')[:700]}")
        except Exception as e:  # research is best-effort
            out.append(f"(search failed for {pkg}: {e})")
    return "\n".join(out)[:5000]


def fix(repo: Path, findings: list[Finding], settings: Settings, llm: LLM, tavily: Tavily | None,
        log=print) -> FixResult:
    res = FixResult()
    pins = {f.dep.name: f.min_fix for f in findings if f.dep.ecosystem == "PyPI" and f.min_fix}
    res.upgrades = {f.dep.name: (f.dep.version, f.min_fix) for f in findings
                    if f.dep.ecosystem == "PyPI" and f.min_fix}
    if not pins:
        res.status = "skipped"
        res.notes.append("No PyPI findings with a known fixed version.")
        return res
    sb = Sandbox(repo, repo / ".patchwise" / "work", settings)
    log("  running baseline tests…")
    res.baseline = sb.test()
    if not res.baseline.ok:
        res.notes.append(f"Baseline tests already failing ({res.baseline.summary}); results are advisory.")
    sb.set_pins(pins)
    log(f"  upgraded pins: {', '.join(f'{k}->{v}' for k, v in pins.items())}; re-running tests…")
    run = sb.test()
    resolved_once = False
    for _ in range(8):  # make the upgraded set installable before judging tests
        if run.ok or run.summary != "dependency install failed":
            break
        m = _BUILD_FAIL.search(run.output)
        if m and norm(m.group(1)) in pins:
            pkg = norm(m.group(1))
            nxt = next_release(pkg, m.group(2))
            if not nxt:
                break
            log(f"  {pkg}=={m.group(2)} does not build on this Python; trying {nxt}")
            res.notes.append(f"{pkg} {m.group(2)} fails to build on this Python; used {nxt} instead.")
            pins[pkg] = nxt
            res.upgrades[pkg] = (res.upgrades[pkg][0], nxt)
            sb.set_pins({pkg: nxt})
        elif not resolved_once:
            resolved_once = True
            bumps, err = sb.compatible_bumps(pins)
            if not bumps:
                if err:
                    res.notes.append("Resolver could not find a compatible set: " + err[-500:])
                break
            log(f"  resolver: compatible bumps needed: {', '.join(f'{k}->{v}' for k, v in bumps.items())}")
            cur = sb.current_pins()
            for k, v in bumps.items():
                res.compat_bumps[k] = (cur.get(k), v)
            sb.set_pins(bumps)
        else:
            break
        run = sb.test()
    it = 0
    notes = None
    while not run.ok and it < settings.max_repair_iterations and llm.online:
        it += 1
        notes = notes or migration_notes(tavily, res.upgrades)
        files = _relevant_files(sb, run.output)
        user = REPAIR_TMPL.format(
            upgrades=", ".join(f"{k} {a}->{b}" for k, (a, b) in res.upgrades.items()), notes=notes,
            output=run.output[-6000:],
            files="\n\n".join(f"### {n}\n```python\n{c}\n```" for n, c in files.items()))
        try:
            d = llm.chat_json("deep", REPAIR_SYSTEM, user, max_tokens=4000)
        except LLMError as e:
            res.notes.append(f"repair iteration {it} failed: {e}")
            break
        changed = sb.apply_edits(d.get("edits") or [])
        log(f"  repair {it}: edited {changed or 'nothing'}; re-running tests…")
        run = sb.test()
        res.repairs.append({"iteration": it, "files": changed, "rationale": d.get("rationale", ""),
                            "tests_ok": run.ok, "summary": run.summary})
        if not changed:
            break
    res.final = run
    res.diff = sb.diff()
    if run.ok and run.summary == "no tests collected":
        res.status = "no_tests"
    elif run.ok:
        res.status = "verified_with_code_changes" if res.repairs else "verified"
    else:
        res.status = "tests_fail"
    return res
