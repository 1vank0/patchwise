"""Verified fixes: bump vulnerable pins to the minimal safe version in a sandboxed copy,
run the project's tests, and if something breaks, let Nemotron Ultra repair the code
(with Tavily-sourced migration notes) until tests pass or the budget is exhausted."""
from __future__ import annotations

import difflib
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings
from .llm import LLM, LLMError
from .research import Tavily
from .scan import Finding, is_requirements_file, norm

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".patchwise", ".pytest_cache",
             ".tox", ".mypy_cache", "build", "dist", ".eggs"}
IGNORE = shutil.ignore_patterns(*SKIP_DIRS, "*.pyc", "*.egg-info")


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
    patch_tests: TestRun | None = None
    review: dict | None = None   # post-fix review of the code changes: {"ok": bool, "concerns": [...]}
    patch_applies: bool = False   # fix.patch re-applied to a pristine copy with git apply --check
    status: str = "not_run"   # verified | verified_with_code_changes | tests_pass_needs_review |
    #                           tests_pass_patch_unverified | tests_fail | no_tests | skipped
    notes: list = field(default_factory=list)


SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH)", re.I)


def safe_env(extra: dict | None = None) -> dict:
    """Environment for project code (installs, tests): never hand API keys or tokens to it."""
    env = {k: v for k, v in os.environ.items() if not SECRET_ENV.search(k)}
    env.update(extra or {})
    return env


def _run(cmd: str, cwd: Path, env: dict | None = None, timeout: int = 900) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True, timeout=timeout,
                       env=safe_env(env))
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
    if m:  # pytest
        return m[-1]
    ran = re.findall(r"^Ran (\d+ tests?) in ([\d.]+s)", out, re.M)  # unittest / nose2
    if ran:
        tail = re.findall(r"^(OK.*|FAILED \(.*\))$", out, re.M)
        return f"{ran[-1][0]} in {ran[-1][1]}: {tail[-1] if tail else '?'}"
    return out.strip().splitlines()[-1][:200] if out.strip() else ""


class Sandbox:
    def __init__(self, repo: Path, work: Path, settings: Settings):
        self.repo, self.work, self.s = repo, work, settings
        if work.exists():
            shutil.rmtree(work)
        shutil.copytree(repo, work, ignore=IGNORE)
        self.venv = work / ".venv"

    def reqs(self) -> list[Path]:
        """Every requirements file (pins are edited in all of them)."""
        return sorted(p for p in self.work.rglob("*.txt") if ".venv" not in p.parts
                      and is_requirements_file(p, self.work))

    def install_reqs(self) -> list[Path]:
        """The files installed for testing: --requirements if given, else all of them."""
        if self.s.install_requirements:
            return [self.work / r for r in self.s.install_requirements]
        return self.reqs()

    def python_version(self) -> str | None:
        if self.s.python_version:
            return self.s.python_version
        pyv = self.work / ".python-version"
        return pyv.read_text().strip() if pyv.exists() else None

    def install(self) -> tuple[bool, str]:
        if self.venv.exists():
            shutil.rmtree(self.venv)
        pv = self.python_version()
        py = f" --python {pv}" if pv else ""
        code, out = _run(f"uv venv -q{py} {self.venv}", self.work)
        if code:
            return False, out
        args = " ".join(f"-r {p}" for p in self.install_reqs())
        drop = set(getattr(self, "dropped_extras", []))
        extra = " ".join(shlex_quote(re.split(r"[=<>!~;]", p)[0] if p in drop else p)
                         for p in self.s.extra_test_packages)
        code, out = _run(f"uv pip install -q --python {self.venv}/bin/python {args} pytest {extra}", self.work)
        return code == 0, out

    def test(self) -> TestRun:
        ok, out = self.install()
        if not ok:
            return TestRun(False, "dependency install failed", out)
        cmd = self.s.test_command or f"{self.venv}/bin/python -m pytest -q --no-header -p no:cacheprovider"
        code, out = _run(cmd, self.work, env={"VIRTUAL_ENV": str(self.venv),
                                              "PATH": f"{self.venv}/bin:{os.environ.get('PATH', '')}"},
                         timeout=self.s.test_timeout)
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

    def _resolve(self, lines: list[str]) -> tuple[dict[str, str] | None, str]:
        tmp = self.work / ".patchwise-resolve.in"
        tmp.write_text("\n".join(lines) + "\n")
        pv = self.python_version()
        py = f" --python-version {pv}" if pv else ""
        code, out = _run(f"uv pip compile -q --no-header --resolution lowest-direct{py} {tmp.name}", self.work)
        tmp.unlink(missing_ok=True)
        if code:
            return None, out
        resolved = {}
        for line in out.splitlines():
            m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s]+)", line.strip())
            if m:
                resolved[norm(m.group(1))] = m.group(2)
        return resolved, ""

    def compatible_bumps(self, security: dict[str, str]) -> tuple[dict[str, str], dict[str, str], str]:
        """Make the upgraded set installable with the smallest moves (uv, lowest-direct).
        Pass 1: security pins fixed at their minimal safe version, other direct pins may only
        move up. Pass 2 (if two security minimums conflict, e.g. httpie 3.2.3 caps requests
        below the requests fix): security pins become `>= minimal safe version`, so the
        resolver may raise one of them further. Never goes below a safe version.
        Returns (compat bumps for non-security pins, raised security pins, error)."""
        cur = self.current_pins()
        extras = [p for p in self.s.extra_test_packages if re.match(r"^[A-Za-z0-9_.\-\[\]]+\s*[=<>!~]", p)]
        strict = [f"{k}=={v}" if k in security else f"{k}>={v}" for k, v in cur.items()] + extras
        resolved, err = self._resolve(strict)
        raised: dict[str, str] = {}
        if resolved is None:
            relaxed = [f"{k}>={v}" for k, v in cur.items()]
            resolved, err2 = self._resolve(relaxed + extras)
            if resolved is None and extras:
                # test-only pins (--with) exist to make the OLD set installable; they must not
                # block a security fix, so drop their version constraints and retry.
                resolved, err2 = self._resolve(relaxed)
                if resolved is not None:
                    self.dropped_extras = extras
            if resolved is None:
                return {}, {}, err
            raised = {k: resolved[k] for k in security if k in resolved and resolved[k] != security[k]}
        bumps = {k: resolved[k] for k in cur if k not in security and k in resolved and resolved[k] != cur[k]}
        return bumps, raised, ""

    def _files(self, root: Path) -> set[str]:
        out = set()
        for p in root.rglob("*"):
            rel = p.relative_to(root)
            if p.is_file() and not any(part in SKIP_DIRS or part.endswith(".egg-info") for part in rel.parts) \
                    and p.suffix != ".pyc" and not rel.name.startswith(".patchwise-"):
                out.add(str(rel))
        return out

    def diff(self) -> str:
        """Unified diff (a/ b/ paths, git-apply compatible) of every text file the sandbox
        changed relative to the original repo."""
        chunks = []
        for rel in sorted(self._files(self.work) | self._files(self.repo)):
            a, b = self.repo / rel, self.work / rel
            try:
                ta = a.read_text() if a.exists() else ""
                tb = b.read_text() if b.exists() else ""
            except UnicodeDecodeError:
                continue
            if ta == tb or not b.exists():
                continue  # the fixer never deletes files; absent = ignored by the copy
            d = list(difflib.unified_diff(ta.splitlines(True), tb.splitlines(True),
                                          f"a/{rel}", f"b/{rel}"))
            if d:
                if not d[-1].endswith("\n"):
                    d[-1] += "\n\\ No newline at end of file\n"
                chunks.append(f"diff --git a/{rel} b/{rel}\n" + "".join(
                    x if x.endswith("\n") else x + "\n\\ No newline at end of file\n" for x in d))
        return "".join(chunks)

    def changed_files(self) -> set[str]:
        out = set()
        for rel in self._files(self.work):
            a, b = self.repo / rel, self.work / rel
            try:
                if not a.exists() or a.read_bytes() != b.read_bytes():
                    out.add(rel)
            except OSError:
                continue
        return out

    def snapshot(self) -> dict[str, bytes]:
        return {rel: (self.work / rel).read_bytes() for rel in self.changed_files()}

    def restore(self, snap: dict[str, bytes]) -> None:
        for rel in self.changed_files() | set(snap):
            if rel in snap:
                (self.work / rel).write_bytes(snap[rel])
            elif (self.repo / rel).exists():
                (self.work / rel).write_bytes((self.repo / rel).read_bytes())
            else:
                (self.work / rel).unlink(missing_ok=True)

    def verify_patch(self, patch: str) -> tuple[bool, str, "TestRun | None"]:
        """Independent check of the deliverable: apply fix.patch with `git apply` to a fresh,
        pristine copy of the repo, reinstall from scratch and re-run the tests there."""
        if not patch:
            return False, "empty patch", None
        with tempfile.TemporaryDirectory(prefix="patchwise-verify-") as tmp:
            fresh = Sandbox(self.repo, Path(tmp) / "r", self.s)
            fresh.dropped_extras = getattr(self, "dropped_extras", [])
            pf = Path(tmp) / "fix.patch"
            pf.write_text(patch)
            code, out = _run(f"git apply --verbose {pf}", fresh.work)
            if code:
                return False, out.strip()[-500:], None
            return True, out.strip()[-300:], fresh.test()

    def apply_edits(self, edits: list[dict], rejected: list | None = None) -> list[str]:
        changed = []
        for e in edits:
            rel = str(e.get("file", ""))
            target = (self.work / rel).resolve()
            if not str(target).startswith(str(self.work.resolve())) or ".venv" in target.parts:
                continue  # never write outside the sandbox
            if not target.exists() or "requirements" in target.name:
                continue
            src = target.read_text()
            search, replace = str(e.get("search", "")), str(e.get("replace", ""))
            bad = security_regressions(search, replace)
            if bad:  # a dependency upgrade must never make the code less safe
                if rejected is not None:
                    rejected.append({"file": rel, "patterns": bad, "replace": replace[:200]})
                continue
            new = None
            if search and search in src:
                new = src.replace(search, replace, 1)
            elif search:
                new = fuzzy_replace(src, search, replace)
            if new is not None and target.suffix == ".py" and not _parses(new):
                new = None  # never leave a module unparsable
            if new is not None:
                target.write_text(new)
                changed.append(rel)
            elif rejected is not None:
                rejected.append({"file": rel, "patterns": [], "unmatched": True, "replace": search[:120]})
        return changed


def _indent(s: str) -> int:
    return len(s) - len(s.lstrip(" \t"))


def _parses(src: str) -> bool:
    import ast
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ast.parse(src)
        return True
    except (SyntaxError, ValueError):
        return False


def fuzzy_replace(src: str, search: str, replace: str) -> str | None:
    """Whitespace-tolerant search/replace for model edits whose indentation is off: match the
    search block line-by-line ignoring leading/trailing whitespace (must be unique), then
    re-indent the replacement relative to the indentation actually found in the file."""
    s_lines = [ln for ln in search.splitlines() if ln.strip()]
    if not s_lines:
        return None
    lines = src.splitlines(keepends=True)
    hits = []
    for i in range(len(lines)):
        if lines[i].strip() != s_lines[0].strip():
            continue
        j, k, idx = i, 0, []
        while k < len(s_lines) and j < len(lines):
            if not lines[j].strip():
                j += 1
                continue
            if lines[j].strip() != s_lines[k].strip():
                break
            idx.append(j)
            j, k = j + 1, k + 1
        if k == len(s_lines):
            hits.append((i, j, idx))
    if len(hits) != 1:
        return None
    start, end, idx = hits[0]
    file_ind = [_indent(lines[x]) for x in idx]
    out, used = [], set()
    last_model, last_file = _indent(s_lines[0]), file_ind[0]
    for r in replace.splitlines():
        if not r.strip():
            out.append("\n")
            continue
        k = next((k for k, sl in enumerate(s_lines) if k not in used and sl.strip() == r.strip()), None)
        if k is not None:
            used.add(k)
            ind, last_model, last_file = file_ind[k], _indent(s_lines[k]), file_ind[k]
        else:
            ind = max(0, last_file + _indent(r) - last_model)
        out.append(" " * ind + r.strip() + "\n")
    return "".join(lines[:start]) + "".join(out) + "".join(lines[end:])


# Patterns a repair must never introduce (it may keep them if they were already there).
DANGEROUS = {
    "yaml unsafe loader": r"\byaml\.(unsafe_load(_all)?|UnsafeLoader|Loader\b)|Loader\s*=\s*(yaml\.)?(Unsafe)?Loader\b",
    "TLS verification disabled": r"verify\s*=\s*False|CERT_NONE|_create_unverified_context",
    "autoescape disabled": r"autoescape\s*=\s*False|\|\s*safe\b",
    "JWT signature/alg checks disabled": r"verify_signature['\"]?\s*[:=]\s*False|algorithms\s*=\s*\[?\s*['\"]none",
    "arbitrary code execution": r"\beval\(|\bexec\(|pickle\.loads?\(|marshal\.loads\(|shell\s*=\s*True",
}


def security_regressions(search: str, replace: str) -> list[str]:
    return [name for name, pat in DANGEROUS.items()
            if re.search(pat, replace) and not re.search(pat, search)]


REPAIR_SYSTEM = """You are an expert Python engineer performing a security dependency upgrade.
The dependency pins were raised to patched versions and the test suite now fails. Modify the
APPLICATION code (never tests, never requirements, never weaken security) so it works with the
new versions. Make minimal, idiomatic changes that use the new versions' public APIs (import
from the package that officially exports a name, not from internal modules that happen to
re-export it). Tests often stop at the first error, so fix EVERY usage in the shown files that
the upgrades break, not just the one in the traceback, but do NOT touch code that still works
on the new versions. Never make the code less safe: no yaml.unsafe_load/UnsafeLoader, no
verify=False, no autoescape=False, no disabling JWT checks, no eval/pickle. Such edits are
rejected automatically. If the failure happens INSIDE a third-party package (traceback in
site-packages) because that package is too old for the upgraded ones, do not monkeypatch it:
raise its pin instead via "pin_bumps" (an existing newer release; security pins cannot be
lowered). Each edit is an exact search/replace on
a file; 'search' must be copied verbatim from the CURRENT file content and be unique."""

REPAIR_TMPL = """Upgrades applied: {upgrades}

Migration notes from the web:
{notes}

Where names reported missing now live in the INSTALLED (upgraded) packages:
{hints}
{history}
Failing test output (tail):
{output}

Relevant source files:
{files}

Current pins: {pins}

Return JSON: {{"rationale": str, "edits": [{{"file": str, "search": str, "replace": str}}],
 "pin_bumps": {{"<package>": "<newer version>"}}}}
(pin_bumps is optional; use it only for non-security packages, see the rules.)"""


def _relevant_files(sb: Sandbox, output: str, upgraded: list[str], limit: int = 8) -> dict[str, str]:
    """Files named in the failing traceback first, then every non-test file that imports an
    upgraded package: tests often stop at the first collection error, so the model must see
    the other call sites the upgrade will break."""
    from .reach import PyIndex, module_names
    names = []
    for m in re.findall(r"([\w./\-]+\.py):\d+", output):
        rel = m.replace(str(sb.work) + "/", "")
        if ".venv" in rel or rel.startswith("/") or rel in names or _is_test(rel):
            continue
        if (sb.work / rel).exists():
            names.append(rel)
    idx = PyIndex.build(sb.work)
    for dist in upgraded:
        for mod in module_names(dist):
            for file, *_ in idx.imports.get(mod.split(".")[0], []):
                if file not in names and not _is_test(file):
                    names.append(file)
    if not names:
        names = [str(p.relative_to(sb.work)) for p in sb.work.rglob("*.py") if ".venv" not in p.parts][:limit]
    return {n: excerpt(sb, n, output) for n in names[:limit]}


def excerpt(sb: Sandbox, rel: str, output: str, full_limit: int = 9000, ctx: int = 25) -> str:
    """Whole file if small; otherwise the import header plus windows around the lines the
    traceback points at and around every line mentioning a name from the error messages
    (e.g. `localeselector`), so edits can target code deep inside large modules."""
    src = (sb.work / rel).read_text()
    if len(src) <= full_limit:
        return src
    lines = src.splitlines()
    want = set(range(min(len(lines), 60)))
    for m in re.finditer(re.escape(rel) + r"\"?, line (\d+)|" + re.escape(rel) + r":(\d+)", output):
        n = int(m.group(1) or m.group(2)) - 1
        want |= set(range(max(0, n - ctx), min(len(lines), n + ctx)))
    names = set(re.findall(r"(?:attribute|name) '(\w+)'", output))
    for i, ln in enumerate(lines):
        if any(re.search(rf"\b{re.escape(nm)}\b", ln) for nm in names):
            want |= set(range(max(0, i - 8), min(len(lines), i + 12)))
    out, prev = [], -2
    for i in sorted(want):
        if i != prev + 1:
            out.append(f"# ... (excerpt; file continues, line {i + 1} follows) ...")
        out.append(lines[i])
        prev = i
    return "\n".join(out)[:20000]


def _is_test(rel: str) -> bool:
    parts = Path(rel).parts
    return any(p in ("tests", "test", "testing") for p in parts[:-1]) or Path(rel).name.startswith("test_") \
        or Path(rel).name.endswith("_test.py") or Path(rel).name == "conftest.py"


_MISSING = [
    re.compile(r"cannot import name '(\w+)' from '([\w.]+)'"),
    re.compile(r"module '([\w.]+)' has no attribute '(\w+)'"),
    re.compile(r"'(\w+)' object has no attribute '(\w+)'"),
]


PROBE = r"""
import importlib, json, sys
out = []
for mod, name, where in json.loads(sys.argv[1]):
    try:
        m = importlib.import_module(mod)
    except Exception as e:
        out.append([mod, "*", where]); continue
    if name != "*" and not hasattr(m, name):
        try:
            importlib.import_module(mod + "." + name)
        except Exception:
            out.append([mod, name, where])
print(json.dumps(out))
"""


CLASS_PROBE = r"""
import difflib, importlib, inspect, json, sys, pkgutil
cls_name, attr, tops = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
seen, out = set(), []
for top in tops:
    try:
        mods = [importlib.import_module(top)]
    except Exception:
        continue
    for m in list(mods):
        for name, obj in vars(m).items():
            if name == cls_name and inspect.isclass(obj) and id(obj) not in seen:
                seen.add(id(obj))
                pub = sorted(a for a in dir(obj) if not a.startswith("_"))
                sig = lambda f: str(inspect.signature(f)) if callable(f) else "?"
                info = {"class": f"{obj.__module__}.{obj.__qualname__}", "init": sig(obj.__init__),
                        "public": pub[:40], "close": difflib.get_close_matches(attr, pub, 3, 0.5)}
                if hasattr(obj, "init_app"):
                    info["init_app"] = sig(obj.init_app)
                out.append(info)
print(json.dumps(out[:2]))
"""


def class_probe(sb: Sandbox, cls_name: str, attr: str, upgraded: list[str]) -> str:
    """For "'X' object has no attribute 'y'": show the upgraded class's real API (constructor
    and init_app signatures, public attributes, close matches) from the installed venv."""
    import json
    from .reach import module_names
    tops = sorted({m.split(".")[0] for d in upgraded for m in module_names(d)})
    _, out = _run(f"{sb.venv}/bin/python -c {shlex_quote(CLASS_PROBE)} {shlex_quote(cls_name)} "
                  f"{shlex_quote(attr)} {shlex_quote(json.dumps(tops))}", sb.work, timeout=120)
    try:
        infos = json.loads(out.strip().splitlines()[0])
    except (ValueError, IndexError):
        return ""
    return "\n".join(
        f"    {i['class']}{i['init']}" + (f"; init_app{i['init_app']}" if "init_app" in i else "")
        + f"\n    public attributes: {', '.join(i['public'])}"
        + (f"\n    closest to '{attr}': {', '.join(i['close'])}" if i["close"] else "")
        for i in infos)


def import_probe(sb: Sandbox, files: dict[str, str], upgraded: list[str]) -> list[tuple[str, str, str]]:
    """Statically list every `from <upgraded pkg> import name` in the app files and check each
    name against the installed upgraded packages. Python reports only the FIRST missing name of
    an import line; this finds all of them, so one repair round can fix every import."""
    import ast
    import json
    from .reach import module_names
    tops = {m.split(".")[0] for d in upgraded for m in module_names(d)}
    pairs = []
    for rel, src in files.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0 \
                    and node.module.split(".")[0] in tops:
                pairs += [(node.module, a.name, f"{rel}:{node.lineno}") for a in node.names if a.name != "*"]
    if not pairs:
        return []
    code, out = _run(f"{sb.venv}/bin/python -c {shlex_quote(PROBE)} {shlex_quote(json.dumps(pairs))}",
                     sb.work, timeout=120)
    try:
        return [tuple(x) for x in json.loads(out.strip().splitlines()[0])]
    except (ValueError, IndexError):
        return []


def shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)


def api_hints(sb: Sandbox, output: str, limit: int = 8,
              missing: list[tuple[str, str, str]] | None = None, upgraded: list[str] | None = None) -> str:
    """Ground the repair in the *installed* upgraded code: for every name the tests (or the
    import probe) report as missing, grep the sandbox's site-packages for where that name is
    now defined."""
    names = [(n, f"{m} (imported at {w})") for m, n, w in (missing or []) if n != "*"]
    for m in _MISSING[0].finditer(output):
        names.append((m.group(1), m.group(2)))
    for m in _MISSING[1].finditer(output):
        names.append((m.group(2), m.group(1)))
    objs = []
    for m in _MISSING[2].finditer(output):
        if (m.group(1), m.group(2)) not in objs:
            objs.append((m.group(1), m.group(2)))
    site = next(iter(sb.venv.glob("lib/python*/site-packages")), None)
    if not site or not (names or objs):
        return "(none)"
    out, seen = [], set()
    for cls_name, attr in objs[:3]:
        api = class_probe(sb, cls_name, attr, upgraded or [])
        if api:
            out.append(f"- `{cls_name}` objects have no attribute `{attr}` in the upgraded version. "
                       f"Actual API of `{cls_name}`:\n{api}")
    for name, where in names:
        if name in seen or len(out) >= limit:
            continue
        seen.add(name)
        excl = "grep -vE '/(tests?|_vendor)/'"
        _, defs = _run(f"grep -rnE --include='*.py' '^(def|class) {name}\\b|^{name} *=' . 2>/dev/null "
                       f"| {excl} | head -4", site, timeout=60)
        _, reexp = _run(f"grep -rnE --include='*.py' '^from [.a-zA-Z_]+ import .*\\b{name}\\b' . "
                        f"2>/dev/null | {excl} | head -3", site, timeout=60)
        hits = defs.strip() + "\n" + reexp.strip()
        hits = hits.strip()
        out.append(f"- `{name}` (reported missing from `{where}`): "
                   + ("now defined/exported at:\n" + "\n".join("    " + h for h in hits.splitlines())
                      if hits else "not found anywhere in the installed packages (removed)"))
    return "\n".join(out)


def validate_pin_bumps(sb: Sandbox, bumps, security: dict[str, str],
                       rejected: list | None = None) -> dict[str, str]:
    """Accept only upward moves of existing non-security pins. A spec such as ">=4" or a
    version that does not exist snaps to the lowest real (non-yanked, final) release that
    satisfies it and is above the current pin."""
    import httpx
    from packaging.version import InvalidVersion, Version
    if not isinstance(bumps, dict):
        return {}
    cur, ok = sb.current_pins(), {}
    for pkg, spec in bumps.items():
        k = norm(str(pkg))
        m = re.search(r"\d+(?:\.\d+)*", str(spec))
        why = None
        if k not in cur:
            why = "not a pinned dependency"
        elif k in security:
            why = "security pin"
        elif not m:
            why = f"unparseable version {spec!r}"
        if why:
            if rejected is not None:
                rejected.append(f"{pkg}={spec}: {why}")
            continue
        try:
            want, now = Version(m.group(0)), Version(cur[k])
            rel = httpx.get(f"https://pypi.org/pypi/{k}/json", timeout=20).json().get("releases", {})
        except (InvalidVersion, httpx.HTTPError, ValueError):
            continue
        avail = []
        for v, files in rel.items():
            try:
                pv = Version(v)
            except InvalidVersion:
                continue
            if not pv.is_prerelease and pv > now and files and not all(f.get("yanked") for f in files):
                avail.append(pv)
        # A repair bump exists because a third-party package broke against the upgraded ones;
        # its newest release is the likeliest to support them (seen live: the model asked for
        # flask-babel 3.0.0, which still caps Flask<3; 4.0.0 works). If the newest release is
        # not installable here, the resolver step after this falls back to the lowest one that is.
        best = max(avail) if avail else None
        if best:
            ok[k] = str(best)
        elif rejected is not None:
            rejected.append(f"{pkg}={spec}: no release >= {want} above {now}")
    return ok


REVIEW_SYSTEM = """You review a dependency-upgrade patch whose tests already pass. Find behaviour
the APPLICATION CODE EDITS removed or broke that tests may not cover: a decorator or callback
registration deleted without being re-registered elsewhere, a feature disabled, an exception
swallowed, a security check weakened, a removed import still used. Ignore style, the
requirements changes themselves, and harmless modernisations. Be concrete and brief."""

REVIEW_TMPL = """Upgrades: {upgrades}
Repair rationales: {rationales}

Patch (code part):
{diff}

Return JSON: {{"ok": true|false, "concerns": [str]}}  (ok=true when nothing was lost)"""


def review_diff(llm: LLM, diff: str, res: "FixResult") -> dict:
    code = "".join(c for c in re.split(r"(?=^diff --git )", diff, flags=re.M)
                   if c.startswith("diff --git") and "requirements" not in c.splitlines()[0])
    if not code.strip():
        return {"ok": True, "concerns": []}
    try:
        d = llm.chat_json("reason", REVIEW_SYSTEM, REVIEW_TMPL.format(
            upgrades=", ".join(f"{k} {a}->{b}" for k, (a, b) in res.upgrades.items()),
            rationales=" | ".join(r["rationale"][:200] for r in res.repairs if r.get("rationale")),
            diff=code[:12000]), max_tokens=4000, want=("ok", "concerns"), tag="review", temperature=0.0)
    except LLMError as e:
        return {"ok": True, "concerns": [], "error": str(e)[:200]}
    concerns = [str(c) for c in (d.get("concerns") or []) if str(c).strip()][:5]
    return {"ok": bool(d.get("ok")) and not concerns, "concerns": concerns}


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
    key = hashlib.sha1(str(repo.resolve()).encode()).hexdigest()[:10]
    sb = Sandbox(repo, Path(tempfile.gettempdir()) / "patchwise" / f"{repo.name}-{key}", settings)
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
            bumps, raised, err = sb.compatible_bumps(pins)
            if not bumps and not raised and not getattr(sb, "dropped_extras", None):
                if err:
                    res.notes.append("Resolver could not find a compatible set: " + err[-500:])
                    pyreq = re.findall(r"([A-Za-z0-9_.\-]+)==([^\s]+) depends on Python>=([\d.]+)", err)
                    if pyreq:
                        need = max(pyreq, key=lambda t: tuple(int(x) for x in t[2].split(".")))
                        res.notes.append(f"The security fixes need a newer Python: {need[0]} {need[1]} requires "
                                         f"Python >= {need[2]}, but the project targets "
                                         f"{sb.python_version() or 'an older Python'}. Upgrade Python first.")
                break
            if bumps:
                log(f"  resolver: compatible bumps needed: {', '.join(f'{k}->{v}' for k, v in bumps.items())}")
            cur = sb.current_pins()
            for k, v in bumps.items():
                res.compat_bumps[k] = (cur.get(k), v)
            if getattr(sb, "dropped_extras", None):
                res.notes.append("Test-only pins dropped because they conflict with the security "
                                 f"upgrade: {', '.join(sb.dropped_extras)}")
                log(f"  resolver: dropped conflicting test-only pins {sb.dropped_extras}")
            for k, v in raised.items():
                log(f"  resolver: security pin {k} raised {pins[k]}->{v} to resolve a conflict")
                res.notes.append(f"{k}: minimal safe version {pins[k]} conflicts with another fix; "
                                 f"resolver chose {v}.")
                pins[k] = v
                res.upgrades[k] = (res.upgrades[k][0], v)
            sb.set_pins({**bumps, **raised})
        else:
            break
        run = sb.test()
    it = 0
    notes = None
    if run.summary == "dependency install failed":
        res.notes.append("Upgraded dependency set could not be installed; code repair skipped "
                         "(an install failure is not something application edits can fix).")
    empty = 0
    green = (sb.snapshot(), run) if run.ok else None  # last state whose tests passed
    feedback = None  # concerns from the post-fix review, fed back as a repair round
    reviews = 0
    while llm.online and run.summary != "dependency install failed" and it < settings.max_repair_iterations:
        if run.ok and not feedback:
            if not res.repairs or reviews >= 2:
                break
            reviews += 1
            res.review = review_diff(llm, sb.diff(), res)
            log(f"  review {reviews}: {'behaviour preserved' if res.review.get('ok') else res.review.get('concerns')}")
            if res.review.get("ok"):
                break
            feedback = "; ".join(res.review.get("concerns") or [])
            continue
        it += 1
        notes = notes or migration_notes(tavily, res.upgrades)
        files = _relevant_files(sb, run.output, list(res.upgrades) + list(res.compat_bumps))
        history = "".join(f"\nPrevious attempt {r['iteration']}: {r['rationale'][:300]} -> {r['summary']}"
                          + "".join(f"\n  (edit to {u['file']} NOT applied: search text not found verbatim: "
                                    f"{u['replace']!r})" for u in r.get("unmatched", []))
                          for r in res.repairs)
        user = REPAIR_TMPL.format(
            upgrades=", ".join(f"{k} {a}->{b}" for k, (a, b) in res.upgrades.items()), notes=notes,
            hints=api_hints(sb, run.output, missing=import_probe(
                sb, files, list(res.upgrades) + list(res.compat_bumps)),
                upgraded=list(res.upgrades) + list(res.compat_bumps)), history=history and "\nEarlier repair attempts (the files"
            " below already include their edits):" + history + "\n",
            output=(run.output[-6000:] if not feedback else
                    "The tests PASS, but a code review of the current diff found behaviour that was "
                    "lost or broken by the edits (the tests do not cover it). Fix it:\n- " + feedback
                    + "\n\nCurrent diff:\n" + sb.diff()[-5000:]), pins=", ".join(f"{k}=={v}" for k, v in sb.current_pins().items())[:3000],
            files="\n\n".join(f"### {n}\n```python\n{c}\n```" for n, c in files.items()))
        try:
            d = llm.chat_json("deep", REPAIR_SYSTEM, user, max_tokens=8000, want=("edits", "pin_bumps", "rationale"), tag="repair",
                              temperature=0.0)
        except LLMError as e:
            res.notes.append(f"repair iteration {it} failed: {e}")
            break
        rejected: list = []
        changed = sorted(set(sb.apply_edits(d.get("edits") or [], rejected)))
        bad_pins: list = []
        bumped = validate_pin_bumps(sb, d.get("pin_bumps"), pins, bad_pins)
        for b in bad_pins:
            res.notes.append(f"repair {it}: pin bump rejected ({b})")
        pin_note = ""
        if bumped:
            before = sb.current_pins()
            sb.set_pins(bumped)
            log(f"  repair {it}: pin bumps {bumped}")
            ok, _ = sb.install()
            if not ok:  # let the resolver add the companions the bump needs (e.g. Babel for flask-babel)
                more, _, _ = sb.compatible_bumps(pins)
                # the resolver may also raise the model's own choice (lowest compatible >= it)
                if more:
                    sb.set_pins(more)
                    bumped.update(more)
                    ok, _ = sb.install()
            if ok:
                for k, v in bumped.items():
                    res.compat_bumps[k] = (res.compat_bumps.get(k, (before.get(k),))[0], v)
                changed.append("pins: " + ", ".join(f"{k}=={v}" for k, v in bumped.items()))
            else:
                sb.set_pins({k: before[k] for k in bumped if k in before})
                pin_note = f" (pin bumps {bumped} reverted: not installable together)"
                log(f"  repair {it}: pin bumps not installable; reverted")
        unmatched = [rj for rj in rejected if rj.get("unmatched")]
        rejected = [rj for rj in rejected if not rj.get("unmatched")]
        for rj in rejected:
            res.notes.append(f"repair {it}: rejected an edit to {rj['file']} that would introduce "
                             f"{', '.join(rj['patterns'])}")
            log(f"  repair {it}: REJECTED unsafe edit to {rj['file']} ({', '.join(rj['patterns'])})")
        log(f"  repair {it}: edited {changed or 'nothing'}; re-running tests…")
        run = sb.test()
        if run.summary == "dependency install failed":
            res.notes.append(f"repair {it}: dependency install failed after edits; stopping.")
        if run.ok:
            green = (sb.snapshot(), run)
        if feedback:
            res.notes.append(f"repair {it}: attempted review concern: {feedback[:300]}")
            feedback = None
        res.repairs.append({"iteration": it, "files": changed,
                            "rationale": str(d.get("rationale") or d.get("explanation") or d.get("summary")
                                             or "") + pin_note, "unmatched": unmatched,
                            "rejected": rejected,
                            "tests_ok": run.ok, "summary": run.summary})
        if not changed and not rejected and not bad_pins and not pin_note and not unmatched:
            empty += 1
            res.repairs[-1]["rationale"] += " (no applicable edits returned)"
            if empty >= 2:
                break
        else:
            empty = 0
    if not run.ok and green is not None:
        sb.restore(green[0])
        run = green[1]
        sb.install()  # venv back in sync with the restored pins (verify_patch reinstalls anyway)
        res.notes.append("Later (review-driven) repair rounds did not stay green; kept the last "
                         "state whose tests passed.")
    res.final = run
    res.diff = sb.diff()
    res.patch_applies, why, res.patch_tests = sb.verify_patch(res.diff)
    if not res.patch_applies:
        res.notes.append(f"fix.patch does not apply cleanly to the original repo: {why}")
    elif res.patch_tests is not None:
        res.notes.append(f"fix.patch re-applied to a pristine copy with git apply; tests there: "
                         f"{res.patch_tests.summary}")
    if run.ok and res.repairs and llm.online and res.review is None:
        res.review = review_diff(llm, res.diff, res)
    if res.review and not res.review.get("ok"):
        res.notes.append("Reviewer concerns NOT resolved (tests pass, but check by hand): "
                         + "; ".join(res.review.get("concerns") or []))
    if run.ok and run.summary == "no tests collected":
        res.status = "no_tests"
    elif run.ok and res.patch_applies and res.patch_tests is not None and res.patch_tests.ok:
        if res.review and not res.review.get("ok"):
            res.status = "tests_pass_needs_review"  # green, but the reviewer found lost behaviour
        else:
            res.status = "verified_with_code_changes" if res.repairs else "verified"
    elif run.ok:
        res.status = "tests_pass_patch_unverified"
    else:
        res.status = "tests_fail"
    return res
