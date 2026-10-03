"""End-to-end run: scan -> research -> reachability -> verified fix -> report."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings
from .fix import FixResult, fix
from .llm import LLM
from .reach import PyIndex, Reachability, analyze_group, group_advisories
from .research import Intel, Tavily, research
from .scan import Finding, Vuln, discover, lookup

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}


@dataclass
class Item:
    finding: Finding
    vuln_id: str
    intel: Intel
    reach: Reachability

    @property
    def vuln(self):
        return next(v for v in self.finding.vulns if v.id == self.vuln_id)

    @property
    def proof(self) -> list:
        """Evidence to show: the model's (validated) citations first, else candidate call sites."""
        cited = set(self.reach.cited)
        ev = [e for e in self.reach.evidence if f"{e.file}:{e.line}" in cited]
        return ev or [e for e in self.reach.evidence if e.kind == "call"]

    @property
    def priority(self) -> str:
        if self.reach.verdict == "reachable":
            return "review" if self.reach.dev_only else "fix-now"
        if self.reach.verdict == "uncertain":
            return "review"
        return "deprioritize"

    @property
    def sort_key(self):
        order = {"fix-now": 0, "review": 1, "deprioritize": 2}[self.priority]
        return (order, -SEV_RANK.get(self.vuln.severity, 0), self.finding.dep.name)


@dataclass
class Run:
    repo: str
    started: float
    items: list[Item] = field(default_factory=list)
    deps_scanned: int = 0
    fix: FixResult | None = None
    llm_usage: dict = field(default_factory=dict)
    tavily_calls: int = 0
    mode: str = "online"
    seconds: float = 0.0
    fix_scope: str = "fix-now"


SCOPES = {"fix-now": {"fix-now"}, "review": {"fix-now", "review"}, "all": {"fix-now", "review", "deprioritize"}}


def fix_targets(items: list[Item], scope: str = "fix-now") -> list[Finding]:
    """Findings to upgrade, each restricted to the advisories in scope, so a package is raised
    only as far as its in-scope advisories require (not to the fix of an unreachable one)."""
    want = SCOPES.get(scope, SCOPES["fix-now"])
    keep: dict[int, tuple[Finding, list[Vuln]]] = {}
    for it in items:
        if it.priority in want:
            f = it.finding
            keep.setdefault(id(f), (f, []))[1].append(it.vuln)
    out = []
    for f, vulns in keep.values():
        sub = Finding(f.dep, vulns)
        if sub.min_fix:
            out.append(sub)
    return out


def run(repo: Path, settings: Settings | None = None, *, do_fix: bool = True, log=print) -> Run:
    settings = settings or Settings()
    repo = repo.resolve()
    llm = LLM(settings)
    tavily = Tavily(settings)
    r = Run(str(repo), time.time(), mode="online" if llm.online else "offline-heuristic")
    log(f"[1/4] Discovering dependencies in {repo} …")
    deps = discover(repo)
    r.deps_scanned = len(deps)
    findings = lookup(deps)
    nv = sum(len(f.vulns) for f in findings)
    log(f"      {len(deps)} pinned deps, {len(findings)} vulnerable, {nv} advisories (OSV.dev)")
    log("[2/4] Researching advisories (Tavily + Nemotron) …")
    pairs = [(f, v) for f in findings for v in f.vulns]
    with ThreadPoolExecutor(max_workers=4) as ex:
        intels = list(ex.map(lambda fv: research(fv[0], fv[1], llm, tavily), pairs))
    for (f, v), i in zip(pairs, intels):
        log(f"      {f.dep.name} {v.id}: {', '.join(i.vulnerable_symbols[:3])[:90]}"
            + (f"  [{'/'.join(i.platforms)} only]" if i.platforms else ""))
    log("[3/4] Reachability analysis against your code …")
    idx = PyIndex.build(repo)
    intel_of = {v.id: i for (f, v), i in zip(pairs, intels)}
    with ThreadPoolExecutor(max_workers=4) as ex:
        grouped = list(ex.map(lambda f: (f, group_advisories(f, [intel_of[v.id] for v in f.vulns], llm)), findings))
    jobs = [(f, g) for f, groups in grouped for g in groups]
    sib = sum(len(g) for _, g in jobs if len(g) > 1)
    log(f"      {len(pairs)} advisories → {len(jobs)} judgments ({sib} advisories judged with siblings)")
    with ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(lambda j: analyze_group(idx, j[0], j[1], llm, deps, settings.deploy_os), jobs))
    reach_of = {rc.vuln_id: rc for res in results for rc in res}
    r.items = sorted((Item(f, v.id, intel_of[v.id], reach_of[v.id]) for f, v in pairs), key=lambda it: it.sort_key)
    for it in r.items:
        cite = f" ({it.reach.cited[0]})" if it.reach.cited else ""
        note = " [dev/test only]" if it.reach.dev_only and it.reach.verdict == "reachable" else ""
        tag = {"fix-now": "FIX NOW", "review": "REVIEW", "deprioritize": "not reachable"}[it.priority]
        log(f"      {tag:>13}  {it.finding.dep.name} {it.vuln_id}{cite}{note}")
    if do_fix and findings:
        targets = fix_targets(r.items, settings.fix_scope)
        r.fix_scope = settings.fix_scope
        if not targets:
            r.fix = FixResult(status="skipped", notes=[f"No advisories in scope '{settings.fix_scope}' "
                                                     "have a fixed version; nothing to upgrade."])
            log(f"[4/4] Nothing to fix in scope '{settings.fix_scope}'")
        else:
            log(f"[4/4] Building a verified fix in a sandbox (scope: {settings.fix_scope}; "
                f"{', '.join(t.dep.name for t in targets)}) …")
            r.fix = fix(repo, targets, settings, llm, tavily, log=log)
            log(f"      fix status: {r.fix.status}")
        nofix = [it for it in r.items if it.priority in SCOPES.get(settings.fix_scope, SCOPES["fix-now"])
                 and not Finding(it.finding.dep, [it.vuln]).min_fix]
        for it in nofix:
            r.fix.notes.append(f"{it.finding.dep.name} {it.vuln_id} has no patched release; mitigate in code "
                               f"({it.vuln.summary[:90]}).")
    r.llm_usage = {"calls": llm.usage.calls, "input_tokens": llm.usage.input_tokens,
                   "output_tokens": llm.usage.output_tokens, "cost_usd": round(llm.usage.cost_usd, 5),
                   "by_model": llm.usage.by_model}
    r.tavily_calls = tavily.calls
    r.seconds = round(time.time() - r.started, 1)
    return r


def to_json(r: Run) -> dict:
    return {
        "repo": r.repo, "name": Path(r.repo).name, "mode": r.mode,
        "generated": time.strftime("%Y-%m-%d %H:%M", time.localtime(r.started)), "seconds": r.seconds, "deps_scanned": r.deps_scanned,
        "llm_usage": r.llm_usage, "tavily_calls": r.tavily_calls, "fix_scope": r.fix_scope,
        "items": [{
            "package": it.finding.dep.name, "version": it.finding.dep.version,
            "ecosystem": it.finding.dep.ecosystem, "manifest": it.finding.dep.manifest,
            "vuln": it.vuln_id, "aliases": it.vuln.aliases, "severity": it.vuln.severity,
            "summary": it.vuln.summary, "min_fix": it.finding.min_fix, "priority": it.priority,
            "intel": it.intel.to_dict(), "reachability": it.reach.to_dict(),
        } for it in r.items],
        "fix": None if not r.fix else {
            "status": r.fix.status, "upgrades": r.fix.upgrades, "compat_bumps": r.fix.compat_bumps, "repairs": r.fix.repairs,
            "baseline": r.fix.baseline and r.fix.baseline.summary,
            "final": r.fix.final and r.fix.final.summary, "notes": r.fix.notes,
            "patch_applies": r.fix.patch_applies, "review": r.fix.review,
            "patch_tests": r.fix.patch_tests and r.fix.patch_tests.summary, "diff": r.fix.diff,
        },
    }


def save(r: Run, out: Path) -> dict:
    from .report import html_report, markdown_report, openvex

    out.mkdir(parents=True, exist_ok=True)
    data = to_json(r)
    (out / "report.json").write_text(json.dumps(data, indent=2))
    (out / "report.md").write_text(markdown_report(r))
    (out / "report.html").write_text(html_report(r))
    (out / "openvex.json").write_text(json.dumps(openvex(r), indent=2))
    if r.fix and r.fix.diff:
        (out / "fix.patch").write_text(r.fix.diff)
    return data
