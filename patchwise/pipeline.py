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
from .reach import PyIndex, Reachability, analyze
from .research import Intel, Tavily, research
from .scan import Finding, discover, lookup

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
    def priority(self) -> str:
        if self.reach.verdict == "reachable":
            return "fix-now"
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
    log("[3/4] Reachability analysis against your code …")
    idx = PyIndex.build(repo)
    with ThreadPoolExecutor(max_workers=4) as ex:
        reaches = list(ex.map(lambda a: analyze(idx, a[0][0], a[1], llm), zip(pairs, intels)))
    r.items = sorted((Item(f, v.id, i, re) for (f, v), i, re in zip(pairs, intels, reaches)),
                     key=lambda it: it.sort_key)
    if do_fix and findings:
        log("[4/4] Building a verified fix in a sandbox …")
        r.fix = fix(repo, findings, settings, llm, tavily, log=log)
        log(f"      fix status: {r.fix.status}")
    r.llm_usage = {"calls": llm.usage.calls, "input_tokens": llm.usage.input_tokens,
                   "output_tokens": llm.usage.output_tokens, "cost_usd": round(llm.usage.cost_usd, 5),
                   "by_model": llm.usage.by_model}
    r.tavily_calls = tavily.calls
    r.seconds = round(time.time() - r.started, 1)
    return r


def to_json(r: Run) -> dict:
    return {
        "repo": r.repo, "mode": r.mode, "seconds": r.seconds, "deps_scanned": r.deps_scanned,
        "llm_usage": r.llm_usage, "tavily_calls": r.tavily_calls,
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
