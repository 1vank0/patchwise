"""Dependency discovery + vulnerability lookup via the free OSV.dev API (no key needed)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from packaging.version import InvalidVersion, Version

OSV = "https://api.osv.dev/v1"


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str  # "PyPI" | "npm"
    manifest: str   # relative path of the file that pins it
    line: int | None = None


@dataclass
class Vuln:
    id: str
    aliases: list[str]
    summary: str
    details: str
    severity: str
    references: list[str]
    fixed_versions: list[str]
    published: str | None = None


@dataclass
class Finding:
    dep: Dependency
    vulns: list[Vuln] = field(default_factory=list)

    @property
    def min_fix(self) -> str | None:
        """Smallest version > current that is >= every advisory's fix (per advisory, the
        lowest fix above current)."""
        try:
            cur = Version(self.dep.version)
        except InvalidVersion:
            return None
        need: list[Version] = []
        for v in self.vulns:
            cands = []
            for f in v.fixed_versions:
                try:
                    fv = Version(f)
                except InvalidVersion:
                    continue
                if fv > cur:
                    cands.append(fv)
            if cands:
                need.append(min(cands))
        return str(max(need)) if need else None


_REQ = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.\-+!]+)")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.split("[")[0]).lower()


def discover(repo: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    skip = {".git", ".venv", "venv", "node_modules", "__pycache__", ".patchwise"}
    for p in sorted(repo.rglob("*")):
        if any(part in skip for part in p.relative_to(repo).parts):
            continue
        rel = str(p.relative_to(repo))
        if p.is_file() and re.match(r"requirements.*\.txt$", p.name):
            for i, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
                m = _REQ.match(line.split("#")[0])
                if m:
                    deps.append(Dependency(norm(m.group(1)), m.group(2), "PyPI", rel, i))
        elif p.is_file() and p.name == "package-lock.json":
            try:
                data = json.loads(p.read_text())
            except json.JSONDecodeError:
                continue
            for key, meta in (data.get("packages") or {}).items():
                if not key.startswith("node_modules/") or "version" not in meta:
                    continue
                name = key.split("node_modules/")[-1]
                deps.append(Dependency(name, meta["version"], "npm", rel))
    # de-duplicate
    seen, out = set(), []
    for d in deps:
        k = (d.ecosystem, d.name, d.version)
        if k not in seen:
            seen.add(k)
            out.append(d)
    return out


def _severity(v: dict) -> str:
    ds = (v.get("database_specific") or {}).get("severity")
    if ds:
        return str(ds).upper()
    for s in v.get("severity") or []:
        score = s.get("score", "")
        try:
            if score.startswith("CVSS:3"):
                from cvss import CVSS3
                return CVSS3(score).severities()[0].upper()
            if score.startswith("CVSS:4"):
                from cvss import CVSS4
                return CVSS4(score).severity.upper()
        except Exception:
            pass
    return "UNKNOWN"


def _fixed(v: dict, dep: Dependency) -> list[str]:
    out = []
    for aff in v.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != dep.ecosystem:
            continue
        if dep.ecosystem == "PyPI" and norm(pkg.get("name", "")) != dep.name:
            continue
        if dep.ecosystem == "npm" and pkg.get("name") != dep.name:
            continue
        for r in aff.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    out.append(ev["fixed"])
    return sorted(set(out))


def lookup(deps: list[Dependency], client: httpx.Client | None = None) -> list[Finding]:
    own = client is None
    client = client or httpx.Client(timeout=30)
    try:
        queries = [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                   for d in deps]
        findings: list[Finding] = []
        cache: dict[str, dict] = {}
        for start in range(0, len(queries), 500):
            r = client.post(f"{OSV}/querybatch", json={"queries": queries[start:start + 500]})
            r.raise_for_status()
            for dep, res in zip(deps[start:start + 500], r.json().get("results", [])):
                ids = [v["id"] for v in res.get("vulns") or []]
                if not ids:
                    continue
                f = Finding(dep)
                for vid in ids:
                    if vid not in cache:
                        cache[vid] = client.get(f"{OSV}/vulns/{vid}").json()
                    v = cache[vid]
                    f.vulns.append(Vuln(
                        id=vid, aliases=v.get("aliases") or [], summary=v.get("summary") or "",
                        details=(v.get("details") or "")[:4000], severity=_severity(v),
                        references=[x.get("url") for x in v.get("references") or [] if x.get("url")][:12],
                        fixed_versions=_fixed(v, dep), published=v.get("published"),
                    ))
                f.vulns = dedupe(f.vulns)
                findings.append(f)
        return findings
    finally:
        if own:
            client.close()


def dedupe(vulns: list[Vuln]) -> list[Vuln]:
    """OSV often lists the same issue as GHSA-*, PYSEC-* and CVE-*; merge by alias overlap,
    keeping the GHSA record (richest text) as primary."""
    groups: list[list[Vuln]] = []
    for v in vulns:
        keys = {v.id, *v.aliases}
        for g in groups:
            if any(keys & {x.id, *x.aliases} for x in g):
                g.append(v)
                break
        else:
            groups.append([v])
    out = []
    for g in groups:
        g.sort(key=lambda x: (not x.id.startswith("GHSA"), -len(x.details)))
        primary = g[0]
        aliases = sorted({a for x in g for a in [x.id, *x.aliases]} - {primary.id})
        fixed = sorted({f for x in g for f in x.fixed_versions})
        refs = list(dict.fromkeys(r for x in g for r in x.references))[:12]
        sev = next((x.severity for x in g if x.severity != "UNKNOWN"), primary.severity)
        out.append(Vuln(primary.id, aliases, primary.summary or next((x.summary for x in g if x.summary), ""),
                        primary.details, sev, refs, fixed, primary.published))
    return out
