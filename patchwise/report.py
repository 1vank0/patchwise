"""Human report (Markdown/HTML) + machine-readable OpenVEX statements."""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

from jinja2 import Environment, select_autoescape

from .pipeline import Run

LABEL = {"fix-now": "Fix now", "review": "Needs review", "deprioritize": "Not reachable"}


def _counts(r: Run):
    c = {"fix-now": 0, "review": 0, "deprioritize": 0}
    for it in r.items:
        c[it.priority] += 1
    return c


def markdown_report(r: Run) -> str:
    c = _counts(r)
    lines = [f"# Patchwise report", "",
             f"Repo: `{r.repo}` · mode: **{r.mode}** · {r.deps_scanned} pinned deps · "
             f"{len(r.items)} advisories · {r.seconds}s", "",
             f"**{c['fix-now']} fix now · {c['review']} need review · {c['deprioritize']} not reachable**", ""]
    if r.mode != "online":
        lines += ["> Offline heuristic mode (no NEBIUS_API_KEY): verdicts are rough. Set the key for "
                  "Nemotron analysis.", ""]
    u = r.llm_usage
    if u.get("calls"):
        lines += [f"Nemotron on Nebius Token Factory: {u['calls']} calls, {u['input_tokens']:,} in / "
                  f"{u['output_tokens']:,} out tokens, **${u['cost_usd']:.4f}**. Tavily calls: {r.tavily_calls}.", ""]
    for pr in ("fix-now", "review", "deprioritize"):
        group = [it for it in r.items if it.priority == pr]
        if not group:
            continue
        lines += [f"## {LABEL[pr]} ({len(group)})", ""]
        for it in group:
            d, v = it.finding.dep, it.vuln
            lines += [f"### {d.name} {d.version} — {v.id} ({v.severity})",
                      f"{v.summary}  ", f"Fix: upgrade to **{it.finding.min_fix or 'n/a'}** · "
                      f"Verdict: **{it.reach.verdict}** ({it.reach.confidence:.0%})  ",
                      f"Why: {it.reach.rationale}  ",
                      f"Vulnerable code: `{', '.join(it.intel.vulnerable_symbols)}`"]
            if it.reach.group:
                lines += [f"Judged together with: {', '.join(it.reach.group)}  "]
            if it.reach.dev_only:
                lines += [f"Dev/test only: {it.reach.dev_only} (priority lowered to review)  "]
            ev = it.proof[:2]
            for e in ev:
                lines += ["", f"`{e.file}:{e.line}`", "```", e.snippet, "```"]
            if it.intel.sources:
                lines += ["", "Sources: " + ", ".join(it.intel.sources[:3])]
            lines.append("")
    if r.fix:
        f = r.fix
        lines += ["## Verified fix", "", f"Status: **{f.status}**  ",
                  "Upgrades: " + ", ".join(f"{k} {a}→{b}" for k, (a, b) in f.upgrades.items()) + "  ",
                  ("Compatibility bumps: " + ", ".join(f"{k} {a}→{b}" for k, (a, b) in f.compat_bumps.items()) + "  ")
                  if f.compat_bumps else "",
                  f"Baseline tests: {f.baseline.summary if f.baseline else '-'} · After fix: "
                  f"{f.final.summary if f.final else '-'}  ",
                  f"fix.patch re-applied to a pristine copy: {'yes' if f.patch_applies else 'no'}"
                  f" · tests there: {f.patch_tests.summary if f.patch_tests else '-'}", ""]
        for rep in f.repairs:
            lines += [f"- Repair {rep['iteration']}: {', '.join(rep['files']) or 'no edits'} — "
                      f"{rep['rationale']} (tests {'pass' if rep['tests_ok'] else 'fail'})"]
        for n in f.notes:
            lines.append(f"- Note: {n}")
        if f.diff:
            lines += ["", "```diff", f.diff[:8000], "```"]
    return "\n".join(lines) + "\n"


ASSETS = Path(__file__).resolve().parent / "assets"
ROLES = {  # model id fragment -> (display name, what it does in Patchwise)
    "Lightning": ("Nemotron 3.5 Lightning", "advisory research: extracts vulnerable functions & triggers"),
    "super": ("Nemotron 3 Super 120B", "reachability verdicts, sibling grouping, patch review"),
    "Ultra": ("Nemotron 3 Ultra 550B", "repairs code broken by the upgrade"),
    "Nano": ("Nemotron 3 Nano 30B", "fast tier"),
}
STATUS_TEXT = {
    "verified": ("good", "Verified: upgraded, tests pass, patch re-applies cleanly"),
    "verified_with_code_changes": ("good", "Verified with code repair: tests pass after Nemotron fixed breaking changes"),
    "tests_pass_needs_review": ("warn", "Tests pass, but the reviewer flagged concerns: needs human review"),
    "tests_pass_patch_unverified": ("warn", "Tests pass, but the patch did not re-apply cleanly"),
    "tests_fail": ("bad", "Not verified: tests or install fail after the upgrade"),
    "no_tests": ("warn", "Upgraded, but the project has no tests to verify against"),
    "skipped": ("warn", "Nothing to upgrade in the selected scope"),
}


def _role(model: str):
    for k, v in ROLES.items():
        if k.lower() in model.lower():
            return v
    return (model, "")


def _code(snippet: str, hit: int | None) -> list:
    out = []
    for ln in snippet.splitlines():
        m = re.match(r"^\s*(\d+)\|", ln)
        out.append({"text": ln, "hit": bool(m and hit and int(m.group(1)) == hit)})
    return out


def _diff(diff: str) -> list:
    out = []
    for ln in diff.splitlines()[:900]:
        cls = ("hunk" if ln.startswith("@@") else "add" if ln.startswith("+") and not ln.startswith("+++")
               else "del" if ln.startswith("-") and not ln.startswith("---") else "")
        out.append({"text": ln, "cls": cls})
    return out


def view(data: dict) -> dict:
    """Template-ready view of a report.json document (also used by the web UI)."""
    items = data.get("items", [])
    c = {"fix-now": 0, "review": 0, "deprioritize": 0}
    for it in items:
        c[it["priority"]] += 1
    cards = []
    for it in items:
        rc = it["reachability"]
        cited = set(rc.get("cited") or [])
        ev = [e for e in rc.get("evidence", []) if f"{e['file']}:{e['line']}" in cited] or \
             [e for e in rc.get("evidence", []) if e["kind"] == "call"]
        cards.append({**it, "proof": [{"loc": f"{e['file']}:{e['line']}", "lines": _code(e["snippet"], e["line"])}
                                      for e in ev[:3]],
                      "group": rc.get("group") or [], "dev_only": rc.get("dev_only") or "",
                      "platforms": it["intel"].get("platforms") or [], "method": rc.get("method", "llm")})
    fix = data.get("fix")
    fx = None
    if fix:
        tone, text = STATUS_TEXT.get(fix["status"], ("warn", fix["status"]))
        fx = {**fix, "tone": tone, "text": text, "diff_lines": _diff(fix.get("diff") or ""),
              "rounds": len(fix.get("repairs") or [])}
    u = data.get("llm_usage") or {}
    models = [{"id": m, "name": _role(m)[0], "role": _role(m)[1], **v} for m, v in (u.get("by_model") or {}).items()]
    total = max(1, len(items))
    return {"d": data, "c": c, "cards": cards, "fix": fx, "models": models, "u": u,
            "pct": {k: round(100 * v / total, 1) for k, v in c.items()},
            "name": data.get("name") or Path(data.get("repo", "repo")).name,
            "label": LABEL, "judgments": len({tuple(sorted([x["vuln"], *x["group"]])) for x in cards})}


TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Patchwise report · {{ name }}</title><style>{{ css|safe }}</style></head><body><div class="wrap">
<div class="top"><div class="brand"><div class="logo">⛨</div>Patchwise <span class="meta" style="font-weight:400">report · {{ name }}</span></div>
<div class="meta">{{ d.generated or '' }} · {{ d.deps_scanned }} pinned deps · {{ d.seconds }} s{% if d.mode != 'online' %} · <b>offline heuristic mode</b>{% endif %}</div></div>

<div class="hero">
 <div class="panel"><div class="kicker">Before → after triage</div>
  <div class="ba"><div class="raw"><div class="n">{{ d['items']|length }}</div><div class="l">raw scanner alerts</div></div><div class="arrow">→</div>
   <div class="tri"><div class="t fix"><div class="n">{{ c['fix-now'] }}</div><div class="l">fix now</div></div>
   <div class="t rev"><div class="n">{{ c['review'] }}</div><div class="l">needs review</div></div>
   <div class="t ok"><div class="n">{{ c['deprioritize'] }}</div><div class="l">not reachable</div></div></div></div>
  <div class="bar"><i class="fix" style="width:{{ pct['fix-now'] }}%"></i><i class="rev" style="width:{{ pct['review'] }}%"></i><i class="ok" style="width:{{ pct['deprioritize'] }}%"></i></div>
  <div class="note">Each alert was researched live (Tavily) and checked against this code base by NVIDIA Nemotron, with file:line citations.
  {{ judgments }} independent judgments; related advisories are judged together so near-duplicates can't disagree.</div>
 </div>
 <div class="panel"><div class="kicker">Verified fix</div>
 {% if fix %}<div class="status {{ fix.tone }}">{{ '✔' if fix.tone=='good' else ('!' if fix.tone=='warn' else '✖') }} {{ fix.status.replace('_',' ') }}</div>
  <div class="note" style="margin-top:4px">{{ fix.text }}</div>
  <div class="stat"><span>Scope</span><span>{{ (d.fix_scope or 'fix-now') }} advisories</span></div>
  <div class="stat"><span>Tests</span><span>{{ fix.baseline or '–' }} → {{ fix.final or '–' }}</span></div>
  <div class="stat"><span>Code repair rounds</span><span>{{ fix.rounds }}</span></div>
  <div class="stat"><span>Patch re-applied to clean copy</span><span>{{ 'yes' if fix.patch_applies else 'no' }}</span></div>
 {% else %}<div class="status warn">– triage only</div><div class="note">No upgrade was attempted for this run.</div>{% endif %}
  <div class="stat"><span>Model cost</span><span><b>${{ '%.3f'|format(u.cost_usd or 0) }}</b> · {{ u.calls or 0 }} Nemotron calls</span></div>
  <div class="stat"><span>Live research</span><span>{{ d.tavily_calls }} Tavily calls</span></div>
 </div>
</div>

{% if models %}<div class="models">{% for m in models %}<div class="model"><b><span class="nv">NVIDIA</span> {{ m.name }}</b>{{ m.role }}<br><span class="meta">{{ m.calls }} calls · ${{ '%.4f'|format(m.cost_usd) }} · via Nebius Token Factory</span></div>{% endfor %}</div>{% endif %}

<div class="filters" id="filters"><button class="on" data-f="all">All ({{ d['items']|length }})</button><button data-f="fix-now">Fix now ({{ c['fix-now'] }})</button><button data-f="review">Needs review ({{ c['review'] }})</button><button data-f="deprioritize">Not reachable ({{ c['deprioritize'] }})</button></div>
{% for it in cards %}<details class="adv {{ it.priority }}" data-p="{{ it.priority }}" {% if it.priority=='fix-now' %}open{% endif %}>
<summary><span class="pill {{ it.priority }}">{{ label[it.priority] }}</span><span class="pkg">{{ it.package }} {{ it.version }}</span>
<a class="vid" href="https://osv.dev/vulnerability/{{ it.vuln }}" target="_blank" rel="noopener">{{ it.vuln }}</a><span class="sev {{ it.severity }}">{{ it.severity }}</span>
{% if it.group %}<span class="tag" title="Judged together: same vulnerable feature and preconditions">+ {{ it.group|length }} sibling{{ 's' if it.group|length > 1 }}</span>{% endif %}
{% if it.dev_only %}<span class="tag dev">dev/test only</span>{% endif %}{% if it.platforms %}<span class="tag os">{{ it.platforms|join('/') }} only</span>{% endif %}
<span class="ttl">{{ it.summary }}</span></summary>
<div class="body"><div class="why"><b>Why · {{ it.reachability.verdict.replace('_',' ') }} ({{ '%.0f'|format(it.reachability.confidence*100) }}% confidence)</b>{{ it.reachability.rationale }}
{% if it.dev_only %}<br><i>Priority lowered to review: {{ it.dev_only }}.</i>{% endif %}</div>
{% for e in it.proof %}<div class="ev"><div class="loc">{{ e.loc }}</div><pre>{% for l in e.lines %}<span class="ln{{ ' hit' if l.hit }}">{{ l.text }}</span>{% endfor %}</pre></div>{% endfor %}
<div class="row"><span>Vulnerable code:</span>{% for s in it.intel.vulnerable_symbols[:6] %}<span class="sym">{{ s }}</span>{% endfor %}</div>
<div class="row"><span>Fix: upgrade to <b>{{ it.min_fix or 'n/a' }}</b></span>{% if it.group %}<span>· judged with {{ it.group|join(', ') }}</span>{% endif %}</div>
{% if it.intel.sources %}<div class="src">Sources (Tavily): {% for s in it.intel.sources[:4] %}<a href="{{ s }}" target="_blank" rel="noopener">{{ s.split('/')[2] if '//' in s else s }}</a>{% endfor %}</div>{% endif %}
</div></details>{% endfor %}

{% if fix %}<h2>Verified fix</h2><div class="panel">
<table><tr><th>Package</th><th>From</th><th>To</th><th>Why</th></tr>
{% for k, v in fix.upgrades.items() %}<tr><td><b>{{ k }}</b></td><td>{{ v[0] }}</td><td>{{ v[1] }}</td><td>security fix</td></tr>{% endfor %}
{% for k, v in fix.compat_bumps.items() %}<tr><td>{{ k }}</td><td>{{ v[0] or '–' }}</td><td>{{ v[1] }}</td><td class="meta">needed to stay installable</td></tr>{% endfor %}</table>
{% if fix.repairs %}<ul class="steps">{% for rep in fix.repairs %}<li class="{{ '' if rep.tests_ok else 'f' }}"><b>Repair round {{ rep.iteration }}</b> · {{ rep.files|join(', ') or 'no edits' }} — {{ rep.rationale }} <span class="meta">(tests {{ 'pass' if rep.tests_ok else 'fail' }})</span></li>{% endfor %}</ul>{% endif %}
{% if fix.review %}<p class="note"><b>Post-fix review (Nemotron Super):</b> {{ 'no concerns' if fix.review.ok else (fix.review.concerns|join(' · ')) }}</p>{% endif %}
{% for n in fix.notes %}<p class="note">• {{ n }}</p>{% endfor %}
{% if fix.diff_lines %}<div class="ev"><div class="loc">fix.patch</div><pre>{% for l in fix.diff_lines %}<span class="ln {{ l.cls }}">{{ l.text }}</span>{% endfor %}</pre></div>{% endif %}
</div>{% endif %}
<footer>Generated by Patchwise · NVIDIA Nemotron models on Nebius Token Factory · live research by Tavily · advisories from OSV.dev</footer>
</div><script>
document.getElementById('filters').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;
document.querySelectorAll('#filters button').forEach(x=>x.classList.toggle('on',x===b));
document.querySelectorAll('.adv').forEach(a=>{a.style.display=(b.dataset.f==='all'||a.dataset.p===b.dataset.f)?'':'none'})});
</script></body></html>"""


def render_html(data: dict) -> str:
    env = Environment(autoescape=select_autoescape(default=True))
    return env.from_string(TEMPLATE).render(css=(ASSETS / "report.css").read_text(), **view(data))


def html_report(r: Run) -> str:
    from .pipeline import to_json
    return render_html(to_json(r))


def _purl(dep) -> str:
    eco = {"PyPI": "pypi", "npm": "npm"}[dep.ecosystem]
    return f"pkg:{eco}/{dep.name}@{dep.version}"


def openvex(r: Run) -> dict:
    """OpenVEX v0.2.0 document so scanners (Grype, Trivy) can suppress non-exploitable alerts."""
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    stmts = []
    for it in r.items:
        st = {"vulnerability": {"name": it.vuln_id, "aliases": it.vuln.aliases},
              "products": [{"@id": _purl(it.finding.dep)}], "timestamp": now}
        if it.reach.verdict == "not_reachable" and it.reach.confidence >= 0.7:
            st.update(status="not_affected", justification="vulnerable_code_not_in_execute_path",
                      impact_statement=it.reach.rationale[:500])
        elif it.reach.verdict == "reachable":
            st.update(status="affected", action_statement=f"Upgrade {it.finding.dep.name} to "
                      f"{it.finding.min_fix or 'a patched version'}")
        else:
            st.update(status="under_investigation")
        stmts.append(st)
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"patchwise-{int(r.started)}",
            "author": "Patchwise (automated; review before publishing)", "timestamp": now,
            "version": 1, "statements": stmts}
