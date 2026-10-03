"""Human report (Markdown/HTML) + machine-readable OpenVEX statements."""
from __future__ import annotations

import datetime as dt
import html

from jinja2 import Environment, select_autoescape

from .pipeline import Run

LABEL = {"fix-now": "Fix now", "review": "Needs review", "deprioritize": "Not exploitable here"}


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
             f"**{c['fix-now']} fix now · {c['review']} need review · {c['deprioritize']} not exploitable here**", ""]
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


TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><title>Patchwise report</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#1b1f24}
h1{margin-bottom:.2rem}.muted{color:#57606a}.pill{display:inline-block;padding:.1rem .55rem;border-radius:1rem;font-size:.8rem;font-weight:600}
.fix-now{background:#ffebe9;color:#a40e26}.review{background:#fff8c5;color:#7d4e00}.deprioritize{background:#dafbe1;color:#116329}
.cards{display:flex;gap:1rem;margin:1rem 0}.card{flex:1;border:1px solid #d0d7de;border-radius:10px;padding:1rem;text-align:center}
.card b{font-size:2rem;display:block}details{border:1px solid #d0d7de;border-radius:10px;padding:.7rem 1rem;margin:.6rem 0}
summary{cursor:pointer;font-weight:600}pre{background:#f6f8fa;padding:.7rem;border-radius:6px;overflow:auto;font-size:13px}
code{background:#f6f8fa;padding:0 .25rem;border-radius:4px}.ok{color:#116329}.bad{color:#a40e26}
</style></head><body>
<h1>Patchwise</h1><div class="muted">{{ r.repo }} · {{ r.deps_scanned }} pinned deps · {{ r.items|length }} advisories · {{ r.seconds }}s · mode: {{ r.mode }}</div>
<div class="cards"><div class="card"><b class="bad">{{ c['fix-now'] }}</b>fix now</div>
<div class="card"><b>{{ c['review'] }}</b>need review</div><div class="card"><b class="ok">{{ c['deprioritize'] }}</b>not exploitable here</div>
{% if r.fix %}<div class="card"><b class="{{ 'ok' if r.fix.status.startswith('verified') else 'bad' }}">{{ '✔' if r.fix.status.startswith('verified') else '✖' }}</b>fix {{ r.fix.status.replace('_',' ') }}</div>{% endif %}</div>
{% if r.llm_usage.calls %}<p class="muted">NVIDIA Nemotron on Nebius Token Factory: {{ r.llm_usage.calls }} calls ·
{{ "{:,}".format(r.llm_usage.input_tokens) }} in / {{ "{:,}".format(r.llm_usage.output_tokens) }} out tokens · ${{ "%.4f"|format(r.llm_usage.cost_usd) }} · Tavily calls: {{ r.tavily_calls }}</p>{% endif %}
{% for it in r.items %}<details {% if it.priority=='fix-now' %}open{% endif %}><summary><span class="pill {{ it.priority }}">{{ label[it.priority] }}</span>
{{ it.finding.dep.name }} {{ it.finding.dep.version }} — {{ it.vuln_id }} <span class="muted">({{ it.vuln.severity }})</span></summary>
<p>{{ it.vuln.summary }}</p><p><b>Verdict:</b> {{ it.reach.verdict }} ({{ "%.0f"|format(it.reach.confidence*100) }}%) — {{ it.reach.rationale }}</p>
<p><b>Vulnerable code:</b> <code>{{ it.intel.vulnerable_symbols|join(', ') }}</code>{% if it.intel.trigger_conditions %}<br><b>Triggered when:</b> {{ it.intel.trigger_conditions }}{% endif %}</p>
<p><b>Fix:</b> upgrade to {{ it.finding.min_fix or 'n/a' }}</p>
{% for e in it.proof %}{% if loop.index <= 3 %}<div class="muted">{{ e.file }}:{{ e.line }}</div><pre>{{ e.snippet }}</pre>{% endif %}{% endfor %}
{% if it.intel.sources %}<p class="muted">Sources: {% for s in it.intel.sources[:4] %}<a href="{{ s }}">{{ s[:70] }}</a> {% endfor %}</p>{% endif %}
</details>{% endfor %}
{% if r.fix %}<h2>Verified fix</h2><p>Status: <b>{{ r.fix.status }}</b> · baseline tests: {{ r.fix.baseline.summary if r.fix.baseline else '-' }} · after: {{ r.fix.final.summary if r.fix.final else '-' }} · fix.patch re-applied to a pristine copy: {{ 'yes' if r.fix.patch_applies else 'no' }}{% if r.fix.patch_tests %} (tests: {{ r.fix.patch_tests.summary }}){% endif %}</p>
<ul>{% for rep in r.fix.repairs %}<li>Repair {{ rep.iteration }}: {{ rep.files|join(', ') or 'no edits' }} — {{ rep.rationale }}</li>{% endfor %}
{% for n in r.fix.notes %}<li>{{ n }}</li>{% endfor %}</ul>{% if r.fix.diff %}<pre>{{ r.fix.diff[:20000] }}</pre>{% endif %}{% endif %}
</body></html>"""


def html_report(r: Run) -> str:
    env = Environment(autoescape=select_autoescape(default=True))
    return env.from_string(TEMPLATE).render(r=r, c=_counts(r), label=LABEL)


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
