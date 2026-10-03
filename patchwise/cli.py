"""patchwise <repo> [--out DIR] [--no-fix]"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Settings
from .pipeline import run, save


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="patchwise", description="Reachability-aware dependency "
                                 "vulnerability triage + verified fixes (Nemotron on Nebius Token Factory).")
    ap.add_argument("repo", type=Path)
    ap.add_argument("--out", type=Path, default=None, help="output dir (default: <repo>/.patchwise/report)")
    ap.add_argument("--no-fix", action="store_true", help="triage only; skip sandboxed upgrade+tests")
    ap.add_argument("--offline", action="store_true", help="heuristic mode without the LLM (dev only)")
    ap.add_argument("--fail-on", choices=["fix-now", "review", "never"], default="never",
                    help="CI gate: exit 1 if any advisory has this priority or worse")
    a = ap.parse_args(argv)
    s = Settings()
    if a.offline:
        s.offline = True
    if not s.llm_available:
        print("! NEBIUS_API_KEY not set (or --offline): running heuristic mode.", file=sys.stderr)
    r = run(a.repo, s, do_fix=not a.no_fix)
    out = a.out or (a.repo / ".patchwise" / "report")
    save(r, out)
    c = {p: sum(1 for it in r.items if it.priority == p) for p in ("fix-now", "review", "deprioritize")}
    print(f"\n{c['fix-now']} fix now · {c['review']} review · {c['deprioritize']} not exploitable here")
    if r.fix:
        print(f"fix: {r.fix.status}")
    if r.llm_usage.get("calls"):
        print(f"Nemotron: {r.llm_usage['calls']} calls, ${r.llm_usage['cost_usd']:.4f}")
    print(f"report: {out / 'report.html'}")
    if a.fail_on == "fix-now" and c["fix-now"]:
        return 1
    if a.fail_on == "review" and (c["fix-now"] or c["review"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
