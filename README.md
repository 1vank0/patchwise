# Patchwise

**Your scanner reports 60 vulnerabilities. Patchwise tells you which ones your code can
actually reach, and gives you the smallest upgrade that keeps your tests passing.**

Patchwise is an agent built on **NVIDIA Nemotron** models served by **Nebius Token Factory**,
with live advisory research through **Tavily**. It writes, runs and tests code:

1. **Scan.** It finds pinned dependencies (`requirements*.txt`, `package-lock.json`) and looks
   them up in [OSV.dev](https://osv.dev). Duplicate GHSA, PYSEC and CVE records for the same
   issue are merged.
2. **Research (Tavily + Nemotron Lightning).** For each advisory it searches the web and pulls
   in the fix commit, then extracts *which code is actually vulnerable*: functions, classes,
   options and trigger conditions. OSV data rarely includes this.
3. **Reachability (Nemotron Super).** An AST index of your code finds imports and candidate
   call sites. Nemotron then decides **reachable / not reachable / uncertain** and cites
   `file:line`. Example: `yaml.load(..., Loader=FullLoader)` on uploaded data is reachable;
   `jwt.decode(..., algorithms=["HS256"])` is not affected by the algorithm-confusion CVE.
4. **Verified fix (Nemotron Ultra).** In a sandboxed copy it raises each vulnerable pin to the
   lowest patched version. It lets the resolver make only the companion bumps needed to keep
   the set installable, and skips fix versions that can't build on your Python. Then it runs
   your tests. If tests break (for example, Jinja2 3 removed `Markup` and `contextfilter`),
   Ultra reads the failures plus Tavily-sourced migration notes, edits the **application code**
   (never the tests, never security settings) and re-runs, up to N iterations.
5. **Output.** You get a prioritized report (HTML/Markdown/JSON), a `fix.patch`, and an
   **OpenVEX** document so Grype or Trivy can suppress alerts that are proven unreachable.
   There is also a CI gate (`--fail-on fix-now`).

## Why it matters
Dependency scanners flood teams with alerts, and most of them involve code the application
never runs. Teams either ignore the noise, which hides the real issues, or spend days on
upgrades that break builds. Patchwise produces a short list that comes with evidence and a
patch that has already been tested.

## How Nebius Token Factory + Nemotron are used
| Step | Model (Token Factory) | Why this tier |
|---|---|---|
| Advisory extraction (high volume) | `nvidia/Nemotron-3_5-Lightning` | Cheap ($0.06/$0.24 per M tokens), 1M context, fast |
| Reachability judgment | `nvidia/nemotron-3-super-120b-a12b` | Careful reasoning over code evidence |
| Code repair after upgrades | `nvidia/Nemotron-3-Ultra-550b-a55b` | Hardest step; called only when tests fail |

Every call goes through Token Factory's OpenAI-compatible API. Token usage and dollar cost
are tracked per model and printed in each report. You can override models with
`PATCHWISE_MODEL_FAST`, `PATCHWISE_MODEL_REASON` and `PATCHWISE_MODEL_DEEP`.

## Quick start
```bash
uv venv && . .venv/bin/activate && uv pip install -e '.[dev]'
export NEBIUS_API_KEY=...        # https://tokenfactory.nebius.com
export TAVILY_API_KEY=...        # optional; without it Patchwise uses Tavily keyless mode (rate-limited)
patchwise demo/statuspage        # writes demo/statuspage/.patchwise/report/report.html
uvicorn patchwise.web:app        # web UI on :8000
```
`patchwise <repo> --no-fix` runs triage only. `--offline` uses a crude heuristic with no LLM;
it exists for development and tests only. `pytest` runs the test suite, including an
end-to-end upgrade-and-repair test with a scripted model.

## Demo repo
`demo/statuspage` is a small service pinned in 2021: jinja2 2.11, PyYAML 5.3.1, PyJWT 1.7.1,
requests 2.25, urllib3 1.26. It has 32 unique advisories, a real reachable RCE (PyYAML
`FullLoader` on customer-uploaded YAML), many non-reachable issues, and upgrades that break
the code (Jinja2 3 API removals, PyJWT 2 `encode` now returns `str`).

## Safety
- Tests run in a copied sandbox with its own venv. Run Patchwise in a container or VM for
  untrusted repositories.
- The public web demo only runs triage on arbitrary repos; it executes tests only for the
  bundled demos.
- Model edits are limited to files inside the sandbox and cannot touch requirements or tests.
- The OpenVEX output is marked "automated; review before publishing".

## Deploy
`Dockerfile` targets Nebius Serverless Endpoints (or any container host). Inject
`NEBIUS_API_KEY` as an environment variable.

## License
Apache-2.0
