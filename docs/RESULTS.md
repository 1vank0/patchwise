# Patchwise: results on real repositories

Updated 2026-10-03 (evening ET) for the **consistency release**. That release added:
- sibling-advisory grouping
- platform awareness
- dev/test-only dependency handling
- auto-used transitive packages
- verified fixes that upgrade **only fix-now advisories** by default
- a repair budget of 8

The demo, microblog and searx (triage) were re-run on this code. The flasky row and the searx *fix* row are from the
previous release (marked). Full reports are in `runs/<name>/`: report.html/md/json, openvex.json, fix.patch, run.log.

## Current results (consistency release)

| Run | Pinned deps | Vuln. pkgs | Raw advisories | Judgments¹ | Fix now | Review | Not reachable | Fix status (scope: fix-now) | Upgrades applied | Tests (baseline → after) | Repair rounds | Wall time | Nemotron calls | Model cost |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| demo (`demo/statuspage`) | 6 | 5 | 32 | 31 | 6 | 0 | 26 | verified_with_code_changes | pyyaml 5.3.1→6.0, pyjwt 1.7.1→2.12.0, urllib3 1.26.4→2.6.0, requests 2.25.1→2.32.4 | 3 passed → 3 passed | 1 | 78 s | 68 | $0.043 |
| microblog (miguelgrinberg/microblog @ a975ef6) | 54 | 18 | 54 | 51 | 2 | 1 | 51 | verified | pyjwt 2.8.0→2.12.0, certifi 2023.11.17→2024.7.4 | 4 passed → 4 passed | 0 | 188 s | 115 | $0.087 |
| searx triage (searx/searx @ 00abe3d) | 32 | 8 | 18 | 16 | 4 | 2 | 12 | (triage only, `--no-fix`) | – | – | – | 49 s | 39 | $0.046 |

¹ Judgments are the independent verdicts after sibling grouping and the platform rule. Grouped siblings always share one verdict.

**Noise reduction:** across these three runs, 104 raw alerts became 12 fix-now and 3 for review, and 89 were set aside with a cited
reason. Under the previous release microblog alone had 7 fix-now. Five of those came from the issues fixed here:
two Windows-only `safe_join` advisories, and urllib3 decompression issues on calls to a fixed, trusted API endpoint.

**Fix scope:** microblog's verified fix now touches only the two packages with reachable advisories (pyjwt and certifi). The
previous release upgraded every vulnerable package, including httpie. The demo still exercises the full repair loop:
PyJWT 2 returns `str` from `encode`, the tests fail, Nemotron Ultra edits `statuspage/auth.py` in one round, the patch re-applies
to a clean copy and passes there, and the Super review reports no concerns.

### Demo criteria (runs/demo, plus the recorded replay and a live run through the web UI)
- **(a) PASS:** PyYAML GHSA-8q59-q68h-6hv4 is **fix now**, citing `statuspage/config.py:7` (`yaml.load(raw, Loader=yaml.FullLoader)` on customer uploads).
- **(b) PASS:** PyJWT GHSA-ffqj-6fqr-9h24 is **not reachable** (`algorithms=["HS256"]` with a string secret). GHSA-xgmm and GHSA-ffc3 are also not reachable.
- **(c) PASS:** 6 fix now. They are PyYAML RCE; PyJWT unknown-`crit` header on bearer tokens from the admin API's Authorization header; PyJWT
  PYSEC-2025-183 (hard-coded `"change-me"` secret; no patched release exists, and the report says to mitigate in code); urllib3 decompression
  and URL-parser issues on tenant-supplied health-check URLs; and requests' `.netrc` leak via redirects. Jinja2's sandbox and `xmlattr` advisories are
  not reachable (the demo uses neither). Across four demo runs today the fix-now count ranged from **5 to 7**. The variation is
  confined to low-impact PyJWT/urllib3 items (for example PyJWT GHSA-hxm8 revocation bypass). Criteria (a), (b) and (d) held in every run.
- **(d) PASS:** verified_with_code_changes, as above. Jinja2 is no longer upgraded because none of its advisories are reachable, so the
  Jinja2 3 repair that earlier runs showed does not happen by default (`--fix-scope all` brings it back).
- Note: the demo's `auth.py` docstring now states where tokens come from: the Authorization header of admin API requests. That is the
  realistic use of such a verifier, and it makes the `crit` advisory reachable. Without it the token source was invisible to the model.

## What the consistency work fixed (spot-checked by hand)
- **Windows-only advisories:** the Werkzeug `safe_join` family (GHSA-29vq, -hgf8, -87hc, -f9vj) in microblog was split 2 fix-now /
  2 not reachable before. All four are now **not reachable** by a deterministic platform rule ("Only affects Windows; this
  project deploys on Linux"), with no model call. Mako GHSA-2h4p (Windows) and setuptools GHSA-h35f (macOS) get the same rule.
  The rule needs both the model's platform claim and an OS mention in the advisory text, which guards against hallucinated limits.
- **certifi root removals in searx:** e-Tugra was fix-now and GLOBALTRUST not reachable before. They are now grouped and share one verdict.
- **brotli via urllib3 in searx:** was not reachable before. It is now **fix now**: urllib3 decodes `br` responses automatically whenever
  brotli is installed, and searx fetches arbitrary upstream pages.
- **selenium in searx:** was fix-now before. It is now **review**: it is pinned only in `requirements-dev.txt` and used only by `searx/testing.py`.
- **Over-grouping guard:** the first grouping attempt (Lightning) merged four unrelated requests advisories (`.netrc` leak, Session verify,
  temp-file reuse, Proxy-Authorization leak) and gave all four one verdict. Grouping now uses Super with a stricter prompt, plus a
  deterministic check: grouped advisories must share distinctive vulnerable symbols or most of their summary wording.

## Known weaknesses that remain
- **Werkzeug multipart DoS (GHSA-q34m) in microblog is still judged not reachable.** The model reasons that no view reads
  `request.form`/`files`, but Flask-WTF forms do that on every POST. The previous release once got this right. The verdict flips between runs.
- **Run-to-run variance on low-impact items** (demo fix-now 5–7, see above), even at temperature 0.
- **searx lxml GHSA-vfmq** (iterparse/ETCompatXMLParser defaults) is now fix-now, citing `etree.fromstring` on network content. That is debatable:
  the advisory is about `iterparse` and `ETCompatXMLParser`.
- **Context sensitivity of the requests `.netrc` leak:** fix-now in the demo (tenant-supplied URLs), not reachable in microblog (one fixed
  API endpoint) and in searx. The microblog and demo verdicts look right; searx is debatable, because it fetches user-influenced URLs.

## Previous release (for reference; not re-run)

| Run | Raw advisories | Fix now | Uncertain | Not reachable | Fix status | Tests | Repair rounds | Model cost |
|---|---|---|---|---|---|---|---|---|
| searx fix run (00abe3d, `--python 3.11 --test-cmd "python -m nose2 -s tests/unit" --with werkzeug==2.2.3`, 7 repairs, upgrade of all advisories) | 18 | 3 | 3 | 12 | tests green, but the reviewer flagged real regressions → **not mergeable** (would be `tests_pass_needs_review` now) | 161 OK → 161 OK | 7 | $0.269 |
| flasky (3beedd6, `--python 3.8 --requirements requirements/dev.txt`) | 70 | 4 | 2 | 64 | tests_fail: the fixed versions need Python ≥ 3.10, the project targets 3.8 | 34 passed, 1 skipped → install failed | 0 | $0.098 |

**searx regression the tests don't catch** (confirmed by hand): the flask-babel 4 fix removed `@babel.localeselector` without
registering `locale_selector=`, and added a self-recursive `get_translations`. All 161 tests still passed. The Super post-fix
review flagged both problems. Ultra's repair on this hard upgrade was non-deterministic across four runs (green but incomplete, two failures,
and green with concerns).

## How each run was invoked
```
python -m patchwise.cli demo/statuspage --out runs/demo
python -m patchwise.cli runs/src-microblog --python 3.11 --test-cmd "python -m pytest -q -p no:cacheprovider tests.py" --out runs/microblog
python -m patchwise.cli runs/src-searx --no-fix --out runs/searx-triage
```
Wall times are for sequential runs on one shared box and include venv creation and test runs.

## Spend
The ledger (`runs/spend.jsonl`) holds all development, debugging and evaluation runs. Totals are in STATUS.md. A typical run costs $0.04–0.09; a hard repair
like searx costs about $0.27.
