# Patchwise — results on real repositories

Generated 2026-10-03 with the code at patchwise commit `4cd3e70` (searx: see note).
Table produced by `python3 runs/summarize.py demo microblog searx flasky`; full
reports (HTML/Markdown/JSON, OpenVEX, fix.patch, run.log) are in `runs/<name>/`.

| Run | Pinned deps | Vuln. pkgs | Raw advisories | Fix now | Uncertain | Not reachable | Fix status | Tests (baseline → after) | Repair rounds | Wall time | Nemotron calls | Tavily calls | Model cost |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| demo (bundled `demo/statuspage`) | 6 | 5 | 32 | 6 | 1 | 25 | verified_with_code_changes | 3 passed → 3 passed | 2 | 87 s | 68 | 35 | $0.049 |
| microblog (miguelgrinberg/microblog @ a975ef6) | 54 | 18 | 54 | 7 | 1 | 46 | verified (no code changes; httpie raised to 3.2.4 to satisfy security minimums) | 4 passed → 4 passed | 0 | 125 s | 112 | 54 | $0.083 |
| searx (searx/searx @ 00abe3d) | 32 | 8 | 18 | 3 | 3 | 12 | tests green, **but reviewer concerns unresolved → not mergeable** (saved report says verified_with_code_changes; predates the `tests_pass_needs_review` rule) | 161 OK → 161 OK | 7 | 359 s | 48 | 21 | $0.269 |
| flasky (miguelgrinberg/flasky @ 3beedd6) | 44 | 19 | 70 | 4 | 2 | 64 | tests_fail — fixed versions need Python ≥ 3.10, project targets 3.8 | 34 passed, 1 skipped → install failed | 0 | 233 s | 151 | 70 | $0.098 |

Noise reduction: 174 raw advisories across the three real repos → 14 fix-now, 6 for review,
154 deprioritised with a cited reason. Wall times are for sequential runs on one box
(shared network/pip cache); they include venv creation and test runs.

## How each run was invoked

```
python -m patchwise.cli demo/statuspage --out runs/demo
python -m patchwise.cli runs/src-microblog --python 3.11 \
    --test-cmd "python -m pytest -q -p no:cacheprovider tests.py" --out runs/microblog
PATCHWISE_MAX_REPAIRS=7 python -m patchwise.cli runs/src-searx --python 3.11 \
    --test-cmd "python -m nose2 -s tests/unit" --with "werkzeug==2.2.3" --out runs/searx
python -m patchwise.cli runs/src-flasky --python 3.8 --requirements requirements/dev.txt \
    --test-cmd "SERVER_NAME=localhost python -m pytest -q -p no:cacheprovider tests" --out runs/flasky
```

searx leaves Werkzeug unpinned and today's Werkzeug 3 breaks its own baseline, so the
baseline is pinned with `--with werkzeug==2.2.3`; Patchwise drops that test-only pin when it
conflicts with the fix.

## Demo criteria (runs/demo)

- (a) PASS — PyYAML GHSA-8q59-q68h-6hv4 is **fix now**, citing `yaml.load(..., Loader=FullLoader)` on uploaded YAML at `statuspage/config.py:7`.
- (b) PASS — PyJWT GHSA-ffqj-6fqr-9h24 (key confusion) is **not reachable**, because `jwt.decode` pins `algorithms=["HS256"]` with a string secret. The sibling PyJWT key-confusion advisories (GHSA-xgmm, GHSA-ffc3) get the same verdict.
- (c) PASS (with caveats) — 6 fix now, 1 review, 25 not reachable. The urllib3 decompression/chunked-read advisories are reachable via `requests.get` on fetched URLs, which is defensible. The debatable items are PyJWT `crit` (GHSA-752w) and PYSEC-2025-183 (a disputed weak-key CVE, flagged because the secret is the hard-coded `"change-me"`).
- (d) PASS — Ultra repaired the code with no help: in round 1 Jinja2 3 needed `pass_context` and `from markupsafe import Markup`; in round 2 PyJWT 2 returns `str`. Tests 3 → 3 pass. The patch re-applied with `git apply` to a pristine copy and passed again, and Super's review came back OK. PyYAML landed on 6.0 because 5.4.x doesn't build on Python 3.11.

## Spot-check of verdicts (by hand)

Correct and useful:
- Jinja2 sandbox and `xmlattr` advisories are not reachable in all repos. Patchwise indexed the filters actually used in the templates (searx: 55 templates, no `xmlattr` or `attr`).
- SQLAlchemy `order_by`/`group_by` injection is not reachable (no user input reaches them). bleach mutation-XSS is not reachable (`strip=True` with a safe tag list).
- microblog: the Werkzeug multipart DoS (GHSA-q34m) is now **fix now**. Flask parses forms on every request, and the framework-wrapper rule caught this; the run before that rule missed it.
- searx: the lxml `iterparse`/XXE advisory is not reachable, since only `html.fromstring`/`etree.fromstring` are used.

Wrong or debatable (known limits):
- **Windows-only `safe_join` advisories in microblog are inconsistent.** Two of the four near-identical advisories came out fix-now and two not reachable. All four should be deprioritised on a Linux deployment. Root cause: the model has no deployment-OS context, and verdicts per advisory are made independently.
- **flasky Werkzeug multipart DoS:** GHSA-xg9f is "review" (it was "not reachable" before the framework rule). The near-duplicate PYSEC-2023-221 is still "not reachable". This is the same cross-advisory inconsistency.
- **flasky Werkzeug debugger (GHSA-2g68, GHSA-gq9m) are fix-now** because `DevelopmentConfig.DEBUG = True`. Production config doesn't enable it, so this is arguably a false positive. The prompt asks for production config, but the model still flagged them.
- **searx selenium PYSEC-2023-206 is fix-now**, but selenium is used only by `searx/testing.py` (robot tests). Test-only and dev dependencies aren't separated yet.
- **certifi root removals:** e-Tugra came out fix-now and GLOBALTRUST not reachable, which is inconsistent. Both are trust-store hygiene issues and should get the same verdict.
- **searx brotli GHSA-2qfp is not reachable**, but urllib3 decodes `br` automatically when brotli is installed, so a malicious upstream could reach it. The transitive edge was found (`requests > urllib3 > brotli`); the model still said no.

## Fix-step findings

- **searx, a regression that tests don't catch:** the green fix raised flask-babel to 4.0.0 and babel to 2.12.0. It removed `@babel.localeselector` but never registered `Babel(app, locale_selector=...)`, so locale selection silently stops. It also rebinds `get_translations = _get_translations`, which causes infinite recursion and drops the Occitan monkeypatch. All 161 unit tests still pass. Super's post-fix review flagged both problems; I confirmed them by hand. With the current code this status is `tests_pass_needs_review`. Patch: `runs/searx/fix.patch`. The lxml `_ElementStringResult` edit in the same patch looks correct.
- **Ultra repair is not deterministic on hard upgrades.** Across four searx runs: green but incomplete once, failed twice, green with reviewer concerns once. The repair loop runs at temperature 0, and it still varies (thinking traces differ).
- **flasky:** the fixed bleach (6.4.0) and others require Python ≥ 3.10, and the project targets 3.8. Patchwise reports the resolver conflict and makes no code changes. This is the correct, honest outcome: the real fix is a Python upgrade.
- **microblog:** a pure version bump. The only resolver adjustment was httpie 3.2.3 → 3.2.4 to meet the security minimums.

## Spend

The model spend ledger (`runs/spend.jsonl`) totals **$3.51 across 2,358 Nemotron calls** for all development, debugging and evaluation runs. That's under the $5 cap. A typical full scan + fix run costs $0.05–$0.27.
