import json
import shutil
from pathlib import Path

import pytest

from patchwise.config import Settings
from patchwise.fix import Sandbox, fix
from patchwise.llm import LLM, parse_json
from patchwise.reach import PyIndex, analyze, gather
from patchwise.research import Intel
from patchwise.scan import Dependency, Finding, Vuln, dedupe, discover

DEMO = Path(__file__).resolve().parents[1] / "demo" / "statuspage"


def v(id, aliases=(), fixed=("2.0",), sev="HIGH", summary="s", details=""):
    return Vuln(id, list(aliases), summary, details, sev, [], list(fixed))


def test_parse_json_variants():
    assert parse_json('<think>hmm</think>```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json('Sure! {"verdict": "reachable"} done') == {"verdict": "reachable"}


def test_dedupe_merges_aliases_prefers_ghsa():
    out = dedupe([v("PYSEC-1", ["CVE-1"], sev="UNKNOWN"), v("GHSA-x", ["CVE-1"], fixed=("2.1",)), v("GHSA-y")])
    assert [o.id for o in out] == ["GHSA-x", "GHSA-y"]
    assert "PYSEC-1" in out[0].aliases and out[0].fixed_versions == ["2.0", "2.1"]


def test_min_fix_takes_max_of_per_advisory_minimums():
    f = Finding(Dependency("pkg", "1.0", "PyPI", "requirements.txt"),
                [v("A", fixed=("1.2", "2.0")), v("B", fixed=("1.5",)), v("C", fixed=("0.9",))])
    assert f.min_fix == "1.5"


def test_discover_demo():
    deps = {d.name: d.version for d in discover(DEMO)}
    assert deps["pyyaml"] == "5.3.1" and deps["jinja2"] == "2.11.2"


def test_gather_finds_vulnerable_call_site():
    idx = PyIndex.build(DEMO)
    f = Finding(Dependency("pyyaml", "5.3.1", "PyPI", "requirements.txt"), [v("GHSA-8q59-q68h-6hv4")])
    ev = gather(idx, f, Intel("GHSA-8q59-q68h-6hv4", vulnerable_symbols=["yaml.load", "FullLoader"]))
    calls = [e for e in ev if e.kind == "call"]
    assert any(e.file.endswith("config.py") and "FullLoader" in e.snippet for e in calls)


class FakeLLM(LLM):
    """Scripted stand-in for Nemotron so the agent loop is testable without a key."""

    def __init__(self, replies):
        super().__init__(Settings(offline=True))
        self.replies = list(replies)
        self.prompts = []

    @property
    def online(self):
        return True

    def chat(self, tier, system, user, **kw):
        self.prompts.append((tier, user))
        self.usage.add(self.model(tier), len(user) // 4, 50)
        return self.replies.pop(0)


def test_reachability_uses_model_verdict():
    idx = PyIndex.build(DEMO)
    f = Finding(Dependency("pyjwt", "1.7.1", "PyPI", "requirements.txt"), [v("GHSA-ffqj-6fqr-9h24")])
    llm = FakeLLM(['{"verdict":"not_reachable","confidence":0.85,"rationale":"algorithms pinned",'
                   '"cited":["statuspage/auth.py:17"]}'])
    r = analyze(idx, f, Intel("GHSA-ffqj-6fqr-9h24", vulnerable_symbols=["jwt.decode"]), llm)
    assert r.verdict == "not_reachable" and r.confidence == 0.85
    assert llm.prompts[0][0] == "reason" and "auth.py" in llm.prompts[0][1]


def test_apply_edits_never_escapes_sandbox(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")
    sb = Sandbox(repo, tmp_path / "w", Settings(offline=True))
    changed = sb.apply_edits([{"file": "../r/a.py", "search": "x = 1", "replace": "x = 2"},
                              {"file": "a.py", "search": "x = 1", "replace": "x = 3"}])
    assert changed == ["a.py"] and (repo / "a.py").read_text() == "x = 1\n"
    assert (tmp_path / "w" / "a.py").read_text() == "x = 3\n"


@pytest.mark.slow
def test_repair_loop_end_to_end(tmp_path):
    """Upgrade the demo's pins for real (uv + pytest), then feed a scripted repair."""
    repo = tmp_path / "statuspage"
    shutil.copytree(DEMO, repo, ignore=shutil.ignore_patterns(".patchwise", ".venv", "__pycache__"))
    findings = [Finding(Dependency("jinja2", "2.11.2", "PyPI", "requirements.txt"), [v("J", fixed=("3.1.6",))]),
                Finding(Dependency("pyjwt", "1.7.1", "PyPI", "requirements.txt"), [v("P", fixed=("2.10.1",))])]
    edits = {"rationale": "Jinja2 3 removed Markup/contextfilter; PyJWT 2 returns str", "edits": [
        {"file": "statuspage/render.py", "search": "from jinja2 import Environment, Markup, contextfilter",
         "replace": "from jinja2 import Environment, pass_context\nfrom markupsafe import Markup"},
        {"file": "statuspage/render.py", "search": "@contextfilter", "replace": "@pass_context"},
        {"file": "statuspage/auth.py", "search": '    return token.decode("utf-8")',
         "replace": '    return token if isinstance(token, str) else token.decode("utf-8")'}]}
    llm = FakeLLM([json.dumps(edits), '{"ok": true, "concerns": []}'])
    res = fix(repo, findings, Settings(offline=True), llm, None, log=lambda *a: None)
    assert res.baseline.ok
    assert res.status == "verified_with_code_changes", (res.final.summary, res.final.output[-800:])
    assert res.compat_bumps.get("markupsafe")
    assert "pass_context" in res.diff and "jinja2==3.1.6" in res.diff
    assert res.review == {"ok": True, "concerns": []} and llm.prompts[-1][0] == "reason"
    assert res.patch_applies and res.patch_tests.ok


def test_repair_cannot_introduce_security_regressions(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "c.py").write_text("import yaml\nx = yaml.load(raw, Loader=yaml.FullLoader)\nr = get(u)\n")
    sb = Sandbox(repo, tmp_path / "w", Settings(offline=True))
    rejected = []
    changed = sb.apply_edits([
        {"file": "c.py", "search": "yaml.load(raw, Loader=yaml.FullLoader)", "replace": "yaml.unsafe_load(raw)"},
        {"file": "c.py", "search": "get(u)", "replace": "get(u, verify=False)"},
    ], rejected)
    assert changed == [] and {p for r in rejected for p in r["patterns"]} == {
        "yaml unsafe loader", "TLS verification disabled"}
    # safe edits still apply, and pre-existing patterns may be kept
    assert sb.apply_edits([{"file": "c.py", "search": "x = yaml.load(raw, Loader=yaml.FullLoader)",
                            "replace": "x = yaml.safe_load(raw)"}]) == ["c.py"]


def test_parse_json_tolerates_reasoning_and_sloppy_json():
    leaked = ('Here\'s a thinking process: the user wants {verdict}. I think it\'s reachable.\n'
              '{"verdict": "reachable", "cited": ["a.py:3"],}')
    assert parse_json(leaked, ("verdict",))["verdict"] == "reachable"
    assert parse_json("</think>{'verdict': 'uncertain', 'ok': True}")["ok"] is True
    nested = 'x {"rationale": "r", "edits": [{"file": "a.py", "search": "{", "replace": "}"}]} y'
    assert parse_json(nested, ("edits",))["edits"][0]["search"] == "{"
    with pytest.raises(Exception):
        parse_json("no json here")
    with pytest.raises(Exception):  # a lone inner fragment is not the requested answer
        parse_json('{"file": "a.py", "search": "x", "replace": "y"}', ("edits", "pin_bumps"))


def test_llm_retries_rate_limits_then_fails_fast_on_4xx(monkeypatch):
    import httpx
    import openai

    s = Settings(nebius_api_key="test-key", offline=False, llm_retries=3)
    llm = LLM(s)
    llm._sleep = lambda *_: None
    req = httpx.Request("POST", "https://x/v1/chat/completions")

    class Resp:
        class usage:
            prompt_tokens, completion_tokens = 10, 5

        def __init__(self, content, finish="stop"):
            msg = type("M", (), {"content": content, "model_extra": {}})()
            self.choices = [type("C", (), {"message": msg, "finish_reason": finish})()]

    calls = []

    def flaky(model, messages, max_tokens, temperature, thinking):
        calls.append((max_tokens, thinking))
        if len(calls) == 1:
            raise openai.RateLimitError("slow down", response=httpx.Response(429, request=req), body=None)
        if len(calls) == 2:
            raise openai.APITimeoutError(request=req)
        if len(calls) == 3:
            return Resp("Let me think about this carefully", finish="length")  # truncated reasoning
        return Resp('{"verdict": "reachable"}')

    monkeypatch.setattr(llm, "_create", flaky)
    assert llm.chat_json("reason", "s", "u", max_tokens=100, want=("verdict",)) == {"verdict": "reachable"}
    # rate limit + timeout are retried; truncated reasoning is retried once with thinking off
    assert calls == [(100, True), (100, True), (100, True), (100, False)] and llm.usage.retries == 3

    def bad(*a, **k):
        calls.append("bad")
        raise openai.BadRequestError("nope", response=httpx.Response(400, request=req), body=None)

    calls.clear()
    monkeypatch.setattr(llm, "_create", bad)
    with pytest.raises(Exception, match="BadRequestError"):
        llm.chat("fast", "s", "u")
    assert calls == ["bad"]


def test_test_summary_parses_pytest_and_unittest():
    from patchwise.fix import _summ
    assert _summ("..\n==== 3 passed, 2 warnings in 0.1s ====\n") == "3 passed, 2 warnings in 0.1s"
    assert _summ("....\n----\nRan 161 tests in 1.308s\n\nOK\n") == "161 tests in 1.308s: OK"
    assert _summ("F.\nRan 2 tests in 0.1s\n\nFAILED (failures=1)\n").endswith("FAILED (failures=1)")


def test_template_filters_are_indexed_as_evidence(tmp_path):
    (tmp_path / "app.py").write_text("import jinja2\n")
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "page.html").write_text("<p>{{ name|e }}</p>\n<div {{ attrs|xmlattr }}></div>\n")
    idx = PyIndex.build(tmp_path)
    f = Finding(Dependency("jinja2", "3.1.2", "PyPI", "requirements.txt"), [v("GHSA-h5c8-rqwp-cp95")])
    ev = gather(idx, f, Intel("GHSA-h5c8-rqwp-cp95", vulnerable_symbols=["jinja2.filters.do_xmlattr", "xmlattr"]))
    assert [(e.file, e.line, e.kind) for e in ev if e.kind == "template"] == [("templates/page.html", 2, "template")]


def test_fuzzy_edit_fixes_model_indentation(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "w.py").write_text("babel = Babel(app)\n\n\n@babel.localeselector\ndef get_locale():\n    return 'en'\n")
    sb = Sandbox(repo, tmp_path / "w", Settings(offline=True))
    edit = {"file": "w.py", "search": "@babel.localeselector\n    def get_locale():",
            "replace": "def get_locale():"}
    assert sb.apply_edits([edit]) == ["w.py"]
    assert (tmp_path / "w" / "w.py").read_text().endswith("\n\ndef get_locale():\n    return 'en'\n")
    # an edit that would leave the module unparsable is not applied
    assert sb.apply_edits([{"file": "w.py", "search": "    return 'en'", "replace": "  return ("}]) == []


def test_min_fix_never_picks_a_prerelease():
    f = Finding(Dependency("sqlalchemy", "1.1.11", "PyPI", "requirements.txt"),
                [v("A", fixed=("1.2.18", "1.3.0b3")), v("B", fixed=("1.3.0b3",))])
    assert f.min_fix == "1.3.0"


def test_sandbox_snapshot_restore(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")
    sb = Sandbox(repo, tmp_path / "w", Settings(offline=True))
    sb.apply_edits([{"file": "a.py", "search": "x = 1", "replace": "x = 2"}])
    snap = sb.snapshot()
    sb.apply_edits([{"file": "a.py", "search": "x = 2", "replace": "x = 3"}])
    (tmp_path / "w" / "b.py").write_text("y = 1\n")
    sb.restore(snap)
    assert (tmp_path / "w" / "a.py").read_text() == "x = 2\n" and not (tmp_path / "w" / "b.py").exists()


# --- consistency, platform, dev-only, fix scope -------------------------------------------

def test_platform_limited_advisory_is_not_reachable_on_linux_without_a_model_call():
    from patchwise.research import platform_limits
    idx = PyIndex.build(DEMO)
    f = Finding(Dependency("werkzeug", "2.0.0", "PyPI", "requirements.txt"),
                [v("GHSA-x", summary="Werkzeug safe_join() allows Windows special device names")])
    intel = Intel("GHSA-x", vulnerable_symbols=["werkzeug.utils.safe_join"],
                  platforms=platform_limits(f.vulns[0].summary, ["windows"]))
    llm = FakeLLM([])
    r = analyze(idx, f, intel, llm)
    assert r.verdict == "not_reachable" and r.method == "platform" and not llm.prompts
    assert analyze(idx, f, intel, FakeLLM(['{"verdict":"reachable","cited":[]}']), deploy_os="windows").verdict == "reachable"
    assert platform_limits("High resource usage when parsing multipart form data", ["windows"]) == []


def test_sibling_advisories_get_one_verdict_and_platform_groups_stay_apart():
    from patchwise.reach import analyze_group, group_advisories
    idx = PyIndex.build(DEMO)
    f = Finding(Dependency("certifi", "2020.1.1", "PyPI", "requirements.txt"),
                [v("GHSA-a", summary="Removal of e-Tugra root certificate"),
                 v("GHSA-b", summary="Certifi removes GLOBALTRUST root certificate"),
                 v("GHSA-c", summary="Windows only thing")])
    intels = [Intel("GHSA-a", ["certifi.where"]), Intel("GHSA-b", ["certifi.where"]),
              Intel("GHSA-c", ["certifi.where"], platforms=["windows"]), Intel("GHSA-d", ["certifi.contents"])]
    f.vulns.append(v("GHSA-d", summary="Unrelated parsing bug"))
    llm = FakeLLM(['{"groups": [["GHSA-a", "GHSA-b", "GHSA-c", "GHSA-d", "GHSA-zzz"]]}'])
    groups = group_advisories(f, intels, llm)
    # the platform-limited one and the unrelated one (no shared symbols, different summary) split off
    assert [[i.vuln_id for i in g] for g in groups] == [["GHSA-a", "GHSA-b"], ["GHSA-c"], ["GHSA-d"]]
    llm2 = FakeLLM(['{"verdict":"not_reachable","confidence":0.8,"rationale":"x","cited":[]}'])
    rs = analyze_group(idx, f, groups[0], llm2)
    assert {r.vuln_id for r in rs} == {"GHSA-a", "GHSA-b"} and {r.verdict for r in rs} == {"not_reachable"}
    assert rs[0].group == ["GHSA-b"] and len(llm2.prompts) == 1 and "judge together" in llm2.prompts[0][1]


def test_dev_only_dependencies_are_review_not_fix_now(tmp_path):
    from patchwise.pipeline import Item
    from patchwise.reach import Reachability, dev_only, is_test_path
    repo = tmp_path / "r"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "testing.py").write_text("import selenium\n")
    (repo / "app" / "main.py").write_text("import yaml\n")
    idx = PyIndex.build(repo)
    sel = Finding(Dependency("selenium", "3.0", "PyPI", "requirements.txt"), [v("X")])
    yml = Finding(Dependency("pyyaml", "5.1", "PyPI", "requirements.txt"), [v("Y")])
    dev = Finding(Dependency("pytest", "6.0", "PyPI", "requirements-dev.txt"), [v("Z")])
    assert "test/dev code" in dev_only(idx, sel, []) and dev_only(idx, yml, []) == ""
    assert "dev/test requirements" in dev_only(idx, dev, [])
    assert is_test_path("tests/x.py") and is_test_path("pkg/conftest.py") and not is_test_path("app/views.py")
    it = Item(sel, "X", Intel("X"), Reachability("X", "reachable", 0.9, "r", dev_only="imported only from tests"))
    assert it.priority == "review"


def test_brotli_through_urllib3_is_marked_auto_used():
    from patchwise.reach import auto_note
    assert "brotli" in auto_note("requests > urllib3 (optional extra)", "brotli")
    assert auto_note("requests", "urllib3") == ""


def test_fix_targets_respect_scope_and_only_raise_as_far_as_needed():
    from patchwise.pipeline import Item, fix_targets
    from patchwise.reach import Reachability
    f = Finding(Dependency("pyjwt", "1.7.1", "PyPI", "requirements.txt"),
                [v("A", fixed=("2.4.0",)), v("B", fixed=("2.12.0",))])
    g = Finding(Dependency("jinja2", "2.11.2", "PyPI", "requirements.txt"), [v("C", fixed=("3.1.6",))])
    items = [Item(f, "A", Intel("A"), Reachability("A", "reachable", .9, "")),
             Item(f, "B", Intel("B"), Reachability("B", "not_reachable", .9, "")),
             Item(g, "C", Intel("C"), Reachability("C", "uncertain", .5, ""))]
    t = fix_targets(items)
    assert [(x.dep.name, x.min_fix) for x in t] == [("pyjwt", "2.4.0")]
    assert {x.dep.name for x in fix_targets(items, "review")} == {"pyjwt", "jinja2"}
    assert [x.min_fix for x in fix_targets(items, "all") if x.dep.name == "pyjwt"] == ["2.12.0"]


def test_project_code_never_sees_api_keys(monkeypatch):
    from patchwise.fix import safe_env
    monkeypatch.setenv("NEBIUS_API_KEY", "secret")
    monkeypatch.setenv("TAVILY_API_KEY", "secret")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    env = safe_env({"VIRTUAL_ENV": "/v"})
    assert "NEBIUS_API_KEY" not in env and "GITHUB_TOKEN" not in env and env["VIRTUAL_ENV"] == "/v"
    assert "PATH" in env
