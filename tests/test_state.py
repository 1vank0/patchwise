import json

import httpx
import pytest
from fastapi import HTTPException

from patchwise import state, web


class FakeGcs:
    """Minimal Cloud Storage JSON API: one object, generation numbers, ifGenerationMatch."""

    def __init__(self):
        self.body, self.gen, self.down, self.conflicts = None, 0, False, 0

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("unreachable")
        assert req.headers["authorization"] == "Bearer t"
        if req.method == "GET":
            if self.body is None:
                return httpx.Response(404)
            return httpx.Response(200, content=self.body, headers={"x-goog-generation": str(self.gen)})
        want = int(req.url.params["ifGenerationMatch"])
        if self.conflicts:
            self.conflicts -= 1
            self.gen += 1  # simulate another writer
            return httpx.Response(412)
        if want != self.gen:
            return httpx.Response(412)
        self.body, self.gen = req.content, self.gen + 1
        return httpx.Response(200, json={"generation": str(self.gen)})


@pytest.fixture
def gcs():
    fake = FakeGcs()
    store = state.GcsState("b", client=httpx.Client(transport=httpx.MockTransport(fake)), token=lambda: "t")
    return fake, store


@pytest.fixture
def guard(gcs, monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "x")
    monkeypatch.setattr(web, "DAILY_BUDGET", 0.50)
    monkeypatch.setattr(web, "PER_HOUR", 3)
    monkeypatch.setattr(web, "PER_DAY", 8)
    monkeypatch.setattr(web, "MAX_CONCURRENT", 5)
    return web.Guard(gcs[1])


def test_counters_persist_across_instances(gcs, guard):
    fake, store = gcs
    guard.acquire("203.0.113.9")
    guard.release()
    guard.add_spend(0.12)
    # a new instance (cold start / new revision) reads the same counters
    g2 = web.Guard(state.GcsState("b", client=store.client, token=lambda: "t"))
    d = g2.snapshot(fresh=True)
    assert d["spent"] == 0.12 and g2.runs_left("203.0.113.9") == 2
    assert "203.0.113.9" not in fake.body.decode()  # only hashed addresses are stored


def test_rate_limit_and_refund(guard):
    for _ in range(3):
        guard.acquire("198.51.100.1")
        guard.release()
    with pytest.raises(HTTPException) as e:
        guard.acquire("198.51.100.1")
    assert e.value.status_code == 429
    guard.refund("198.51.100.1")
    assert guard.runs_left("198.51.100.1") == 1
    guard.acquire("192.0.2.5")  # other addresses are unaffected


def test_daily_budget_blocks_live(guard):
    guard.add_spend(0.51)
    ok, why = guard.live_status(fresh=True)
    assert not ok and "budget" in why
    with pytest.raises(HTTPException) as e:
        guard.acquire("192.0.2.7")
    assert e.value.status_code == 503


def test_storage_outage_fails_safe(gcs, guard):
    fake, _ = gcs
    fake.down = True
    ok, why = guard.live_status(fresh=True)
    assert not ok and "paused" in why
    assert guard.runs_left("192.0.2.8") == 0
    with pytest.raises(HTTPException) as e:
        guard.acquire("192.0.2.8")
    assert e.value.status_code == 503 and guard.running == 0


def test_write_conflict_is_retried(gcs, guard):
    fake, _ = gcs
    guard.add_spend(0.01)
    fake.conflicts = 2
    guard.add_spend(0.02)
    assert json.loads(fake.body)["spent"] == 0.03


def test_job_spend_counts_killed_runs(tmp_path):
    job = web.Job("demo", "x")
    job.out = tmp_path
    (tmp_path / "spend.jsonl").write_text('{"cost_usd": 0.01}\n{"cost_usd": 0.02}\n')
    assert abs(web.job_spend(job) - 0.03) < 1e-9


def test_new_day_resets_budget_keeps_recent_hits(monkeypatch):
    d = state.normalize({"day": "2000-01-01", "spent": 9, "hits": {"k": [0.0]}})
    assert d["spent"] == 0.0 and d["hits"] == {}
