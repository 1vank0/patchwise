import pytest


@pytest.fixture(autouse=True)
def _no_real_ledger(monkeypatch):
    """Scripted/mocked model calls must never land in a real spend ledger."""
    monkeypatch.delenv("PATCHWISE_SPEND_LOG", raising=False)
