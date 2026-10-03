from types import SimpleNamespace

from patchwise.web import client_ip


def _req(headers, host="10.0.0.1"):
    return SimpleNamespace(headers={k.lower(): v for k, v in headers.items()}, client=SimpleNamespace(host=host))


def test_client_ip_cloud_run_uses_last_xff(monkeypatch):
    monkeypatch.setenv("PATCHWISE_CLIENT_IP", "xff-last")
    # a client can prepend a fake address; the Google front end appends the real one
    r = _req({"X-Forwarded-For": "1.2.3.4, 203.0.113.9", "Fly-Client-IP": "9.9.9.9"})
    assert client_ip(r) == "203.0.113.9"


def test_client_ip_fly(monkeypatch):
    monkeypatch.setenv("PATCHWISE_CLIENT_IP", "fly")
    assert client_ip(_req({"Fly-Client-IP": "198.51.100.7", "X-Forwarded-For": "1.1.1.1"})) == "198.51.100.7"


def test_client_ip_fallback(monkeypatch):
    monkeypatch.delenv("PATCHWISE_CLIENT_IP", raising=False)
    assert client_ip(_req({})) == "10.0.0.1"
