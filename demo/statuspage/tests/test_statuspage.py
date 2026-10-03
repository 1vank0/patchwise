from statuspage.auth import issue_admin_token, verify_admin_token
from statuspage.config import load_tenant_config
from statuspage.render import render_page


def test_render_badges_and_escaping():
    html = render_page("Acme", [{"name": "API", "status": "up"}, {"name": "<b>DB</b>", "status": "down"}],
                       labels={"up": "Operational"})
    assert 'class="badge"' in html and "Operational" in html
    assert "&lt;b&gt;DB&lt;/b&gt;" in html


def test_token_roundtrip():
    tok = issue_admin_token("ivan")
    assert isinstance(tok, str)
    assert verify_admin_token(tok) == "ivan"


def test_tenant_config():
    cfg = load_tenant_config("title: Acme\nservices:\n  - name: API\n    url: https://example.com/health\n")
    assert cfg["title"] == "Acme"
