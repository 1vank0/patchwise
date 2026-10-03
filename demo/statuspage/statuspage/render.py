"""Server-side rendering of the public status page."""
from jinja2 import Environment, Markup, contextfilter

STATUS_COLORS = {"up": "#1a7f37", "degraded": "#9a6700", "down": "#cf222e"}


@contextfilter
def status_badge(ctx, status):
    color = STATUS_COLORS.get(status, "#57606a")
    label = ctx.get("labels", {}).get(status, status)
    return Markup(f'<span class="badge" style="background:{color}">{Markup.escape(label)}</span>')


env = Environment(autoescape=True)
env.filters["badge"] = status_badge

PAGE = env.from_string(
    "<h1>{{ title }}</h1><ul>{% for s in services %}"
    "<li>{{ s.name }} {{ s.status|badge }}</li>{% endfor %}</ul>"
)


def render_page(title: str, services: list, labels: dict | None = None) -> str:
    return PAGE.render(title=title, services=services, labels=labels or {})
