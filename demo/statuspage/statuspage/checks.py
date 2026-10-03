"""Polls each service's health endpoint."""
import requests


def check(url: str, timeout: float = 3.0) -> str:
    try:
        r = requests.get(url, timeout=timeout)
    except requests.RequestException:
        return "down"
    if r.status_code == 200:
        return "up"
    return "degraded" if r.status_code < 500 else "down"
