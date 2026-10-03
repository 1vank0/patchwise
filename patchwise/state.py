"""Durable counters for the public web demo (daily model budget + per-IP run history).

Two backends with the same interface:
- LocalState: a JSON file (local runs, tests).
- GcsState:   one JSON object in a Cloud Storage bucket (PATCHWISE_STATE_BUCKET), so counters survive
              cold starts and new revisions. Auth uses the instance's service account via the metadata
              server; writes use generation preconditions (optimistic locking), so concurrent updates
              never lose counts.

Any storage failure raises StateUnavailable; the web app then refuses live runs (replay-only) rather
than running without limits.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Callable

import httpx

META_TOKEN = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
GCS = "https://storage.googleapis.com"


class StateUnavailable(RuntimeError):
    pass


def today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def ip_key(ip: str) -> str:
    """Raw addresses are never stored, only a salted hash."""
    salt = os.environ.get("PATCHWISE_IP_SALT", "patchwise")
    return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()[:16]


def empty() -> dict:
    return {"day": today(), "spent": 0.0, "hits": {}}


def normalize(d: dict | None) -> dict:
    d = dict(d or {})
    if d.get("day") != today():  # new UTC day: the budget resets; run history is pruned by age
        d["day"], d["spent"] = today(), 0.0
    d.setdefault("spent", 0.0)
    now = time.time()
    d["hits"] = {k: [t for t in v if now - t < 86400] for k, v in (d.get("hits") or {}).items()}
    d["hits"] = {k: v for k, v in d["hits"].items() if v}
    return d


class LocalState:
    backend = "local"

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

    def read(self) -> dict:
        try:
            return normalize(json.loads(self.path.read_text()))
        except FileNotFoundError:
            return empty()
        except (OSError, ValueError) as e:
            raise StateUnavailable(f"state file unreadable: {e}") from e

    def update(self, fn: Callable[[dict], dict]) -> dict:
        with self.lock:
            d = fn(self.read())
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(d))
                tmp.replace(self.path)
            except OSError as e:
                raise StateUnavailable(f"state file unwritable: {e}") from e
            return d


class GcsState:
    backend = "cloud-storage"

    def __init__(self, bucket: str, obj: str = "web-guard.json", client: httpx.Client | None = None,
                 token: Callable[[], str] | None = None):
        self.bucket, self.obj = bucket, obj
        self.client = client or httpx.Client(timeout=5)
        self._token_fn = token
        self._tok: tuple[str, float] = ("", 0.0)
        self.lock = threading.Lock()

    def _token(self) -> str:
        if self._token_fn:
            return self._token_fn()
        tok, exp = self._tok
        if tok and time.time() < exp - 60:
            return tok
        r = self.client.get(META_TOKEN, headers={"Metadata-Flavor": "Google"})
        r.raise_for_status()
        d = r.json()
        self._tok = (d["access_token"], time.time() + float(d.get("expires_in", 300)))
        return self._tok[0]

    def _get(self) -> tuple[dict, int]:
        r = self.client.get(f"{GCS}/storage/v1/b/{self.bucket}/o/{self.obj}", params={"alt": "media"},
                            headers={"Authorization": f"Bearer {self._token()}"})
        if r.status_code == 404 and "no such object" in r.text.lower():
            return empty(), 0  # first use: the object doesn't exist yet (a missing *bucket* is an error)
        r.raise_for_status()
        return normalize(r.json()), int(r.headers.get("x-goog-generation", "0"))

    def read(self) -> dict:
        try:
            return self._get()[0]
        except (httpx.HTTPError, ValueError, KeyError) as e:
            raise StateUnavailable(f"cloud storage unavailable: {type(e).__name__}") from e

    def update(self, fn: Callable[[dict], dict], attempts: int = 5) -> dict:
        with self.lock:
            try:
                for _ in range(attempts):
                    d, gen = self._get()
                    d = fn(d)
                    r = self.client.post(f"{GCS}/upload/storage/v1/b/{self.bucket}/o",
                                         params={"uploadType": "media", "name": self.obj, "ifGenerationMatch": gen},
                                         headers={"Authorization": f"Bearer {self._token()}",
                                                  "Content-Type": "application/json"},
                                         content=json.dumps(d))
                    if r.status_code == 412:  # someone else wrote first: re-read and re-apply
                        time.sleep(0.2)
                        continue
                    r.raise_for_status()
                    return d
            except (httpx.HTTPError, ValueError, KeyError) as e:
                raise StateUnavailable(f"cloud storage unavailable: {type(e).__name__}") from e
            raise StateUnavailable("cloud storage busy (write conflicts)")


def from_env(work: Path):
    bucket = os.environ.get("PATCHWISE_STATE_BUCKET")
    return GcsState(bucket) if bucket else LocalState(work / "guard-state.json")
