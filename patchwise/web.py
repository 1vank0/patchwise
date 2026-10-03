"""Patchwise web demo.

Judges can (1) run the full pipeline live on the bundled demo project with one click, (2) watch an
instant replay of a recorded live run (no credits needed), or (3) paste a public GitHub repo for a
triage-only run. Guards for a public deployment:

* per-run model cost cap (PATCHWISE_WEB_MAX_COST, default $0.40) and a daily budget
  (PATCHWISE_DAILY_BUDGET, default $3); when exhausted, live runs are disabled and the replay remains
* at most PATCHWISE_MAX_CONCURRENT live runs at a time (default 1)
* per-IP rate limits (PATCHWISE_RUNS_PER_IP_HOUR=3, PATCHWISE_RUNS_PER_IP_DAY=8)
* wall-clock timeout per run (PATCHWISE_RUN_TIMEOUT, default 600 s): the run is a subprocess and is killed
* GitHub repos: https://github.com/<owner>/<repo> only, size checked before cloning
  (PATCHWISE_MAX_REPO_MB=40), shallow clone with a timeout, and triage only: untrusted repos never get
  their tests executed unless PATCHWISE_ALLOW_FIX=1
* secrets: API keys live only in the server environment; project code (installs, tests) gets an
  environment with every *KEY/TOKEN/SECRET* variable removed, and log lines are scrubbed of key values
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import OrderedDict, defaultdict, deque
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .report import render_html

PKG = Path(__file__).resolve().parent
ROOT = PKG.parent
ASSETS = PKG / "assets"
DEMO = ROOT / "demo" / "statuspage"
REPLAY = PKG / "replay" / "demo.json"
WORK = Path(os.environ.get("PATCHWISE_WORK_DIR", Path(tempfile.gettempdir()) / "patchwise-web"))

ENV = os.environ.get
MAX_COST = float(ENV("PATCHWISE_WEB_MAX_COST", "0.40"))
DAILY_BUDGET = float(ENV("PATCHWISE_DAILY_BUDGET", "3.00"))
MAX_CONCURRENT = int(ENV("PATCHWISE_MAX_CONCURRENT", "1"))
PER_HOUR = int(ENV("PATCHWISE_RUNS_PER_IP_HOUR", "3"))
PER_DAY = int(ENV("PATCHWISE_RUNS_PER_IP_DAY", "8"))
TIMEOUT = int(ENV("PATCHWISE_RUN_TIMEOUT", "600"))
MAX_REPO_MB = int(ENV("PATCHWISE_MAX_REPO_MB", "40"))
ALLOW_FIX = ENV("PATCHWISE_ALLOW_FIX", "0") == "1"
GH = re.compile(r"^https://github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$")

app = FastAPI(title="Patchwise", docs_url=None, redoc_url=None)
app.mount("/assets", StaticFiles(directory=ASSETS), name="assets")


# ----------------------------------------------------------------------------- guards
class Guard:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = 0
        self.hits: dict[str, deque] = defaultdict(deque)
        self.state = WORK / "budget.json"

    def _spent_today(self) -> float:
        try:
            d = json.loads(self.state.read_text())
        except (OSError, ValueError):
            return 0.0
        return d.get("spent", 0.0) if d.get("day") == time.strftime("%Y-%m-%d") else 0.0

    def add_spend(self, usd: float):
        with self.lock:
            WORK.mkdir(parents=True, exist_ok=True)
            self.state.write_text(json.dumps({"day": time.strftime("%Y-%m-%d"),
                                              "spent": round(self._spent_today() + usd, 5)}))

    def live_status(self) -> tuple[bool, str]:
        if not ENV("NEBIUS_API_KEY"):
            return False, "Live runs are not configured on this server; the instant replay shows a recorded live run."
        if self._spent_today() >= DAILY_BUDGET:  # the per-run cap bounds any overshoot
            return False, "Today's model budget for live runs is used up; the instant replay shows a recorded live run."
        return True, ""

    def runs_left(self, ip: str) -> int:
        now = time.time()
        q = self.hits[ip]
        while q and now - q[0] > 86400:
            q.popleft()
        hour = sum(1 for t in q if now - t < 3600)
        return max(0, min(PER_HOUR - hour, PER_DAY - len(q)))

    def acquire(self, ip: str):
        ok, why = self.live_status()
        if not ok:
            raise HTTPException(503, why)
        with self.lock:
            if self.runs_left(ip) <= 0:
                raise HTTPException(429, "Rate limit reached for your address. Try the instant replay, or come back later.")
            if self.running >= MAX_CONCURRENT:
                raise HTTPException(429, "Another live run is in progress. Watch the instant replay meanwhile, "
                                         "or try again in a minute.")
            self.running += 1
            self.hits[ip].append(time.time())

    def refund(self, ip: str):
        with self.lock:
            if self.hits[ip]:
                self.hits[ip].pop()

    def release(self):
        with self.lock:
            self.running = max(0, self.running - 1)


GUARD = Guard()


def client_ip(req: Request) -> str:
    for h in ("fly-client-ip", "cf-connecting-ip", "x-real-ip"):
        if req.headers.get(h):
            return req.headers[h].strip()
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "?"


# ----------------------------------------------------------------------------- jobs
class Job:
    def __init__(self, kind: str, label: str):
        self.id = uuid.uuid4().hex[:12]
        self.kind, self.label = kind, label
        self.lines: list[tuple[float, str]] = []
        self.started = time.time()
        self.done = False
        self.error: str | None = None
        self.out = WORK / "jobs" / self.id
        self.summary: dict | None = None

    def log(self, text: str):
        self.lines.append((round(time.time() - self.started, 2), scrub(text.rstrip("\n"))))


JOBS: "OrderedDict[str, Job]" = OrderedDict()


def _register(job: Job) -> Job:
    JOBS[job.id] = job
    while len(JOBS) > 40:  # bounded memory + disk
        _, old = JOBS.popitem(last=False)
        shutil.rmtree(old.out, ignore_errors=True)
    return job


def scrub(text: str) -> str:
    for k in ("NEBIUS_API_KEY", "TAVILY_API_KEY"):
        v = ENV(k)
        if v and len(v) > 6:
            text = text.replace(v, "[redacted]")
    text = re.sub(r"(Bearer\s+)[A-Za-z0-9._\-]{12,}", r"\1[redacted]", text)
    return re.sub(r"(?:/tmp|" + re.escape(str(WORK)) + r")/[\w./\-]*/", "", text)  # no server paths


def summarize(data: dict) -> dict:
    c = {"fix-now": 0, "review": 0, "deprioritize": 0}
    for it in data.get("items", []):
        c[it["priority"]] += 1
    fix = data.get("fix") or {}
    u = data.get("llm_usage") or {}
    return {"raw": len(data.get("items", [])), "counts": c, "deps": data.get("deps_scanned"),
            "fix_status": fix.get("status"), "tests": [fix.get("baseline"), fix.get("final")],
            "repairs": len(fix.get("repairs") or []), "patch_applies": fix.get("patch_applies"),
            "upgrades": fix.get("upgrades") or {}, "cost": u.get("cost_usd", 0), "calls": u.get("calls", 0),
            "tavily": data.get("tavily_calls", 0), "seconds": data.get("seconds"), "mode": data.get("mode")}


def write_artifacts(out: Path, data: dict, openvex: dict | None = None):
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(data, indent=2))
    (out / "report.html").write_text(render_html(data))
    if openvex:
        (out / "openvex.json").write_text(json.dumps(openvex, indent=2))
    if (data.get("fix") or {}).get("diff"):
        (out / "fix.patch").write_text(data["fix"]["diff"])


def run_cli(job: Job, target: Path, do_fix: bool, max_cost: float = MAX_COST, timeout: int = TIMEOUT):
    """Run the pipeline as a subprocess (killable, memory-isolated) and stream its log."""
    cmd = [sys.executable, "-u", "-m", "patchwise.cli", str(target), "--out", str(job.out),
           "--max-cost", f"{max_cost:.2f}"] + ([] if do_fix else ["--no-fix"])
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}  # the pipeline only needs model/search keys
    env.update(PYTHONUNBUFFERED="1", PATCHWISE_CLEAN_SANDBOX="1")
    p = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    timer = threading.Timer(timeout, p.kill)
    timer.start()
    try:
        for line in p.stdout:
            if line.strip() and not line.startswith("report: "):  # don't show server paths
                job.log(line)
        p.wait()
    finally:
        timer.cancel()
    if p.returncode not in (0, 1):
        if time.time() - job.started >= timeout - 1:
            raise RuntimeError(f"run stopped after the {timeout} s time limit")
        raise RuntimeError("the analysis process failed (see log)")


def _finish(job: Job):
    rep = job.out / "report.json"
    if rep.exists():
        data = json.loads(rep.read_text())
        (job.out / "report.html").write_text(render_html(data))
        job.summary = summarize(data)


def live_worker(job: Job, target: Path, do_fix: bool, cleanup: Path | None):
    try:
        run_cli(job, target, do_fix)
        _finish(job)
        if job.summary:
            GUARD.add_spend(job.summary["cost"] or 0)
    except Exception as e:  # surfaced to the UI without internals
        job.error = scrub(str(e))[:300]
        job.log(f"! {job.error}")
    finally:
        GUARD.release()
        job.done = True
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


def replay_worker(job: Job, speed_total: float = 28.0):
    try:
        rec = json.loads(REPLAY.read_text())
        events = rec["events"]
        span = max(1.0, events[-1][0])
        scale = min(1.0, speed_total / span)
        job.log(f"⏯ Instant replay of a live run recorded {rec.get('recorded', '')} "
                f"(real duration {span:.0f} s, shown at {1 / scale:.0f}× speed; no model calls are made)")
        last = 0.0
        for t, text in events:
            time.sleep(min(4.0, max(0.0, (t - last) * scale)))
            last = t
            job.log(text)
        write_artifacts(job.out, rec["report"], rec.get("openvex"))
        job.summary = summarize(rec["report"])
    except Exception as e:
        job.error = f"replay unavailable: {type(e).__name__}"
    finally:
        job.done = True


def _du(path: Path) -> int:
    total = 0
    for dp, _, fs in os.walk(path):
        for f in fs:
            try:
                total += os.lstat(os.path.join(dp, f)).st_size
            except OSError:
                pass
    return total


def monitored_clone(url: str, target: Path, tmp: Path, timeout: int = 90) -> int:
    """Shallow clone that is killed as soon as it exceeds the size limit or the time limit
    (works even when the GitHub API can't tell us the size up front)."""
    limit = MAX_REPO_MB * 1024 * 1024
    p = subprocess.Popen(["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--quiet", url, str(target)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         env={"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0", "HOME": str(tmp)})
    t0, reason = time.time(), ""
    while p.poll() is None:
        time.sleep(0.5)
        if _du(tmp) > limit:
            reason = f"Repository is larger than the {MAX_REPO_MB} MB demo limit."
        elif time.time() - t0 > timeout:
            reason = "Cloning took too long."
        if reason:
            p.kill()
            p.wait()
            break
    size = _du(target) if target.exists() else 0
    if not reason and (p.returncode or size > limit):
        reason = "Could not clone the repository." if p.returncode else f"Repository is larger than the {MAX_REPO_MB} MB demo limit."
    if reason:
        shutil.rmtree(tmp, ignore_errors=True)
        raise HTTPException(400, reason)
    return size


def gh_target(url: str, job: Job) -> tuple[Path, Path]:
    m = GH.match(url.strip())
    if not m:
        raise HTTPException(400, "Enter a public repository URL like https://github.com/owner/name")
    owner, name = m.group(1), m.group(2)
    headers = {"Accept": "application/vnd.github+json"}
    if ENV("GITHUB_TOKEN"):  # optional: raises the API limit; never passed to project code
        headers["Authorization"] = f"Bearer {ENV('GITHUB_TOKEN')}"
    try:
        meta = httpx.get(f"https://api.github.com/repos/{owner}/{name}", timeout=10, headers=headers)
    except httpx.HTTPError:
        meta = None
    if meta is not None and meta.status_code == 404:
        raise HTTPException(400, "Repository not found (it must be public).")
    if meta is not None and meta.status_code == 200:
        info = meta.json()
        if info.get("private"):
            raise HTTPException(400, "Only public repositories are supported.")
        if info.get("size", 0) > MAX_REPO_MB * 1024:
            raise HTTPException(400, f"Repository is larger than the {MAX_REPO_MB} MB demo limit.")
    tmp = Path(tempfile.mkdtemp(prefix="pw-gh-", dir=WORK))
    target = tmp / name
    size = monitored_clone(f"https://github.com/{owner}/{name}.git", target, tmp)
    job.log(f"cloned {owner}/{name} ({size / 1e6:.1f} MB, shallow)")
    return target, tmp


# ----------------------------------------------------------------------------- routes
@app.get("/", response_class=HTMLResponse)
def index():
    return (ASSETS / "index.html").read_text()


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/config")
def config(request: Request):
    live, why = GUARD.live_status()
    return {"live": live, "why": why, "replay": REPLAY.exists(), "max_cost": MAX_COST,
            "runs_left": GUARD.runs_left(client_ip(request)), "busy": GUARD.running >= MAX_CONCURRENT,
            "github_fix": ALLOW_FIX, "timeout": TIMEOUT, "max_repo_mb": MAX_REPO_MB}


@app.get("/api/demo")
def demo_files():
    files = {}
    for p in sorted(DEMO.rglob("*")):
        if p.is_file() and p.suffix in (".py", ".txt") and "__pycache__" not in p.parts and ".patchwise" not in p.parts:
            files[str(p.relative_to(DEMO))] = p.read_text()[:4000]
    return files


@app.post("/api/run")
async def start(request: Request):
    try:
        body = await request.json()
    except ValueError:
        body = {}
    mode = body.get("mode", "replay")
    WORK.mkdir(parents=True, exist_ok=True)
    if mode == "replay":
        if not REPLAY.exists():
            raise HTTPException(404, "No recorded run available.")
        job = _register(Job("replay", "statuspage (replay)"))
        threading.Thread(target=replay_worker, args=(job,), daemon=True).start()
        return {"id": job.id}
    ip = client_ip(request)
    if mode == "demo":
        GUARD.acquire(ip)
        job = _register(Job("demo", "statuspage (live)"))
        tmp = Path(tempfile.mkdtemp(prefix="pw-demo-", dir=WORK))
        target = tmp / "statuspage"
        shutil.copytree(DEMO, target, ignore=shutil.ignore_patterns(".patchwise", ".venv", "__pycache__"))
        threading.Thread(target=live_worker, args=(job, target, True, tmp), daemon=True).start()
        return {"id": job.id}
    if mode == "github":
        url = str(body.get("repo", ""))
        if not GH.match(url.strip()):
            raise HTTPException(400, "Enter a public repository URL like https://github.com/owner/name")
        GUARD.acquire(ip)
        job = _register(Job("github", url.strip().removeprefix("https://github.com/")))
        try:
            target, tmp = await asyncio.to_thread(gh_target, url, job)
        except Exception:
            GUARD.release()
            GUARD.refund(ip)
            JOBS.pop(job.id, None)
            raise
        if not ALLOW_FIX:
            job.log("public repos run triage only here (their tests are never executed on this server)")
        threading.Thread(target=live_worker, args=(job, target, ALLOW_FIX, tmp), daemon=True).start()
        return {"id": job.id}
    raise HTTPException(400, "unknown mode")


def _job(job_id: str) -> Job:
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "unknown job")
    return j


@app.get("/api/jobs/{job_id}")
def status(job_id: str, since: int = 0):
    j = _job(job_id)
    return JSONResponse({"lines": [t for _, t in j.lines[since:]], "next": len(j.lines), "done": j.done,
                         "error": j.error, "summary": j.summary, "kind": j.kind, "label": j.label})


@app.get("/api/jobs/{job_id}/events")
async def events(job_id: str):
    j = _job(job_id)

    async def gen():
        i, beat = 0, time.time()
        while True:
            while i < len(j.lines):
                t, text = j.lines[i]
                i += 1
                yield f"event: log\ndata: {json.dumps({'t': t, 'text': text})}\n\n"
            if j.done and i >= len(j.lines):
                yield f"event: done\ndata: {json.dumps({'error': j.error, 'summary': j.summary})}\n\n"
                return
            if time.time() - beat > 15:
                beat = time.time()
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.25)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/jobs/{job_id}/report", response_class=HTMLResponse)
def report(job_id: str):
    p = _job(job_id).out / "report.html"
    if not p.exists():
        raise HTTPException(404, "report not ready")
    return p.read_text()


ARTIFACTS = {"openvex": "openvex.json", "patch": "fix.patch", "json": "report.json", "md": "report.md"}


@app.get("/jobs/{job_id}/{name}")
def artifact(job_id: str, name: str):
    if name not in ARTIFACTS:
        raise HTTPException(404)
    p = _job(job_id).out / ARTIFACTS[name]
    if not p.exists():
        raise HTTPException(404, "not available for this run")
    return FileResponse(p, media_type="text/plain; charset=utf-8", filename=p.name)


@app.get("/replay/report", response_class=HTMLResponse)
def replay_report():
    if not REPLAY.exists():
        raise HTTPException(404)
    return render_html(json.loads(REPLAY.read_text())["report"])


# ----------------------------------------------------------------------------- recording
def record_replay(out: Path = REPLAY, max_cost: float = 0.5):
    """Run the demo live once and store its timestamped log + report as the instant replay."""
    WORK.mkdir(parents=True, exist_ok=True)
    job = Job("demo", "record")
    tmp = Path(tempfile.mkdtemp(prefix="pw-rec-", dir=WORK))
    target = tmp / "statuspage"
    shutil.copytree(DEMO, target, ignore=shutil.ignore_patterns(".patchwise", ".venv", "__pycache__"))
    run_cli(job, target, True, max_cost=max_cost, timeout=1200)
    data = json.loads((job.out / "report.json").read_text())
    vex = json.loads((job.out / "openvex.json").read_text()) if (job.out / "openvex.json").exists() else None
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"recorded": time.strftime("%Y-%m-%d"), "events": job.lines, "report": data,
                               "openvex": vex}, indent=1))
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"replay saved: {out} ({len(job.lines)} log lines, ${data['llm_usage'].get('cost_usd', 0):.4f})")


if __name__ == "__main__":
    if sys.argv[1:2] == ["record-replay"]:
        record_replay()
    else:
        print("usage: python -m patchwise.web record-replay")
