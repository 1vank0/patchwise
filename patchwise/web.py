"""Minimal web app: pick the bundled demo or a public GitHub repo, watch the agent work, read
the report. Public deployments run triage only on arbitrary repos (no untrusted test execution);
the full upgrade+test+repair loop runs on bundled demos or when PATCHWISE_ALLOW_FIX=1."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from .config import Settings
from .pipeline import run, save
from .report import html_report

app = FastAPI(title="Patchwise")
ROOT = Path(__file__).resolve().parents[1]
DEMOS = {"statuspage": ROOT / "demo" / "statuspage"}
ALLOW_FIX = os.environ.get("PATCHWISE_ALLOW_FIX", "0") == "1"
JOBS: dict[str, dict] = {}
GH = re.compile(r"^https://github\.com/[\w.\-]+/[\w.\-]+/?$")

INDEX = """<!doctype html><html><head><meta charset="utf-8"><title>Patchwise</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:760px;margin:3rem auto;padding:0 1rem;color:#1b1f24}
input,select,button{font:inherit;padding:.5rem .7rem;border:1px solid #d0d7de;border-radius:8px}
button{background:#1f6feb;color:#fff;border:0;cursor:pointer}pre{background:#0d1117;color:#c9d1d9;padding:1rem;border-radius:8px;min-height:8rem;white-space:pre-wrap}
.muted{color:#57606a}</style></head><body>
<h1>Patchwise</h1>
<p>Your scanner says 60 vulnerabilities. Which ones can actually hurt <i>this</i> code, and what's
the smallest upgrade that keeps your tests green? Patchwise researches each advisory live
(Tavily), checks whether your code reaches the vulnerable function (NVIDIA Nemotron on Nebius
Token Factory), then upgrades, runs your tests and repairs breakages in a sandbox.</p>
<form id="f"><select name="demo"><option value="statuspage">Demo: statuspage (Python)</option>
<option value="">Public GitHub repo →</option></select>
<input name="repo" placeholder="https://github.com/owner/name" size="34">
<label><input type="checkbox" name="fix" checked> verified fix</label> <button>Run</button></form>
<p class="muted" id="hint"></p><pre id="log"></pre><p id="out"></p>
<script>
const f=document.getElementById('f'),log=document.getElementById('log'),out=document.getElementById('out');
f.onsubmit=async e=>{e.preventDefault();log.textContent='';out.textContent='';
 const r=await fetch('/api/run',{method:'POST',body:new FormData(f)});const j=await r.json();
 if(!r.ok){log.textContent=j.detail;return}
 const t=setInterval(async()=>{const s=await (await fetch('/api/jobs/'+j.id)).json();
  log.textContent=s.log.join('\\n');if(s.done){clearInterval(t);
  out.innerHTML=s.error?('Error: '+s.error):'<a href="/jobs/'+j.id+'/report">Open report →</a> · <a href="/jobs/'+j.id+'/openvex">OpenVEX</a> · <a href="/jobs/'+j.id+'/patch">fix.patch</a>'}},1000)}
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX


def _work(job_id: str, repo: Path, do_fix: bool, cleanup: Path | None):
    job = JOBS[job_id]
    try:
        r = run(repo, Settings(), do_fix=do_fix, log=lambda m: job["log"].append(str(m)))
        out = Path(tempfile.gettempdir()) / "patchwise-jobs" / job_id
        save(r, out)
        job.update(out=str(out), html=html_report(r))
        job["log"].append(f"done in {r.seconds}s")
    except Exception as e:  # surface failures to the UI
        job["error"] = f"{type(e).__name__}: {e}"
    finally:
        job["done"] = True
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


@app.post("/api/run")
def start(demo: str = Form(""), repo: str = Form(""), fix: str = Form("")):
    cleanup = None
    if demo:
        if demo not in DEMOS:
            raise HTTPException(400, "unknown demo")
        tmp = Path(tempfile.mkdtemp(prefix="pw-demo-"))
        target = tmp / demo
        shutil.copytree(DEMOS[demo], target, ignore=shutil.ignore_patterns(".patchwise", ".venv"))
        cleanup, do_fix = tmp, bool(fix)
    else:
        if not GH.match(repo.strip()):
            raise HTTPException(400, "enter a public https://github.com/owner/name URL")
        tmp = Path(tempfile.mkdtemp(prefix="pw-gh-"))
        target = tmp / "repo"
        p = subprocess.run(["git", "clone", "--depth", "1", repo.strip(), str(target)],
                           capture_output=True, text=True, timeout=120)
        if p.returncode:
            shutil.rmtree(tmp, ignore_errors=True)
            raise HTTPException(400, "clone failed: " + p.stderr[-300:])
        cleanup, do_fix = tmp, bool(fix) and ALLOW_FIX
    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {"log": [] if do_fix or demo else ["(triage only on public deployments)"], "done": False}
    threading.Thread(target=_work, args=(job_id, target, do_fix, cleanup), daemon=True).start()
    return {"id": job_id}


@app.get("/api/jobs/{job_id}")
def status(job_id: str):
    j = JOBS.get(job_id) or {}
    if not j:
        raise HTTPException(404)
    return JSONResponse({"log": j["log"], "done": j["done"], "error": j.get("error")})


@app.get("/jobs/{job_id}/report", response_class=HTMLResponse)
def report(job_id: str):
    j = JOBS.get(job_id)
    if not j or "html" not in j:
        raise HTTPException(404)
    return j["html"]


@app.get("/jobs/{job_id}/{name}", response_class=PlainTextResponse)
def artifact(job_id: str, name: str):
    files = {"openvex": "openvex.json", "patch": "fix.patch", "json": "report.json", "md": "report.md"}
    j = JOBS.get(job_id)
    if not j or name not in files or "out" not in j:
        raise HTTPException(404)
    p = Path(j["out"]) / files[name]
    return p.read_text() if p.exists() else ""
