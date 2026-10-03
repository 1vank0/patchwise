# Deploying the Patchwise web demo (prepared, not yet deployed)

Requirements: the demo must stay up and be free for judges **through Dec 15, 2026** (judging is Dec 1–15). The container
needs `git`, `uv`, a Python 3.11 toolchain for sandboxed test runs of the demo project, outbound HTTPS (Token Factory,
Tavily, OSV.dev, PyPI), and about 1 GB of RAM. Jobs, rate limits and the concurrency guard live in process memory, so the app runs as a
**single instance**.

## Hosts evaluated (prices checked 2026-10-03)

| Host | Fit | Cost through Dec 15 | Notes |
|---|---|---|---|
| **Nebius AI Cloud: Serverless AI endpoint** (CPU-only) | Works (container VM) | **≈ $100–110** | Smallest CPU preset is `2vcpu-8gb` (cpu-e2: $0.012/vCPU-h + $0.0045/GiB-h = $0.060/h ≈ $1.44/day; cpu-d3 ≈ $1.58/day). It bills while running, with no scale-to-zero (you stop and start it manually). Add a boot disk (default 250 GiB; set `--disk-size 30Gi` ≈ $2/mo) and a public IP. This exceeds the hackathon credit, which is Token Factory credit and may not apply to AI Cloud compute. Sponsor-hosted would be a plus. Option: run a Nebius endpoint only for the judging window (≈ $22 for 15 days), which needs separate AI Cloud credit. |
| **Fly.io** (recommended) | Very good: Dockerfile as-is, remote builder, auto-stop/auto-start | **≈ $2–6** | `shared-cpu-1x` with 1 GB costs $5.92/mo if always on. With auto-stop it bills only while running, plus $0.15/GB-mo rootfs while stopped. Cold start takes a few seconds. Requires a card (the trial is only 2 VM-hours / 7 days). The `Fly-Client-IP` header feeds the per-IP rate limit. |
| Google Cloud Run | Good: scale to zero, request-based billing | **≈ $0** (free tier: 180k vCPU-s, 360k GiB-s, 2M requests per month) | Needs a GCP project with billing (card), Artifact Registry and `gcloud` (not installed here). Set `--max-instances 1 --timeout 900`. CPU is throttled outside requests; the SSE log stream keeps a run's request open. |
| Render | Free tier too small | $0 free / $25 mo for 1 CPU 2 GB | Free = 0.1 CPU / 512 MB and spins down after 15 min (≈1 min wake). That's too slow for sandboxed installs and tests; fine only for replay and triage. |
| Hugging Face Spaces (Docker) | Possible | $9/mo PRO | Creating Docker Spaces now requires a PRO plan. Free CPU Basic sleeps after 48 h idle. |
| Railway | Possible | ≈ $5/mo (Hobby) | No permanent free tier. Pricing not re-verified today. |

**Recommendation: Fly.io**, 1 GB shared VM, auto-stop on, `fly scale count 1`. It is the cheapest option that keeps the full live
demo (sandboxed upgrade, tests and repair) responsive, and it builds the existing Dockerfile remotely, so no local Docker is needed.
Cloud Run is the $0 alternative if a GCP billing account already exists. The Nebius endpoint would cost ≈ $100 for 24/7.

## Steps (Fly.io), after approval
```bash
curl -L https://fly.io/install.sh | sh            # installs flyctl
fly auth login                                     # browser sign-in (Ivan)
fly launch --copy-config --no-deploy --name patchwise-demo   # uses fly.toml in this repo
fly secrets set NEBIUS_API_KEY="$NEBIUS_API_KEY"   # from the environment; never echoed or committed
fly secrets set TAVILY_API_KEY=...                 # recommended for public traffic (free tier: 1,000 credits/mo)
fly deploy                                         # remote build of ./Dockerfile
fly scale count 1                                  # single instance (in-memory guards)
```
Smoke test: `/healthz`, the instant replay, one live demo run (≈ $0.04), and a GitHub triage of a small repo.

## Guard defaults (environment variables)
`PATCHWISE_WEB_MAX_COST=0.40` (per run) · `PATCHWISE_DAILY_BUDGET=3.00` · `PATCHWISE_MAX_CONCURRENT=1` ·
`PATCHWISE_RUNS_PER_IP_HOUR=3` · `PATCHWISE_RUNS_PER_IP_DAY=8` · `PATCHWISE_RUN_TIMEOUT=600` · `PATCHWISE_MAX_REPO_MB=40` ·
`PATCHWISE_ALLOW_FIX=0` (GitHub repos are triage only). Optional `GITHUB_TOKEN` raises the GitHub API limit for the size check; it is
never passed to the pipeline or to project code.

The worst-case model spend is the daily budget × days. At $3/day that is ≈ $220 through Dec 15 if the demo were hammered every
day; lower `PATCHWISE_DAILY_BUDGET` (for example to 0.50) to bound it tightly. The replay keeps working after the budget is spent.
