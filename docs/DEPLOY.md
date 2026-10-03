# Deploying the Patchwise web demo

**Live:** https://patchwise-787826567365.us-east1.run.app: Google Cloud Run, project `patchwise-demo`, region `us-east1`, service `patchwise`.

## Cloud Run (current deployment)
```bash
gcloud projects create patchwise-demo
gcloud billing projects link patchwise-demo --billing-account=<ACCOUNT>
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  secretmanager.googleapis.com --project patchwise-demo
# the key goes in via stdin, never echoed
printf '%s' "$NEBIUS_API_KEY" | gcloud secrets create nebius-api-key --data-file=- --project patchwise-demo
gcloud iam service-accounts create patchwise-run --project patchwise-demo
gcloud secrets add-iam-policy-binding nebius-api-key --project patchwise-demo \
  --member=serviceAccount:patchwise-run@patchwise-demo.iam.gserviceaccount.com --role=roles/secretmanager.secretAccessor
# durable usage counters (daily budget + per-IP history) in a private bucket; only the runtime SA can use it
gcloud storage buckets create gs://patchwise-demo-state --project patchwise-demo --location us-east1 \
  --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets add-iam-policy-binding gs://patchwise-demo-state \
  --member=serviceAccount:patchwise-run@patchwise-demo.iam.gserviceaccount.com --role=roles/storage.objectUser
gcloud run deploy patchwise --project patchwise-demo --region us-east1 --source . --allow-unauthenticated \
  --service-account patchwise-run@patchwise-demo.iam.gserviceaccount.com \
  --set-secrets NEBIUS_API_KEY=nebius-api-key:latest \
  --set-env-vars PATCHWISE_CLIENT_IP=xff-last,PATCHWISE_STATE_BUCKET=patchwise-demo-state,PATCHWISE_WEB_MAX_COST=0.40,PATCHWISE_DAILY_BUDGET=0.50,PATCHWISE_MAX_CONCURRENT=1 \
  --memory 2Gi --cpu 1 --no-cpu-throttling --execution-environment gen2 \
  --timeout 900 --min-instances 0 --max-instances 1 --concurrency 20
```
- **Single instance:** `--max-instances 1` keeps the in-memory concurrency and rate-limit guards correct.
- **Rate limits:** `PATCHWISE_CLIENT_IP=xff-last` keys them on the address Google's front end appends to `X-Forwarded-For`; earlier entries can be spoofed by clients.
- **CPU:** `--no-cpu-throttling` keeps CPU allocated, so a live run (or the replay pacing) finishes even if the visitor closes the tab. It bills per instance-second while the instance is up, and the instance scales to zero about 15 minutes after the last request.
- **Durable counters:** the daily model budget and per-IP run history live in one JSON object in `gs://patchwise-demo-state`, so they survive cold starts and new revisions. Writes use generation preconditions, IP addresses are stored only as salted hashes, and each run's exact spend (even for a killed run) comes from its own cost ledger. If the bucket is unreachable, live runs pause and the replay keeps working. `/api/config` shows `counters`, `spent_today` and `runs_today`.
- **Health check:** use `/health`; Cloud Run's front end reserves `/healthz`.
- **Budget:** a $10/month budget on this project alerts billing admins by email at 50%, 90%, 100% and 100% forecast. It notifies only; it doesn't cap spend.
- **Expected cost:** ≈ $0–2/month. The instance-based free tier covers 240k vCPU-s and 450k GiB-s per month, about 65 hours of a warm 1 vCPU / 2 GiB instance. Artifact Registry storage costs a few cents. If bots kept it warm 24/7, the worst case is ≈ $50/month, and the budget alert would fire well before that.
- **Model spend:** capped separately by the in-app daily budget.


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

## Steps (Fly.io alternative)
```bash
curl -L https://fly.io/install.sh | sh            # installs flyctl
fly auth login                                     # browser sign-in (Ivan)
fly launch --copy-config --no-deploy --name patchwise-demo   # uses fly.toml in this repo
fly secrets set NEBIUS_API_KEY="$NEBIUS_API_KEY"   # from the environment; never echoed or committed
fly secrets set TAVILY_API_KEY=...                 # recommended for public traffic (free tier: 1,000 credits/mo)
fly deploy                                         # remote build of ./Dockerfile
fly scale count 1                                  # single instance (in-memory guards)
```
Smoke test: `/health`, the instant replay, one live demo run (≈ $0.04), and a GitHub triage of a small repo.

## Guard defaults (environment variables)
`PATCHWISE_WEB_MAX_COST=0.40` (per run) · `PATCHWISE_DAILY_BUDGET=0.50` · `PATCHWISE_MAX_CONCURRENT=1` ·
`PATCHWISE_RUNS_PER_IP_HOUR=3` · `PATCHWISE_RUNS_PER_IP_DAY=8` · `PATCHWISE_RUN_TIMEOUT=600` · `PATCHWISE_MAX_REPO_MB=40` ·
`PATCHWISE_ALLOW_FIX=0` (GitHub repos are triage only) · `PATCHWISE_FAST_TIMEOUT=45` / `PATCHWISE_TAVILY_TIMEOUT=20` (per-request timeouts in research). Optional `GITHUB_TOKEN` raises the GitHub API limit for the size check; it is
never passed to the pipeline or to project code.

The worst-case model spend is the daily budget × days. The deploy default is $0.50/day, roughly 11 live demo runs a day. That is ≈ $35 through Dec 15 only if
the demo were maxed out every single day, so the prepaid Token Factory balance is the real hard stop. The replay keeps working after the
budget (or the credit) is used up. Raise the budget for the judging window (Dec 1–15) if credit allows.

Without `PATCHWISE_STATE_BUCKET`, the counters live in a JSON file under `PATCHWISE_WORK_DIR` (default `/tmp/patchwise-web`). On Fly.io, put that on a volume to make it durable.