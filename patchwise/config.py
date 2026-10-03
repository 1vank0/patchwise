"""Runtime configuration. Secrets come ONLY from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

TOKEN_FACTORY_BASE_URL = os.environ.get(
    "NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/"
)

# Model routing: cheap/fast models for high-volume extraction, larger models for judgment.
# IDs from the Token Factory catalog (https://tokenfactory.nebius.com/model-catalog.md).
DEFAULT_MODELS = {
    "fast": os.environ.get("PATCHWISE_MODEL_FAST", "nvidia/Nemotron-3_5-Lightning"),
    "reason": os.environ.get("PATCHWISE_MODEL_REASON", "nvidia/nemotron-3-super-120b-a12b"),
    "deep": os.environ.get("PATCHWISE_MODEL_DEEP", "nvidia/Nemotron-3-Ultra-550b-a55b"),
}

# USD per 1M tokens (input, output), from the public catalog, Oct 2026.
PRICES = {
    "nvidia/Nemotron-3_5-Lightning": (0.06, 0.24),
    "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B": (0.06, 0.24),
    "nvidia/nemotron-3-super-120b-a12b": (0.30, 0.90),
    "nvidia/Nemotron-3-Ultra-550b-a55b": (1.00, 3.00),
}


@dataclass
class Settings:
    nebius_api_key: str | None = field(default_factory=lambda: os.environ.get("NEBIUS_API_KEY"))
    tavily_api_key: str | None = field(default_factory=lambda: os.environ.get("TAVILY_API_KEY"))
    # Keyless Tavily (rate-limited, free) is used when no key is set, unless disabled.
    tavily_keyless: bool = field(
        default_factory=lambda: os.environ.get("PATCHWISE_TAVILY_KEYLESS", "1") == "1"
    )
    models: dict = field(default_factory=lambda: dict(DEFAULT_MODELS))
    # Offline mode uses a deterministic heuristic stand-in for the LLM. For tests/dev only;
    # it is NOT the product and is clearly labeled in reports.
    offline: bool = field(default_factory=lambda: os.environ.get("PATCHWISE_OFFLINE", "0") == "1")
    max_repair_iterations: int = int(os.environ.get("PATCHWISE_MAX_REPAIRS", "8"))
    test_command: str | None = os.environ.get("PATCHWISE_TEST_CMD")
    test_timeout: int = int(os.environ.get("PATCHWISE_TEST_TIMEOUT", "900"))
    python_version: str | None = os.environ.get("PATCHWISE_PYTHON")
    # Requirements files to install for the test run (default: every requirements file found).
    install_requirements: list = field(default_factory=list)
    extra_test_packages: list = field(default_factory=list)
    # Hard ceiling on model spend per run (USD); calls stop once it is reached.
    max_cost_usd: float = float(os.environ.get("PATCHWISE_MAX_COST", "1.00"))
    # Which advisories the verified fix upgrades: "fix-now" (default), "review" (fix-now + review)
    # or "all" (every advisory with a fixed version, reachable or not).
    fix_scope: str = os.environ.get("PATCHWISE_FIX_SCOPE", "fix-now")
    # OS the project is deployed on; advisories limited to other platforms are not reachable.
    deploy_os: str = os.environ.get("PATCHWISE_DEPLOY_OS", "linux")
    llm_timeout: float = float(os.environ.get("PATCHWISE_LLM_TIMEOUT", "180"))
    llm_retries: int = int(os.environ.get("PATCHWISE_LLM_RETRIES", "4"))

    @property
    def llm_available(self) -> bool:
        return bool(self.nebius_api_key) and not self.offline
