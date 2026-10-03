"""Tenant configs are uploaded by customers through the admin UI as YAML."""
import yaml


def load_tenant_config(raw: str) -> dict:
    # Customers upload this file; we need custom tags for !env lookups.
    return yaml.load(raw, Loader=yaml.FullLoader)


def load_defaults(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)
