"""Central config: loads .env once and exposes typed settings."""
import os
from dotenv import load_dotenv

load_dotenv()


def _get(key: str, default: str | None = None, required: bool = False) -> str | None:
    val = os.getenv(key, default)
    if required and not val:
        raise RuntimeError(f"Missing required env var: {key}")
    return val


# LLM
LLM_PROVIDER = _get("LLM_PROVIDER", "anthropic")
LLM_MODEL = _get("LLM_MODEL", "claude-sonnet-5")
ANTHROPIC_API_KEY = _get("ANTHROPIC_API_KEY")
AZURE_OPENAI_ENDPOINT = _get("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_API_KEY = _get("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_DEPLOYMENT = _get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
AZURE_OPENAI_API_VERSION = _get("AZURE_OPENAI_API_VERSION", "2024-10-21")

# Entra
TENANT_ID = _get("TENANT_ID", required=True)
CLIENT_ID = _get("CLIENT_ID", required=True)
CLIENT_SECRET = _get("CLIENT_SECRET", required=True)

# Behaviour
STALE_DAYS_DEFAULT = int(_get("STALE_DAYS_DEFAULT", "90"))
DRY_RUN = _get("DRY_RUN", "true").lower() == "true"
