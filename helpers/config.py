"""
OSINPY — Configuration Manager
Reads API keys from .env or environment variables.
All keys are optional — modules degrade gracefully if not present.
"""

import os
from pathlib import Path

# Load .env if present (won't crash if file doesn't exist)
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).parent.parent / ".env"
    
    # Auto-create .env if it doesn't exist
    if not _env_path.exists():
        try:
            with open(_env_path, "w", encoding="utf-8") as f:
                f.write(
"""# OSINPY — API Keys (all optional)
# Automatically generated template. Fill in what you have.

SHODAN_API_KEY=
HIBP_API_KEY=
HUNTER_API_KEY=
DEHASHED_EMAIL=
DEHASHED_API_KEY=
INTELX_API_KEY=
NUMVERIFY_API_KEY=

# Optional tunables
HTTP_TIMEOUT=10
MAX_THREADS=20
""")
        except Exception:
            pass

    if _env_path.exists():
        load_dotenv(_env_path)
except ImportError:
    pass


class Config:
    """Central config for OSINPY. All values fall back to None if not set."""

    # ── Optional API keys ──────────────────────────────────────────────────
    SHODAN_API_KEY: str | None = os.getenv("SHODAN_API_KEY")
    HIBP_API_KEY: str | None = os.getenv("HIBP_API_KEY")
    HUNTER_API_KEY: str | None = os.getenv("HUNTER_API_KEY")
    DEHASHED_EMAIL: str | None = os.getenv("DEHASHED_EMAIL")
    DEHASHED_API_KEY: str | None = os.getenv("DEHASHED_API_KEY")
    INTELX_API_KEY: str | None = os.getenv("INTELX_API_KEY")
    NUMVERIFY_API_KEY: str | None = os.getenv("NUMVERIFY_API_KEY")

    # ── Timeouts and limits ────────────────────────────────────────────────
    HTTP_TIMEOUT: int = int(os.getenv("HTTP_TIMEOUT", "10"))
    MAX_THREADS: int = int(os.getenv("MAX_THREADS", "20"))
    MAX_SUBDOMAINS_BRUTE: int = int(os.getenv("MAX_SUBDOMAINS_BRUTE", "500"))

    @classmethod
    def show(cls) -> None:
        """Print current config status (masks key values)."""
        keys = {
            "SHODAN_API_KEY": cls.SHODAN_API_KEY,
            "HIBP_API_KEY": cls.HIBP_API_KEY,
            "HUNTER_API_KEY": cls.HUNTER_API_KEY,
            "DEHASHED_EMAIL": cls.DEHASHED_EMAIL,
            "DEHASHED_API_KEY": cls.DEHASHED_API_KEY,
            "INTELX_API_KEY": cls.INTELX_API_KEY,
            "NUMVERIFY_API_KEY": cls.NUMVERIFY_API_KEY,
        }
        print("\n[config] API Key Status:")
        for name, val in keys.items():
            status = "✅ SET" if val else "⬜ not configured"
            print(f"  {name:<22} {status}")
        print()

    @classmethod
    def env_template(cls) -> str:
        """Return a .env file template."""
        return """\
# OSINPY — API Keys (all optional)
# Copy this to .env and fill in what you have

SHODAN_API_KEY=
HIBP_API_KEY=
HUNTER_API_KEY=
DEHASHED_EMAIL=
DEHASHED_API_KEY=
INTELX_API_KEY=
NUMVERIFY_API_KEY=

# Optional tunables
HTTP_TIMEOUT=10
MAX_THREADS=20
"""
