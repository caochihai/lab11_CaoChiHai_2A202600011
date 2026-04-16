"""
Lab 11 - Configuration & API Key Setup
"""
import os
from pathlib import Path


def _load_env_file():
    """Load key/value pairs from project .env into process environment."""
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def setup_api_key():
    """Load OpenAI API key from .env or environment, fallback to prompt."""
    _load_env_file()
    if "OPENAI_API_KEY" not in os.environ:
        os.environ["OPENAI_API_KEY"] = input("Enter OpenAI API Key: ").strip()
    print("OpenAI API key loaded.")


ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
