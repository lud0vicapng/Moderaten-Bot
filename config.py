import os
from dotenv import load_dotenv

load_dotenv()

DISCORD_TOKEN: str = os.getenv("DISCORD_TOKEN", "")
ADMIN_CHANNEL_ID: int = int(os.getenv("ADMIN_CHANNEL_ID", "0"))

OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "")

RATE_LIMIT_MESSAGES: int = int(os.getenv("RATE_LIMIT_MESSAGES", "5"))
RATE_LIMIT_WINDOW: int = int(os.getenv("RATE_LIMIT_WINDOW", "10"))

CONFIDENCE_LOW_THRESHOLD: float = float(os.getenv("CONFIDENCE_LOW_THRESHOLD", "0.6"))
THREAT_TIMEOUT_DURATION: int = int(os.getenv("THREAT_TIMEOUT_DURATION", "60"))
HARASSMENT_TIMEOUT_DURATION: int = int(os.getenv("HARASSMENT_TIMEOUT_DURATION", "30"))
EXPLANATION_COOLDOWN: int = int(os.getenv("EXPLANATION_COOLDOWN", "300"))

DB_PATH: str = os.getenv("DB_PATH", "violations.json")
MAX_VIOLATION_AGE_DAYS: int = int(os.getenv("MAX_VIOLATION_AGE_DAYS", "90"))

_raw_keywords: str = os.getenv("BANNED_KEYWORDS", "")
BANNED_KEYWORDS: list[str] = [kw.strip().lower() for kw in _raw_keywords.split(",") if kw.strip()]

MAX_CONTENT_LENGTH: int = int(os.getenv("MAX_CONTENT_LENGTH", "300"))