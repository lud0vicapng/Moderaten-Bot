import datetime
import logging
from tinydb import TinyDB, Query
from config import DB_PATH, MAX_VIOLATION_AGE_DAYS

logger = logging.getLogger(__name__)

db = TinyDB(DB_PATH)

def log_violation(
    user_id: int,
    username: str,
    guild_id: int,
    channel_id: int,
    message_content: str,
    category: str,
    confidence_score: float,
    action_taken: str,
) -> None:
    """Logs a message violation to TinyDB."""
    db.insert({
        "user_id": user_id,
        "username": username,
        "guild_id": guild_id,
        "channel_id": channel_id,
        "message_content": message_content,
        "category": category,
        "confidence_score": confidence_score,
        "action_taken": action_taken,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })


def get_violations(user_id: int, limit: int = 10) -> list[dict]:
    """
    Returns the most recent `limit` violations for a given user_id.
    Results are sorted newest-first.
    """
    V = Query()
    records = db.search(V.user_id == user_id)
    records.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return [dict(record) for record in records[:limit]]


def purge_old_violations() -> int:
    """
    Removes violations older than MAX_VIOLATION_AGE_DAYS days.
    Returns the number of entries removed.
    """
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(days=MAX_VIOLATION_AGE_DAYS)
    ).isoformat()
    V = Query()
    removed = db.remove(V.timestamp < cutoff)
    count = len(removed)
    if count:
        logger.info("Purged %d old violation(s) from database (older than %d days)", count, MAX_VIOLATION_AGE_DAYS)
    return count
