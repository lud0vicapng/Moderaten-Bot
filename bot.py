import discord
from discord.ext import commands, tasks
from discord import app_commands

import re
import logging
import time
import datetime
from collections import deque

from agents import InputGuardrailTripwireTriggered

from config import (
    DISCORD_TOKEN, ADMIN_CHANNEL_ID, RATE_LIMIT_MESSAGES, MAX_CONTENT_LENGTH, RATE_LIMIT_WINDOW,
    CONFIDENCE_LOW_THRESHOLD, THREAT_TIMEOUT_DURATION, HARASSMENT_TIMEOUT_DURATION, EXPLANATION_COOLDOWN, BANNED_KEYWORDS
)

from database import log_violation, purge_old_violations, get_violations
from defined_agents import classifier_agent, verifier_agent, moderator_agent, inference_worker, enqueue

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

intents = discord.Intents.default()
intents.message_content = True

user_message_timestamps: dict[int, deque[float]] = {}
user_explanation_cooldowns: dict[int, float] = {}
user_warn_counts: dict[int, int] = {}

@tasks.loop(hours=24)
async def daily_purge() -> None:
    """Purges old violations from the database and cleans up in-memory state."""
    purge_old_violations()
    user_warn_counts.clear()

    now = time.time()

    inactive = [uid for uid, ts in user_message_timestamps.items()
                if not ts or now - ts[-1] > RATE_LIMIT_WINDOW]
    for uid in inactive:
        del user_message_timestamps[uid]

    expired = [uid for uid, t in user_explanation_cooldowns.items()
               if now - t > EXPLANATION_COOLDOWN]
    for uid in expired:
        del user_explanation_cooldowns[uid]

class Moderaten(commands.Bot):
    async def setup_hook(self) -> None:
        self.loop.create_task(inference_worker())
        daily_purge.start()
        init_keyword_patterns()

bot = Moderaten(command_prefix="!", intents=intents)


_LEET_MAP = {
    "a": "[a@4]",
    "e": "[e3]",
    "i": "[i1!]",
    "o": "[o0]",
    "s": "[s5$]",
    "t": "[t+]",
}

def _build_pattern(keyword: str) -> re.Pattern:
    """Builds a regex pattern for a keyword."""
    pattern = "".join(_LEET_MAP.get(c, re.escape(c)) for c in keyword.lower())
    return re.compile(pattern, re.IGNORECASE)

_compiled_keywords: list[re.Pattern] = []

def init_keyword_patterns() -> None:
    """Pre-compiles all keyword patterns at startup."""
    global _compiled_keywords
    _compiled_keywords = [_build_pattern(kw) for kw in BANNED_KEYWORDS]

def check_keyword_filter(content: str) -> bool:
    """Check message content against banned keywords using pre-compiled regex patterns."""
    for pattern in _compiled_keywords:
        if pattern.search(content):
            return True
    return False

def check_rate_limit(user_id: int) -> bool:
    """
    Check if the user has exceeded the rate limit of RATE_LIMIT_MESSAGES in RATE_LIMIT_WINDOW seconds.
    Returns True if rate limited, False otherwise.
    """
    now = time.time()
    timestamps = user_message_timestamps.setdefault(user_id, deque())

    while timestamps and now - timestamps[0] > RATE_LIMIT_WINDOW:
        timestamps.popleft()

    timestamps.append(now)

    return len(timestamps) >= RATE_LIMIT_MESSAGES

async def log_to_discord_channel(
    action: str,
    user: discord.Member,
    category: str,
    confidence_score: float,
    content: str
) -> None:
    """Sends a violation log embed to the admin channel."""
    if not ADMIN_CHANNEL_ID:
        return
    admin_channel = bot.get_channel(ADMIN_CHANNEL_ID)
    if not admin_channel:
        return

    color_map = {
        "timeout": discord.Color.orange(),
        "mute": discord.Color.red(),
        "warn": discord.Color.yellow(),
        "dropped": discord.Color.purple(),
        "rate_limited": discord.Color.blurple(),
    }
    color = color_map.get(action, discord.Color.greyple())

    action_emoji_map = {
        "timeout": "⏱️",
        "mute": "🔇",
        "warn": "⚠️",
        "dropped": "🛡️",
        "rate_limited": "🚦",
    }
    emoji = action_emoji_map.get(action, "📋")

    embed = discord.Embed(
        title=f"{emoji} Moderation Action — {action.upper()}",
        color=color,
        timestamp=datetime.datetime.now(datetime.timezone.utc)
    )
    embed.set_author(name=str(user), icon_url=user.display_avatar.url)
    embed.add_field(name="User", value=f"{user.mention} (`{user.id}`)", inline=True)
    embed.add_field(name="Category", value=f"`{category}`", inline=True)
    embed.add_field(name="Confidence", value=f"`{confidence_score:.2f}`", inline=True)
    embed.add_field(name="Message", value=f"```{content[:300]}```", inline=False)
    embed.set_footer(text=f"Server: {user.guild.name}")

    try:
        await admin_channel.send(embed=embed)
    except discord.errors.Forbidden:
        logger.warning("Lacking permissions to send to admin channel")

@bot.event
async def on_ready() -> None:
    if bot.user:
        synced = await bot.tree.sync()
        logger.info("Synced %d command(s): %s", len(synced), [c.name for c in synced])
        logger.info(f"Logged in as %s (%s)", bot.user.name, bot.user.id)

@bot.event
async def on_message(message: discord.Message) -> None:
    """Message processing pipeline."""
    if message.author.bot:
        return

    if not message.guild:
        return

    user_id = message.author.id
    guild_id = message.guild.id
    channel_id = message.channel.id
    content = message.content[:MAX_CONTENT_LENGTH]
    username = str(message.author)

    if check_rate_limit(user_id):
        logger.info("User %s rate limited. Applying automatic timeout.", username)
        try:
            timeout_until = discord.utils.utcnow() + datetime.timedelta(seconds=60)
            await message.author.timeout(timeout_until, reason="Rate limit exceeded")
        except discord.errors.Forbidden:
            logger.warning("Lacking permissions to timeout user %s for rate limiting", username)
        log_violation(user_id, username, guild_id, channel_id, content, "rate_limit", 0.0, "rate_limited")
        await log_to_discord_channel("rate_limited", message.author, "rate_limit", 0.0, content)
        return

    if not check_keyword_filter(content):
        return

    try:
        class_result = await enqueue(classifier_agent(content), label="classifier")
        if not class_result:
            return
    except InputGuardrailTripwireTriggered as e:
        logger.info("Guardrail triggered for user %s: %s", username, e)
        log_violation(user_id, username, guild_id, channel_id, content, "injection", 1.0, "dropped")
        await log_to_discord_channel("dropped", message.author, "injection", 1.0, content)
        return

    category = class_result.category
    confidence_score = class_result.confidence_score
    reasoning = class_result.reasoning

    if confidence_score < CONFIDENCE_LOW_THRESHOLD:
        logger.info("Confidence score %.2f below threshold for user %s — invoking verifier", confidence_score, username)
        verify_result = await enqueue(verifier_agent(content, category, reasoning), label="verifier")
        if verify_result:
            if verify_result.verified:
                logger.info("Verifier confirmed classification: category=%s user=%s", category, username)
            else:
                logger.info("Verifier overrode classification: %s → %s user=%s", category, verify_result.category, username)
                category = verify_result.category
            reasoning = verify_result.reasoning

    confidence_score = max(0.0, min(1.0, float(confidence_score)))

    if category == "normal":
        return

    action_taken = "none"

    match category:
        case "threat":
            action_taken = "timeout"
            try:
                timeout_until = discord.utils.utcnow() + datetime.timedelta(minutes=THREAT_TIMEOUT_DURATION)
                await message.author.timeout(timeout_until, reason="Threat detected")
            except discord.errors.Forbidden:
                            logger.warning("Lacking permissions to timeout user %s for rate limiting", username)

        case "harassment":
            action_taken = "timeout"
            try:
                timeout_until = discord.utils.utcnow() + datetime.timedelta(minutes=HARASSMENT_TIMEOUT_DURATION)
                await message.author.timeout(timeout_until, reason="Harassment detected")
            except discord.errors.Forbidden:
                            logger.warning("Lacking permissions to timeout user %s for rate limiting", username)

        case "insult":
            action_taken = "warn"

        case _:
            action_taken = "none"  

    if action_taken == "none":
        return

    if action_taken != "warn":
        try:
            await message.delete()
        except discord.errors.Forbidden:
            logger.warning("Lacking permissions to delete message")
        except discord.errors.NotFound:
            pass

    log_violation(
        user_id=user_id,
        username=username,
        guild_id=guild_id,
        channel_id=channel_id,
        message_content=content,
        category=str(category),
        confidence_score=confidence_score,
        action_taken=action_taken
    )
    await log_to_discord_channel(action_taken, message.author, str(category), confidence_score, content)
    
    if action_taken == "warn":
        user_warn_counts[user_id] = user_warn_counts.get(user_id, 0) + 1
        warn_count = user_warn_counts[user_id]

        if warn_count >= 3:
            user_warn_counts[user_id] = 0
            try:
                timeout_until = discord.utils.utcnow() + datetime.timedelta(minutes=HARASSMENT_TIMEOUT_DURATION)
                await message.author.timeout(timeout_until, reason="Reached 3 warnings")
            except discord.errors.Forbidden:
                            logger.warning("Lacking permissions to timeout user %s for rate limiting", username)
            log_violation(user_id, username, guild_id, channel_id, content, "warn_threshold", 1.0, "timeout")
            await log_to_discord_channel("timeout", message.author, "warn_threshold", 1.0, content)
            return

        now = time.time()
        last_explanation = user_explanation_cooldowns.get(user_id, 0.0)

        if now - last_explanation >= EXPLANATION_COOLDOWN:
            mod_result = await enqueue(moderator_agent(username, content, str(category), str(reasoning)), label="moderator")
            if mod_result and mod_result.public_message:
                try:
                    await message.channel.send(
                        f"{message.author.mention} {mod_result.public_message} ({warn_count}/3 warnings)"
                    )
                    user_explanation_cooldowns[user_id] = now
                except discord.errors.Forbidden:
                    logger.warning("Lacking permissions to send explanation in channel")


@bot.tree.command(name="history", description="Show recent violations for a user")
@app_commands.describe(user="The user to check", limit="Number of violations to show (default 10)")
@app_commands.default_permissions(administrator=True)
async def history(
    interaction: discord.Interaction,
    user: discord.Member,
    limit: int = 10
) -> None:
    violations = get_violations(user.id, limit=limit)

    if not violations:
        embed = discord.Embed(
            title="No Violations Found",
            description="No violations found for {user.mention}.",
            color=discord.Color.green(),
            timestamp=datetime.datetime.now(datetime.timezone.utc)
        )
        embed.set_author(name=str(user), icon_url=user.display_avatar.url)
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    embed = discord.Embed(
        title=f"Violation History — {user.display_name}",
        description=f"Last **{len(violations)}** violation(s) for {user.mention}",
        color=discord.Color.red(),
        timestamp=datetime.datetime.now(datetime.timezone.utc)
    )
    embed.set_author(name=str(user), icon_url=user.display_avatar.url)
    embed.set_footer(text=f"User ID: {user.id}")

    for i, v in enumerate(violations, start=1):
        ts_str = v.get("timestamp", "")
        try:
            ts = datetime.datetime.fromisoformat(ts_str)
            timestamp = f"<t:{int(ts.timestamp())}:f>"
        except (ValueError, TypeError):
            timestamp = "N/A"

        category = v.get("category", "N/A")
        action = v.get("action_taken", "N/A")
        score = v.get("confidence_score", 0)
        msg = v.get("message_content", "N/A")[:50]

        action_emoji_map = {
            "timeout": "⏱️",
            "mute": "🔇",
            "warn": "⚠️",
            "dropped": "🛡️",
            "rate_limited": "🚦",
        }
        emoji = action_emoji_map.get(action, "📋")

        embed.add_field(
            name=f"{emoji} #{i} — {timestamp}",
            value=(
                f"**Category:** `{category}`\n"
                f"**Action:** `{action}` — **Score:** `{score:.2f}`\n"
                f"**Message:** `{msg}`"
            ),
            inline=False
        )

    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="purgemsg", description="Delete recent messages from a user across all channels")
@app_commands.describe(user="The user to purge", limit="Max messages to check per channel (default 100)")
@app_commands.default_permissions(administrator=True)
async def purgemsg(
    interaction: discord.Interaction,
    user: discord.Member,
    limit: int = 100
) -> None:
    await interaction.response.defer(ephemeral=True)

    total_deleted = 0

    for channel in interaction.guild.text_channels:
        try:
            deleted = await channel.purge(
                limit=limit,
                check=lambda m: m.author == user
            )
            total_deleted += len(deleted)
        except discord.errors.Forbidden:
            logger.warning("Lacking permissions to purge messages in #%s", channel.name)
        except discord.errors.HTTPException as e:
            logger.warning("HTTPException purging #%s: %s", channel.name, e)

    await interaction.followup.send(
        f"🗑️ Deleted {total_deleted} message(s) from {user.mention} across all channels.",
        ephemeral=True
    )

if not DISCORD_TOKEN:
    raise ValueError("DISCORD_TOKEN is not set in .env")

bot.run(DISCORD_TOKEN)