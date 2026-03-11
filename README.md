# Moderaten: a Discord Autonomous Moderation Bot

A proof-of-concept Discord bot that combines deterministic rules with AI agents to moderate server messages. Instead of relying solely on keyword filtering, Moderaten uses a pipeline of LLM agents to analyze flagged messages before applying any sanction and ensures that even without an active admin, the server is kept under control.

Built with a local LLM via [Ollama](https://ollama.com/) for full data compliance.

---

## Architecture

```
User message
     │
     ▼
Rate Limiter ──── exceeded ────► Automatic timeout + log
     │
  not exceeded
     │
     ▼
Keyword Filter ──── no match ───► Ignore
     │
  match
     │
     ▼
Input Guardrail (Prompt Injection check)
     │
  injection ──────────────────► Drop message + log
     │
  clean
     │
     ▼
Classifier Agent
(category + confidence score)
     │
  confidence < threshold ───┐
     │                      │
     │                 Verifier Agent ◄──────── second opinion
     │                        (verified + category + reasoning)
     │
     ▼
Policy Engine (deterministic)
     │
  ┌──┴──────────────┬─────────────────┐
threat           harassment         insult
  │                 │                 │
timeout          timeout            warn
                                      │
                           ┌──────────┴──────┐ 
                    warn count >= 3     warn count < 3
                           │                 │
                        timeout       Moderator Agent
                                 (contextual public warning)
```

### Agents Involved

| Agent | Role |
|---|---|
| **Guardrail** | Detects prompt injection attempts before the classifier runs |
| **Classifier** | Categorizes the message as "normal", "insult", "harassment" or "threat" and assigns a confidence score |
| **Verifier** | Called when confidence is low, acts as final arbiter |
| **Moderator** | Generates a contextualized public warning message in Italian |

### Policy Engine

The Policy Engine is fully deterministic: agents analyze and classify, but the final sanctioning logic is never delegated to them as it's applied through a match/case construct.

| Category | Action |
|---|---|
| `normal` | No action |
| `insult` | Warn (3 warns → timeout) |
| `harassment` | Timeout |
| `threat` | Timeout |
| Prompt injection | Message dropped + logged |
| Rate limit exceeded | Automatic 60s timeout |

---

## Slash Commands

| Command | Description | Permission |
|---|---|---|
| `/history @user [limit]` | Shows the last N violations for a user as a Discord Embed | Admin only |
| `/purgemsg @user [limit]` | Deletes all recent messages from a user across all channels | Admin only |

---

## Inference Queue

All LLM calls are serialized through an `asyncio.Queue` with a dedicated worker, preventing race conditions and model overload. Each request is logged with its ID, label (`classifier`, `verifier`, `moderator`) and current queue size.

---

## Stack

- **Python 3.13**
- **discord.py 2.7.1**
- **OpenAI Agents SDK 0.10.5**
- **Ollama** [local LLM inference (`qwen3:8b`)]
- **TinyDB 4.8.2** [lightweight JSON database for violation logs]
- **Docker and Docker Compose**

---

## Project Structure

```
.
├── bot.py                  # Discord bot, event handlers, slash commands
├── defined_agents.py       # Agent definitions, inference queue
├── models.py               # Models Classes
├── database.py             # TinyDB violation logging and purge logic
├── config.py               # Configuration from environment variables
├── violations.json         # Persistent violation log
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── .env                    # Environment variables
```

---

## Setup

### Prerequisites

- Docker and Docker Compose installed
- Ollama running and accessible (locally or on a remote host, I hosted it on my Gaming PC)
- A Discord bot token with the following permissions: `Send Messages`, `Manage Messages`, `Timeout Members`
- Message Content Intent enabled in the Discord Developer Portal for the Bot

### 1. Pull the model

```bash
ollama pull qwen3:8b
```

### 2. Configure environment variables

Create a `.env` file and include (at least) the variables below:
| Variable | Description | Default |
|---|---|---|
| `DISCORD_TOKEN` | Discord bot token | — |
| `ADMIN_CHANNEL_ID` | Channel ID for moderation logs | — |
| `OLLAMA_BASE_URL` | Ollama API base URL | — |
| `OLLAMA_MODEL` | Model name to use | — |
| `BANNED_KEYWORDS` | Comma-separated list of keywords that trigger agent analysis | — |

### 3. Run with Docker Compose

```bash
docker compose up --build
```

---

## Known Limitations

- **False positives on colloquial Italian**: the model (`qwen3:8b`) can misclassify informal expressions containing flagged keywords used in a non-offensive context. This means that classification quality heavily depends on the model used, so larger or fine-tuned models should significantly reduce false positives.
- **In-memory warn counts**: user warn counts are stored in memory and reset on bot restart. For production use, these should be persisted to the database.
- **Message truncation**: messages are truncated to `MAX_CONTENT_LENGTH` (300 characters) before analysis. Content beyond this limit is never evaluated, which could allow moderation bypass on very long messages.
- **Single-server architecture**: the current setup is designed for one server. Multi-server support at scale would require sharding and a more robust database and worker infrastructure.
- **TinyDB**: suitable for this PoC, not recommended for high-traffic production use. Using a proper database (PostgreSQL, SQLite) would be more appropriate at scale.

---

## Future Development

- Interactive monitoring dashboard (active users, staff online, message frequency, violation trends)
- Sharding support for multi-server deployment and configurable per-server thresholds
- Persistent warn counts across restarts

---

## Authors

[lud0vicapng](https://github.com/lud0vicapng)
