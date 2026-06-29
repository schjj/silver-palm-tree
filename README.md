# Bug Bounty AI Agent + Hunter Bot

AI-powered bug bounty hunting toolkit with autonomous scanning.

## Components

| Tool | Description |
|------|-------------|
| `bb_agent.py` | AI chat agent (Groq/Ollama) with tool orchestration |
| `hunter_bot.py` | Autonomous hunter bot - scheduled or manual scanning |
| `bb_recon.py` | Subdomain enum, port scan, web tech, URL gathering |
| `bb_vulnscan.py` | XSS, SQLi, SSTI, LFI, Open Redirect scanner |
| `bb_jsleak.py` | JS secret scanner (API keys, tokens, passwords) |
| `bb_takeover.py` | Subdomain takeover checker (20+ services) |
| `bb_hackerone.py` | HackerOne program manager |
| `kali_bridge.py` | Kali Linux SSH bridge for remote tools |
| `bb_siem.py` | SIEM — event ingestion, correlation, severity classification, alerting |

## Usage

### AI Agent
```bash
bb_agent.bat
```
Chat with the AI. Use `!recon`, `!scan`, `!js` commands.

### Hunter Bot (Auto-scan)
```bash
hunter_bot.bat
```
Or via GitHub Actions (every 6 hours). Edit `targets.json` to add your targets.

### Auto-sync
```bash
auto-sync.bat
```
Watches for file changes and auto-commits to GitHub.

### SIEM
```bash
python bb_siem.py --verbose
```
Or from the AI agent:
```
bb> !siem
```
Ingests findings from all scan results, correlates events, classifies severity (CRITICAL/HIGH/MEDIUM/LOW), and generates a report in `reports/siem_<timestamp>.md`. Set `SIEM_WEBHOOK_URL` to receive high-severity alerts via Slack/Discord webhook.

## Setup
```bash
pip install requests beautifulsoup4 dnspython colorama
set GROQ_API_KEY=gsk_your_key_here
```

Optional — set `SIEM_WEBHOOK_URL` (Slack/Discord) to receive SIEM alerts:
```bash
set SIEM_WEBHOOK_URL=https://hooks.slack.com/services/...
```

## GitHub Actions
The `.github/workflows/hunt.yml` workflow runs the hunter bot every 6 hours, then runs the SIEM analysis automatically.
Add `GROQ_API_KEY` to your repo secrets. Optionally add `SIEM_WEBHOOK_URL` for alert notifications.
