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

## Setup
```bash
pip install requests beautifulsoup4 dnspython colorama
set GROQ_API_KEY=gsk_your_key_here
```

## GitHub Actions
The `.github/workflows/hunt.yml` workflow runs the hunter bot every 6 hours.
Add `GROQ_API_KEY` to your repo secrets.
