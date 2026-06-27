# Bug Bounty AI Agent

AI-powered bug bounty hunting toolkit with recon, vulnerability scanning, and PortSwigger lab tracking.

## Components
- \b_agent.py\ — AI chat agent (Groq/Ollama) with tool orchestration
- \b_recon.py\ — Subdomain enum, port scan, web tech, URL gathering
- \b_vulnscan.py\ — XSS, SQLi, SSTI, LFI, Open Redirect scanner
- \b_jsleak.py\ — JS secret scanner (API keys, tokens, passwords)
- \b_takeover.py\ — Subdomain takeover checker (20+ services)
- \b_hackerone.py\ — HackerOne program manager
- \kali_bridge.py\ — Kali Linux SSH bridge for remote tools

## Setup
\\\ash
pip install -r requirements.txt
\\\

## Usage
\\\ash
./bb_agent.bat
\\\

## Features
- Full recon pipeline (subdomains, ports, web tech, URLs)
- Vulnerability scanning with payload injection
- PortSwigger Academy lab progress tracker
- HackerOne program management
- Kali VM integration for advanced tools (nmap, nuclei, sqlmap)

