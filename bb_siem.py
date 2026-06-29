import json, os, sys, re, glob, urllib.request
from datetime import datetime

BB_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BB_DIR, "results")
REPORTS_DIR = os.path.join(BB_DIR, "reports")
SIEM_LOG = os.path.join(RESULTS_DIR, "siem_events.json")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# ─── SEVERITY CLASSIFICATION ──────────────────────────────────

SEVERITY_MAP = {
    "sqli": "CRITICAL",
    "ssti": "CRITICAL",
    "lfi": "CRITICAL",
    "rce": "CRITICAL",
    "takeover": "HIGH",
    "xss": "HIGH",
    "api_key": "HIGH",
    "aws_key": "HIGH",
    "aws": "HIGH",
    "secret": "HIGH",
    "token": "HIGH",
    "password": "HIGH",
    "key": "HIGH",
    "open_redirect": "MEDIUM",
    "redirect": "MEDIUM",
    "leak": "MEDIUM",
    "info": "LOW",
    "tech": "LOW",
    "recon": "LOW",
}

SEVERITY_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_COLOR = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[36m",
    "INFO": "\033[0m",
}
RESET = "\033[0m"


def classify_severity(event_type, detail=""):
    detail_lower = detail.lower()
    for keyword, sev in SEVERITY_MAP.items():
        if keyword in event_type.lower() or keyword in detail_lower:
            return sev
    return "INFO"


# ─── EVENT MODEL ──────────────────────────────────────────────

def make_event(source, event_type, detail, target="", severity=None, raw=None):
    sev = severity or classify_severity(event_type, detail)
    return {
        "id": f"{int(datetime.now().timestamp() * 1000)}-{abs(hash(detail)) % 10000}",
        "timestamp": datetime.now().isoformat(),
        "source": source,
        "type": event_type,
        "severity": sev,
        "target": target,
        "detail": detail[:500],
        "raw": raw,
        "acknowledged": False,
    }


# ─── PERSISTENT EVENT LOG ─────────────────────────────────────

def load_events():
    if os.path.exists(SIEM_LOG):
        try:
            with open(SIEM_LOG) as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_events(events):
    with open(SIEM_LOG, "w") as f:
        json.dump(events, f, indent=2, default=str)


def append_events(new_events):
    events = load_events()
    existing_ids = {e.get("id") for e in events}
    added = 0
    for ev in new_events:
        if ev["id"] not in existing_ids:
            events.append(ev)
            existing_ids.add(ev["id"])
            added += 1
    save_events(events)
    return added


# ─── INGESTION: VULN SCAN REPORTS ─────────────────────────────

def ingest_vulnscan_reports():
    events = []
    pattern = os.path.join(REPORTS_DIR, "vulnscan_*.json")
    for path in glob.glob(pattern):
        try:
            with open(path) as f:
                data = json.load(f)
            for entry in data:
                target = entry.get("url", "")
                for vuln in entry.get("vulnerabilities", []):
                    vtype = vuln.get("type", "unknown")
                    detail = (
                        f"{vtype.upper()} on param '{vuln.get('param','')}' "
                        f"payload={vuln.get('payload','')[:60]} "
                        f"status={vuln.get('status','?')}"
                    )
                    events.append(make_event(
                        source="vulnscan",
                        event_type=vtype,
                        detail=detail,
                        target=target,
                        raw=vuln,
                    ))
        except Exception as e:
            _log(f"Skipping {path}: {e}", "-")
    return events


# ─── INGESTION: JS LEAK REPORTS ───────────────────────────────

def ingest_jsleak_results():
    events = []
    pattern = os.path.join(RESULTS_DIR, "**", "js_leaks.txt")
    for path in glob.glob(pattern, recursive=True):
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # Detect high-signal lines (key/token/password hits)
                    low = line.lower()
                    if any(k in low for k in ["key", "token", "secret", "password", "api", "aws"]):
                        sev = "HIGH"
                        etype = "secret_leak"
                    else:
                        sev = "MEDIUM"
                        etype = "js_leak"
                    events.append(make_event(
                        source="jsleak",
                        event_type=etype,
                        detail=line[:300],
                        severity=sev,
                    ))
        except Exception as e:
            _log(f"Skipping {path}: {e}", "-")
    return events


# ─── INGESTION: TAKEOVER RESULTS ──────────────────────────────

def ingest_takeover_results():
    events = []
    pattern = os.path.join(RESULTS_DIR, "**", "takeover.txt")
    for path in glob.glob(pattern, recursive=True):
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    low = line.lower()
                    if any(k in low for k in ["vuln", "takeover", "cname", "found"]):
                        events.append(make_event(
                            source="takeover",
                            event_type="takeover",
                            detail=line[:300],
                            severity="HIGH",
                        ))
        except Exception as e:
            _log(f"Skipping {path}: {e}", "-")
    return events


# ─── INGESTION: RECON FINDINGS ────────────────────────────────

def ingest_recon_results():
    events = []
    pattern = os.path.join(RESULTS_DIR, "**", "recon.txt")
    for path in glob.glob(pattern, recursive=True):
        target_name = os.path.basename(os.path.dirname(path))
        try:
            with open(path) as f:
                content = f.read()
            # Extract notable recon lines
            for line in content.split("\n"):
                low = line.lower()
                if any(k in low for k in ["found", "vuln", "leak", "cname", "aws", "key", "open"]):
                    events.append(make_event(
                        source="recon",
                        event_type="recon",
                        detail=line.strip()[:300],
                        target=target_name,
                        severity="LOW",
                    ))
        except Exception as e:
            _log(f"Skipping {path}: {e}", "-")
    return events


# ─── INGESTION: HUNTER BOT REPORTS ───────────────────────────

def ingest_hunter_reports():
    events = []
    pattern = os.path.join(REPORTS_DIR, "*.md")
    for path in glob.glob(pattern):
        try:
            with open(path) as f:
                content = f.read()
            target_m = re.search(r"\*\*Target:\*\*\s+(\S+)", content)
            target = target_m.group(1) if target_m else os.path.basename(path)
            for line in content.split("\n"):
                if "|" in line and "type" not in line.lower() and "---" not in line:
                    parts = [p.strip() for p in line.split("|") if p.strip()]
                    if len(parts) >= 3:
                        etype = parts[1] if len(parts) > 1 else "finding"
                        detail = parts[2] if len(parts) > 2 else line.strip()
                        events.append(make_event(
                            source="hunter_bot",
                            event_type=etype,
                            detail=detail[:300],
                            target=target,
                        ))
        except Exception as e:
            _log(f"Skipping {path}: {e}", "-")
    return events


# ─── FULL INGESTION PIPELINE ──────────────────────────────────

def ingest_all():
    all_events = []
    all_events.extend(ingest_vulnscan_reports())
    all_events.extend(ingest_jsleak_results())
    all_events.extend(ingest_takeover_results())
    all_events.extend(ingest_recon_results())
    all_events.extend(ingest_hunter_reports())
    return all_events


# ─── ALERT RULES / CORRELATION ────────────────────────────────

ALERT_RULES = [
    {
        "name": "Critical Vulnerability Detected",
        "condition": lambda e: e["severity"] == "CRITICAL",
        "description": "A critical vulnerability (SQLi/SSTI/LFI/RCE) was found.",
    },
    {
        "name": "Subdomain Takeover Possible",
        "condition": lambda e: e["type"] in ("takeover",),
        "description": "A subdomain may be vulnerable to takeover.",
    },
    {
        "name": "Credential / Secret Leak",
        "condition": lambda e: e["type"] in ("secret_leak",) or e["severity"] == "HIGH" and "secret" in e["detail"].lower(),
        "description": "API key, token, or password found in JS or scan output.",
    },
    {
        "name": "Multiple High-Severity Findings on Same Target",
        "condition": None,  # handled separately during correlation
        "description": "Target has 3+ high-severity findings.",
    },
]


def correlate_events(events):
    """Return triggered alerts from events."""
    alerts = []
    target_high = {}
    for ev in events:
        # Per-rule single-event checks
        for rule in ALERT_RULES:
            if rule["condition"] and rule["condition"](ev):
                alerts.append({
                    "rule": rule["name"],
                    "description": rule["description"],
                    "event_id": ev["id"],
                    "severity": ev["severity"],
                    "target": ev.get("target", ""),
                    "detail": ev["detail"],
                    "timestamp": ev["timestamp"],
                })

        # Accumulate for multi-event rules
        tgt = ev.get("target", "unknown")
        if ev["severity"] in ("HIGH", "CRITICAL"):
            target_high[tgt] = target_high.get(tgt, 0) + 1

    # Multi-event rule
    for tgt, count in target_high.items():
        if count >= 3:
            alerts.append({
                "rule": "Multiple High-Severity Findings on Same Target",
                "description": ALERT_RULES[3]["description"],
                "event_id": None,
                "severity": "HIGH",
                "target": tgt,
                "detail": f"{count} high/critical findings on {tgt}",
                "timestamp": datetime.now().isoformat(),
            })

    return alerts


# ─── OPTIONAL WEBHOOK ALERTING ────────────────────────────────

def send_webhook(alerts, webhook_url):
    """Send high-severity alerts to a Slack/Discord webhook."""
    if not webhook_url or not alerts:
        return
    critical = [a for a in alerts if a["severity"] in ("CRITICAL", "HIGH")]
    if not critical:
        return
    lines = ["**🚨 Bug Bounty SIEM Alert**"]
    for a in critical[:10]:
        lines.append(f"**[{a['severity']}] {a['rule']}**")
        lines.append(f"> Target: `{a['target']}`  Detail: {a['detail'][:120]}")
    payload = json.dumps({"content": "\n".join(lines)}).encode()
    try:
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)
        _log(f"Webhook: sent {len(critical)} alerts")
    except Exception as e:
        _log(f"Webhook error: {e}", "-")


# ─── DASHBOARD ────────────────────────────────────────────────

def _severity_counts(events):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for ev in events:
        counts[ev.get("severity", "INFO")] = counts.get(ev.get("severity", "INFO"), 0) + 1
    return counts


def dashboard(events=None, alerts=None):
    if events is None:
        events = load_events()
    if alerts is None:
        alerts = correlate_events(events)

    counts = _severity_counts(events)
    lines = []
    lines.append("\033[36m╔══════════════════════════════════════╗\033[0m")
    lines.append("\033[36m║      BUG BOUNTY SIEM DASHBOARD       ║\033[0m")
    lines.append("\033[36m╚══════════════════════════════════════╝\033[0m")
    lines.append(f"  Events: {len(events)} total")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        c = counts.get(sev, 0)
        if c:
            col = SEVERITY_COLOR.get(sev, "")
            lines.append(f"  {col}{sev:10s}{RESET} {c}")

    lines.append("")
    lines.append(f"  Alerts triggered: {len(alerts)}")
    for a in alerts[:10]:
        col = SEVERITY_COLOR.get(a["severity"], "")
        lines.append(f"  {col}[{a['severity']:8s}]{RESET} {a['rule']}: {a['detail'][:60]}")

    if len(events) > 0:
        lines.append("")
        lines.append("  Recent events (last 5):")
        for ev in sorted(events, key=lambda x: x["timestamp"], reverse=True)[:5]:
            col = SEVERITY_COLOR.get(ev.get("severity", "INFO"), "")
            ts = ev["timestamp"][:16]
            lines.append(f"  {col}[{ev.get('severity','?'):8s}]{RESET} {ts}  {ev['type']:15s}  {ev['detail'][:50]}")

    return "\n".join(lines)


def generate_markdown_report(events, alerts):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = _severity_counts(events)
    lines = [
        "# SIEM Security Report",
        f"**Generated:** {now}",
        f"**Total Events:** {len(events)}  |  **Alerts:** {len(alerts)}",
        "",
        "## Severity Summary",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")

    if alerts:
        lines += [
            "",
            "## Active Alerts",
            "| Severity | Rule | Target | Detail |",
            "|----------|------|--------|--------|",
        ]
        for a in alerts:
            lines.append(f"| {a['severity']} | {a['rule']} | {a['target']} | {a['detail'][:100]} |")

    if events:
        lines += [
            "",
            "## All Events",
            "| Timestamp | Severity | Source | Type | Target | Detail |",
            "|-----------|----------|--------|------|--------|--------|",
        ]
        for ev in sorted(events,
                         key=lambda x: SEVERITY_SCORE.get(x.get("severity", "INFO"), 0),
                         reverse=True)[:100]:
            lines.append(
                f"| {ev['timestamp'][:16]} | {ev.get('severity','')} | {ev['source']} "
                f"| {ev['type']} | {ev.get('target','')[:30]} | {ev['detail'][:80]} |"
            )

    lines += ["", "---", f"*Generated by bb_siem.py at {now}*"]
    return "\n".join(lines)


# ─── LOGGING ──────────────────────────────────────────────────

def _log(msg, status="+"):
    ts = datetime.now().strftime("%H:%M:%S")
    color = {"+": "32", "-": "31", "*": "33", "!": "36"}.get(status, "0")
    print(f"\033[{color}m[{status}]\033[0m {msg}")


# ─── MAIN ─────────────────────────────────────────────────────

def run_siem(webhook_url=None, verbose=False):
    _log("SIEM: ingesting events from all scan results...", "!")
    new_events = ingest_all()
    added = append_events(new_events)
    _log(f"Ingested {len(new_events)} events, {added} new")

    all_events = load_events()
    alerts = correlate_events(all_events)
    _log(f"Alerts: {len(alerts)} triggered")

    # Save markdown report
    report_path = os.path.join(REPORTS_DIR, f"siem_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
    with open(report_path, "w") as f:
        f.write(generate_markdown_report(all_events, alerts))
    _log(f"Report saved: {report_path}", "+")

    if webhook_url:
        send_webhook(alerts, webhook_url)

    if verbose:
        print(dashboard(all_events, alerts))

    return all_events, alerts


if __name__ == "__main__":
    webhook = os.environ.get("SIEM_WEBHOOK_URL", "")
    verb = "--verbose" in sys.argv or "-v" in sys.argv
    events, alerts = run_siem(webhook_url=webhook, verbose=True)
    print(f"\nDone. {len(events)} events, {len(alerts)} alerts.")
