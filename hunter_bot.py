import json, os, sys, subprocess, time, re
from datetime import datetime
from pathlib import Path

BB_DIR = os.path.dirname(os.path.abspath(__file__))
TARGETS_FILE = os.path.join(BB_DIR, "targets.json")
RESULTS_DIR = os.path.join(BB_DIR, "results")
REPORTS_DIR = os.path.join(BB_DIR, "reports")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

PY = sys.executable
SCRIPTS = os.path.expanduser("~\\Desktop\\BugBounty\\scripts")
if not os.path.exists(SCRIPTS):
    SCRIPTS = BB_DIR

def log(msg, status="+"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{status}] {msg}")

def run_script(script, args, timeout=120):
    script_path = os.path.join(SCRIPTS, script)
    if not os.path.exists(script_path):
        script_path = os.path.join(BB_DIR, script)
    cmd = [PY, script_path] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "(timed out)"
    except Exception as e:
        return f"(error: {e})"

def load_targets():
    if not os.path.exists(TARGETS_FILE):
        default = {
            "targets": [
                {
                    "name": "example",
                    "domain": "example.com",
                    "in_scope": ["example.com", "*.example.com"],
                    "out_of_scope": [],
                    "scan_types": ["recon", "vuln", "js", "takeover"]
                }
            ],
            "schedule": {"interval_hours": 24, "auto_scan": True},
            "notifications": {"report_format": "markdown", "save_results": True}
        }
        with open(TARGETS_FILE, "w") as f:
            json.dump(default, f, indent=2)
        log(f"Created default targets.json — edit it with your targets", "!")
        return default["targets"]
    with open(TARGETS_FILE) as f:
        return json.load(f).get("targets", [])

def scan_target(target):
    name = target["name"]
    domain = target["domain"]
    scans = target.get("scan_types", ["recon"])
    safe_name = re.sub(r"[^a-zA-Z0-9]", "_", name)

    log(f"Starting scan on {name} ({domain})", "*")
    results = {"target": name, "domain": domain, "timestamp": datetime.now().isoformat(), "findings": []}

    target_dir = os.path.join(RESULTS_DIR, safe_name)
    os.makedirs(target_dir, exist_ok=True)

    if "recon" in scans:
        log(f"Running recon on {domain}...")
        out = run_script("bb_recon.py", [domain, "--no-scan"])
        with open(os.path.join(target_dir, "recon.txt"), "w") as f:
            f.write(out)
        findings = extract_findings(out, "recon")
        results["findings"].extend(findings)
        log(f"Recon done: {len(findings)} findings")

    if "vuln" in scans:
        urls_file = os.path.join(BB_DIR, "targets", safe_name, "all_urls.txt")
        if os.path.exists(urls_file):
            log(f"Running vuln scan on {domain}...")
            out = run_script("bb_vulnscan.py", [urls_file], timeout=180)
            with open(os.path.join(target_dir, "vulns.txt"), "w") as f:
                f.write(out)
            findings = extract_findings(out, "vuln")
            results["findings"].extend(findings)
            log(f"Vuln scan done: {len(findings)} potential issues")

    if "js" in scans:
        log(f"Running JS leak scan...")
        urls_file = os.path.join(BB_DIR, "targets", safe_name, "all_urls.txt")
        if os.path.exists(urls_file):
            out = run_script("bb_jsleak.py", [urls_file], timeout=120)
            with open(os.path.join(target_dir, "js_leaks.txt"), "w") as f:
                f.write(out)

    if "takeover" in scans:
        log(f"Running takeover check...")
        subs_file = os.path.join(BB_DIR, "targets", safe_name, "subdomains.txt")
        if os.path.exists(subs_file):
            out = run_script("bb_takeover.py", [subs_file], timeout=120)
            with open(os.path.join(target_dir, "takeover.txt"), "w") as f:
                f.write(out)

    report = generate_report(results)
    report_path = os.path.join(REPORTS_DIR, f"{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
    with open(report_path, "w") as f:
        f.write(report)
    log(f"Report saved: {report_path}", "+")

    return results

def extract_findings(output, scan_type):
    findings = []
    if not output:
        return findings
    lines = output.split("\n")
    for line in lines:
        if any(tag in line.lower() for tag in ["vuln", "found", "leak", "takeover", "cname", "aws", "key"]):
            findings.append({"type": scan_type, "detail": line.strip()[:200]})
    return findings

def generate_report(results):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# Bug Bounty Scan Report",
        f"**Target:** {results['target']} (`{results['domain']}`)",
        f"**Date:** {now}",
        f"**Findings:** {len(results['findings'])}",
        "",
        "## Summary",
        f"| Severity | Type | Detail |",
        f"|----------|------|--------|",
    ]
    for f in results["findings"]:
        lines.append(f"| - | {f['type']} | {f['detail']} |")

    lines.extend([
        "",
        "## Files",
        f"- Results: `results/{re.sub(r'[^a-zA-Z0-9]', '_', results['target'])}/`",
        "- Raw scan data in results directory",
        "",
        "---",
        f"*Generated by Hunter Bot at {now}*"
    ])
    return "\n".join(lines)

def auto_commit():
    """Auto-commit results to git if in a repo"""
    try:
        result = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, timeout=10, cwd=BB_DIR)
        if result.stdout.strip():
            subprocess.run(["git", "add", "-A"], cwd=BB_DIR, timeout=10)
            subprocess.run(["git", "commit", "-m", f"Auto-scan results {datetime.now().strftime('%Y-%m-%d %H:%M')}"], cwd=BB_DIR, timeout=10)
            subprocess.run(["git", "push"], cwd=BB_DIR, timeout=30)
            log("Committed and pushed results to GitHub", "+")
    except Exception as e:
        log(f"Auto-commit skipped: {e}", "-")

if __name__ == "__main__":
    print(r"""
   _    _       _
  | |  | |     | |
  | |__| |_   _| |_ _   _ _ __   ___
  |  __  | | | | __| | | | '_ \ / _ \
  | |  | | |_| | |_| |_| | |_) |  __/
  |_|  |_|\__,_|\__|\__,_| .__/ \___|
                          | |
                          |_|
    Autonomous Bug Bounty Hunter
    """)

    targets = load_targets()
    if not targets:
        log("No targets configured. Edit targets.json", "-")
        sys.exit(1)

    log(f"Loaded {len(targets)} targets")
    log(f"Scripts dir: {SCRIPTS}")

    for target in targets:
        print(f"\n{'='*60}")
        log(f"Scanning: {target['name']} ({target['domain']})", "*")
        print(f"{'='*60}")
        try:
            results = scan_target(target)
            log(f"Completed {target['name']}: {len(results['findings'])} findings", "+")
        except Exception as e:
            log(f"Failed on {target['name']}: {e}", "-")

    auto_commit()
    log("Hunter Bot run complete", "+")
