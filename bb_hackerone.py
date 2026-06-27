import json, os, sys, webbrowser, urllib.request, re, ssl as ssl_mod
from datetime import datetime
from urllib.parse import urlparse

BB_DIR = os.path.expanduser("~\\Desktop\\BugBounty")
PROGRAMS_DIR = os.path.join(BB_DIR, "programs")
os.makedirs(PROGRAMS_DIR, exist_ok=True)

H1_API = "https://api.hackerone.com/v1"
SSL_CTX = ssl_mod.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl_mod.CERT_NONE

def log(msg, status="+"):
    ts = datetime.now().strftime("%H:%M:%S")
    color = {"+": "32", "-": "31", "*": "33", "!": "36"}.get(status, "0")
    print(f"\033[{color}m[{status}]\033[0m {msg}")

def open_hackerone():
    """Open HackerOne in the browser"""
    webbrowser.open("https://hackerone.com")
    log("Opened HackerOne")
    log("Sign up or log in to get your API token (Settings → API)")

def create_program(name, in_scope_domains, out_of_scope_domains=None):
    """Create a HackerOne program config for recon"""
    program = {
        "name": name,
        "url": f"https://hackerone.com/{name}",
        "in_scope": {
            "domains": in_scope_domains,
        },
        "out_of_scope": {
            "domains": out_of_scope_domains or [],
        },
        "created": str(datetime.now()),
    }
    
    safe_name = name.lower().replace(" ", "_").replace("/", "_")
    path = os.path.join(PROGRAMS_DIR, f"{safe_name}.json")
    with open(path, "w") as f:
        json.dump(program, f, indent=2)
    
    # Create target directory structure
    target_dir = os.path.join(BB_DIR, "targets", safe_name)
    os.makedirs(target_dir, exist_ok=True)
    
    # Save scope domains
    if in_scope_domains:
        with open(os.path.join(target_dir, "in_scope.txt"), "w") as f:
            f.write("\n".join(in_scope_domains))
    
    log(f"Program '{name}' created: {path}")
    return program

def list_programs():
    """List saved HackerOne programs"""
    files = [f for f in os.listdir(PROGRAMS_DIR) if f.endswith(".json")]
    if not files:
        log("No programs configured yet", "*")
        print("  Use: create_program('name', ['domains'], ['excludes'])")
        return []
    
    programs = []
    for f in files:
        with open(os.path.join(PROGRAMS_DIR, f)) as fp:
            p = json.load(fp)
            programs.append(p)
            print(f"  \033[36m{p['name']}\033[0m")
            print(f"    URL: {p['url']}")
            print(f"    In scope: {len(p['in_scope']['domains'])} domains")
            print(f"    Out of scope: {len(p['out_of_scope']['domains'])} domains")
            print()
    return programs

def recon_program(program_name, quick=True):
    """Run recon on all in-scope domains of a program"""
    path = os.path.join(PROGRAMS_DIR, f"{program_name}.json")
    if not os.path.exists(path):
        log(f"Program '{program_name}' not found", "-")
        return
    
    with open(path) as f:
        program = json.load(f)
    
    log(f"Starting recon on {program['name']}", "!")
    domains = program["in_scope"]["domains"]
    log(f"Targets: {len(domains)} domains")
    
    for domain in domains:
        log(f"Recon: {domain}")
        # Import and run the recon pipeline
        sys.path.insert(0, os.path.join(BB_DIR, "scripts"))
        from bb_recon import run_pipeline
        if quick:
            run_pipeline(domain, do_port_scan=False, do_web=True, do_urls=True)
        else:
            run_pipeline(domain)
    
    log("Program recon complete!", "!")

def scrape_hackerone_programs(limit=10):
    """Scrape publicly listed HackerOne programs (ethical use only)"""
    log("Scraping HackerOne directory...")
    try:
        url = "https://hackerone.com/programs/search?query=&sort=name&page=1"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "application/json",
        })
        resp = urllib.request.urlopen(req, timeout=15, context=SSL_CTX)
        data = json.loads(resp.read().decode())
        results = []
        for item in data.get("results", [])[:limit]:
            results.append({
                "name": item.get("handle", ""),
                "url": f"https://hackerone.com/{item.get('handle', '')}",
                "offers_bounties": item.get("offers_bounties", False),
            })
        return results
    except Exception as e:
        log(f"Scrape error: {e}", "-")
        return []

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "open":
            open_hackerone()
        elif cmd == "list":
            list_programs()
        elif cmd == "create":
            if len(sys.argv) > 3:
                name = sys.argv[2]
                domains = sys.argv[3].split(",")
                excludes = sys.argv[4].split(",") if len(sys.argv) > 4 else []
                create_program(name, domains, excludes)
            else:
                print("Usage: python bb_hackerone.py create <name> <domain1,domain2> [excludes]")
        elif cmd == "recon":
            if len(sys.argv) > 2:
                recon_program(sys.argv[2])
        else:
            print("Commands: open, list, create, recon")
    else:
        open_hackerone()
