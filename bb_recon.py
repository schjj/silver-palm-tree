import json, os, sys, subprocess, socket, ssl, time, re, urllib.request, urllib.error, ssl as ssl_mod
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

PY = r"C:\Users\salva\AppData\Local\Programs\Python\Python312\python.exe"
NMAP = os.path.expanduser("~\\Desktop\\NmapPortable\\nmap.exe")
BB_DIR = os.path.expanduser("~\\Desktop\\BugBounty")
TARGETS_DIR = os.path.join(BB_DIR, "targets")
REPORTS_DIR = os.path.join(BB_DIR, "reports")

os.makedirs(TARGETS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

SSL_CTX = ssl_mod.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl_mod.CERT_NONE

def banner():
    print("""
  ____        _       ____                      _
 | __ ) _   _| |_   | __ )  ___  _ __ ___  _ __| |_ ___ _ __
 |  _ \\| | | | \ \ / /  _ \ / _ \\| '_ ` _ \\| '__| __/ _ \ '__|
 | |_) | |_| | |\ V /| |_) | (_) | | | | | | |  | ||  __/ |
 |____/ \__,_|_| \_/ |____/ \___/|_| |_| |_|_|   \__\___|_|
    """)

def log(msg, status="+"):
    ts = datetime.now().strftime("%H:%M:%S")
    color = {"+": "32", "-": "31", "*": "33", "!": "36"}.get(status, "0")
    print(f"\033[{color}m[{status}]\033[0m {msg}")

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    log(f"Saved: {path}")

def load_json(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

def read_file_lines(path):
    if os.path.exists(path):
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]
    return []

def write_file_lines(path, lines):
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

# ─── SUBDOMAIN ENUMERATION ────────────────────────────────────

def subdomain_crtsh(domain):
    results = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        data = json.loads(urllib.request.urlopen(req, context=SSL_CTX, timeout=15).read().decode())
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    results.add(sub)
        log(f"crt.sh: {len(results)} subdomains")
    except Exception as e:
        log(f"crt.sh error: {e}", "-")
    return sorted(results)

def subdomain_bruteforce(domain, wordlist_file=None):
    results = set()
    if wordlist_file is None:
        wordlist_file = os.path.join(BB_DIR, "wordlists", "subdomains.txt")
    if not os.path.exists(wordlist_file):
        log("No wordlist found, using built-in mini list", "*")
        words = ["www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "blog", "cdn",
                 "shop", "app", "portal", "secure", "vpn", "docs", "support", "m", "mobile", "web",
                 "email", "cloud", "sso", "status", "help", "live", "prod", "uat", "demo", "beta"]
    else:
        words = read_file_lines(wordlist_file)

    def check(word):
        sub = f"{word}.{domain}"
        try:
            socket.getaddrinfo(sub, 80, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            return sub
        except:
            return None

    log(f"Brute forcing {len(words)} subdomains...")
    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(check, w): w for w in words}
        done = 0
        for f in as_completed(futures):
            done += 1
            res = f.result()
            if res:
                results.add(res)
                log(f"Found: {res}")
    log(f"Bruteforce: {len(results)} new subdomains")
    return sorted(results)

def subdomain_enum(domain):
    log(f"Enumerating subdomains for {domain}")
    subs = set()
    subs.update(subdomain_crtsh(domain))
    subs.add(domain)
    if len(subs) < 5:
        subs.update(subdomain_bruteforce(domain))
    return sorted(subs)

# ─── PORT SCANNING ────────────────────────────────────────────

def port_scan(subdomain, ports="21,22,25,53,80,110,143,443,445,465,587,993,995,1433,1521,2049,2082,2083,2086,2087,2095,2096,3306,3389,5432,5900,5985,5986,6379,8080,8443,9000,9090,10000,27017"):
    results = {"host": subdomain, "open_ports": []}
    if os.path.exists(NMAP):
        log(f"Nmap scan: {subdomain}")
        try:
            r = subprocess.run(
                [NMAP, "-T4", "-p", ports, "--open", "-oG", "-", subdomain],
                capture_output=True, text=True, timeout=120
            )
            for line in r.stdout.split("\n"):
                if "/open/" in line:
                    parts = line.split()
                    for part in parts:
                        if "/open/" in part:
                            port = part.split("/")[0]
                            svc = part.split("/")[2] if len(part.split("/")) > 2 else "unknown"
                            results["open_ports"].append({"port": int(port), "service": svc})
        except subprocess.TimeoutExpired:
            log("Nmap timeout", "-")
        except Exception as e:
            log(f"Nmap error: {e}", "-")
    else:
        single_ports = [int(p) for p in ports.split(",")]
        log(f"Socket connect scan (no Npcap): {subdomain}")
        def scan_port(p):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                r = s.connect_ex((subdomain, p))
                if r == 0:
                    try:
                        svc = socket.getservbyport(p)
                    except:
                        svc = "unknown"
                    return {"port": p, "service": svc}
            except:
                pass
            finally:
                s.close()
            return None
        with ThreadPoolExecutor(max_workers=50) as pool:
            for res in pool.map(scan_port, single_ports):
                if res:
                    results["open_ports"].append(res)
    results["open_ports"].sort(key=lambda x: x["port"])
    log(f"Open ports on {subdomain}: {[p['port'] for p in results['open_ports']]}")
    return results

# ─── WEB TECH DETECTION ───────────────────────────────────────

def detect_web_tech(url):
    techs = {"url": url, "technologies": [], "headers": {}}
    if not url.startswith("http"):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=10, context=SSL_CTX)
        headers = dict(resp.headers)
        techs["status"] = resp.status
        techs["headers"] = {k: v[:100] for k, v in headers.items()}

        server = headers.get("Server", "")
        if server:
            techs["technologies"].append(f"Server: {server}")

        powered = headers.get("X-Powered-By", "")
        if powered:
            techs["technologies"].append(f"X-Powered-By: {powered}")

        ct = headers.get("Content-Type", "")
        if "php" in ct or "php" in server.lower():
            techs["technologies"].append("PHP")
        if "asp" in server.lower() or "asp.net" in server.lower():
            techs["technologies"].append("ASP.NET")
        if "nginx" in server.lower():
            techs["technologies"].append("Nginx")
        if "apache" in server.lower():
            techs["technologies"].append("Apache")
        if "cloudflare" in server.lower() or "cloudflare" in str(headers).lower():
            techs["technologies"].append("Cloudflare")
        if "express" in powered.lower():
            techs["technologies"].append("Express.js")
        if "python" in server.lower() or "gunicorn" in server.lower():
            techs["technologies"].append("Python")

        body = resp.read().decode("utf-8", errors="ignore").lower()
        if "wp-content" in body or "wp-includes" in body:
            techs["technologies"].append("WordPress")
        if "csrf" in headers.get("Set-Cookie", "").lower():
            techs["technologies"].append("Django/Flask CSRF")
        if "session" in body:
            techs["technologies"].append("Session-based auth")
        if "jquery" in body:
            techs["technologies"].append("jQuery")
        if "react" in body or "react-dom" in body:
            techs["technologies"].append("React")
        if "angular" in body:
            techs["technologies"].append("Angular")
        if "vue" in body:
            techs["technologies"].append("Vue.js")
        if "bootstrap" in body:
            techs["technologies"].append("Bootstrap")

        log(f"Tech: {', '.join(techs['technologies']) if techs['technologies'] else 'basic'}")
    except urllib.error.HTTPError as e:
        techs["status"] = e.code
        log(f"HTTP {e.code} for {url}")
    except Exception as e:
        techs["error"] = str(e)
        log(f"Tech detection error: {e}", "-")
    return techs

# ─── URL GATHERING ────────────────────────────────────────────

def gather_urls(domain):
    all_urls = set()
    log(f"Gathering URLs for {domain}")

    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=2000"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        data = json.loads(urllib.request.urlopen(req, context=SSL_CTX, timeout=30).read().decode())
        for entry in data[1:]:
            if isinstance(entry, list) and len(entry) > 0:
                all_urls.add(entry[0])
        log(f"Wayback: {len(all_urls)} URLs")
    except Exception as e:
        log(f"Wayback error: {e}", "-")

    try:
        url = f"https://index.commoncrawl.org/CC-MAIN-2025-13-index?url=*.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        data = urllib.request.urlopen(req, context=SSL_CTX, timeout=30).read().decode()
        for line in data.strip().split("\n"):
            try:
                entry = json.loads(line)
                u = entry.get("url", "")
                if u:
                    all_urls.add(u)
            except:
                pass
        log(f"CommonCrawl: more URLs added")
    except Exception as e:
        log(f"CommonCrawl error: {e}", "-")

    return sorted(all_urls)

def categorize_urls(urls):
    kinds = {"js": [], "php": [], "asp": [], "api": [], "admin": [], "params": [], "other": []}
    for u in urls:
        if ".js" in u:
            kinds["js"].append(u)
        if ".php" in u:
            kinds["php"].append(u)
        if ".asp" in u or ".aspx" in u:
            kinds["asp"].append(u)
        if "/api/" in u or "api." in u:
            kinds["api"].append(u)
        if "admin" in u.lower() or "login" in u.lower() or "dashboard" in u.lower():
            kinds["admin"].append(u)
        if "?" in u and "=" in u:
            kinds["params"].append(u)
        kinds["other"].append(u)
    for k, v in kinds.items():
        log(f"  {k}: {len(v)} URLs")
    return kinds

# ─── SCREENSHOT (via text response) ───────────────────────────

def text_screenshot(subdomain, port=80):
    """Grab page title and meta for non-screenshotable env"""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{subdomain}:{port}" if port not in (80, 443) else f"{scheme}://{subdomain}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=8, context=SSL_CTX)
        body = resp.read().decode("utf-8", errors="ignore")
        title = ""
        m = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()[:100]
        size = len(body)
        return {"url": url, "status": resp.status, "title": title, "size": size}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "title": f"HTTP {e.code}"}
    except Exception as e:
        return {"url": url, "error": str(e)}

# ─── MAIN PIPELINE ────────────────────────────────────────────

def run_pipeline(domain, do_port_scan=True, do_web=True, do_urls=True):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safedomain = domain.replace(".", "_")
    output_dir = os.path.join(TARGETS_DIR, safedomain)
    os.makedirs(output_dir, exist_ok=True)

    banner()
    log(f"Starting recon on {domain}")
    log(f"Output: {output_dir}")

    # 1. Subdomains
    log("Phase 1: Subdomain Enumeration", "!")
    subs = subdomain_enum(domain)
    write_file_lines(os.path.join(output_dir, "subdomains.txt"), subs)
    save_json(os.path.join(output_dir, "subdomains.json"), subs)

    if not subs:
        log("No subdomains found, aborting", "-")
        return

    # 2. Subdomain probing (live check)
    log("Phase 2: Probing live hosts", "!")
    live = []
    def probe(sub):
        for port in (80, 443, 8080, 8443):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                ip = socket.gethostbyname(sub)
                if s.connect_ex((sub, port)) == 0:
                    scheme = "https" if port in (443, 8443) else "http"
                    url = f"{scheme}://{sub}" if port in (80, 443) else f"{scheme}://{sub}:{port}"
                    live.append({"subdomain": sub, "ip": ip, "port": port, "url": url})
                    s.close()
                    return url
                s.close()
            except:
                pass
        return None
    with ThreadPoolExecutor(max_workers=20) as pool:
        pool.map(probe, subs)
    write_file_lines(os.path.join(output_dir, "live.txt"), [h["url"] for h in live])
    save_json(os.path.join(output_dir, "live.json"), live)
    log(f"Live hosts: {len(live)}")

    # 3. Port scan
    if do_port_scan:
        log("Phase 3: Port Scanning", "!")
        all_ports = []
        for host in live:
            ps = port_scan(host["subdomain"])
            all_ports.append(ps)
        save_json(os.path.join(output_dir, "ports.json"), all_ports)

    # 4. Web tech & screenshots
    if do_web:
        log("Phase 4: Web Technology Detection", "!")
        techs = []
        screens = []
        for host in live:
            t = detect_web_tech(host["url"])
            techs.append(t)
            s = text_screenshot(host["subdomain"], host["port"])
            screens.append(s)
        save_json(os.path.join(output_dir, "technologies.json"), techs)
        save_json(os.path.join(output_dir, "screenshots.json"), screens)

        # Summary
        print("\n\033[36m=== LIVE HOSTS SUMMARY ===\033[0m")
        for i, host in enumerate(live):
            t = techs[i] if i < len(techs) else {}
            s = screens[i] if i < len(screens) else {}
            tech_str = ", ".join(t.get("technologies", []))[:60] if t.get("technologies") else "?"
            title_str = s.get("title", "?")[:50]
            print(f"  \033[33m{host['url']}\033[0m")
            print(f"    Status: {s.get('status', '?')}  Title: {title_str}")
            print(f"    Tech: {tech_str}  IP: {host['ip']}")
            print()

    # 5. URL gathering
    if do_urls:
        log("Phase 5: URL Gathering", "!")
        urls = gather_urls(domain)
        write_file_lines(os.path.join(output_dir, "all_urls.txt"), urls)
        if urls:
            cats = categorize_urls(urls)
            for k, v in cats.items():
                if v:
                    write_file_lines(os.path.join(output_dir, f"urls_{k}.txt"), v)

    # 6. Final report
    report = {
        "domain": domain,
        "timestamp": str(datetime.now()),
        "subdomain_count": len(subs),
        "live_count": len(live),
        "url_count": len(urls) if 'urls' in dir() else 0,
        "output_dir": output_dir
    }
    save_json(os.path.join(output_dir, "report.json"), report)
    log(f"Recon complete! Results in {output_dir}", "!")
    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python bb_recon.py <domain> [--no-scan] [--no-web] [--no-urls]")
        sys.exit(1)
    domain = sys.argv[1].strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    do_scan = "--no-scan" not in sys.argv
    do_web = "--no-web" not in sys.argv
    do_urls = "--no-urls" not in sys.argv
    run_pipeline(domain, do_scan, do_web, do_urls)
