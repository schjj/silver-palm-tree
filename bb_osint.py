"""
bb_osint.py — OSINT (Open Source Intelligence) module

Capabilities:
  - WHOIS lookup (domain registration / registrant info)
  - DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
  - Certificate Transparency (crt.sh) — find subdomains & SANs
  - Email harvesting from web pages and Hunter.io (optional API key)
  - HaveIBeenPwned breach check (optional API key)
  - GitHub dorking for sensitive org/user repos
  - Google dork URL builder (opens in browser or returns query)
  - Shodan host lookup (optional API key)
  - Social media footprint check (LinkedIn, Twitter/X, GitHub, Facebook)
  - ASN / IP geolocation enrichment

Usage (standalone):
  python bb_osint.py <domain_or_target> [--all] [--emails] [--dns] [--whois]

Usage (from agent):
  !osint <domain>
"""

import json, os, sys, re, socket, ssl as ssl_mod, urllib.request, urllib.parse, urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

BB_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BB_DIR, "results")
REPORTS_DIR = os.path.join(BB_DIR, "reports")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

SSL_CTX = ssl_mod.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl_mod.CERT_NONE

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Optional API keys from environment
HUNTER_API_KEY = os.environ.get("HUNTER_API_KEY", "")
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")


# ─── HELPERS ──────────────────────────────────────────────────

def log(msg, status="+"):
    color = {"+": "32", "-": "31", "*": "33", "!": "36"}.get(status, "0")
    print(f"\033[{color}m[{status}]\033[0m {msg}")


def _get(url, headers=None, timeout=12):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX)
        return resp.read().decode("utf-8", errors="ignore"), resp.status
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="ignore"), e.code
    except Exception as e:
        return None, str(e)


def _json_get(url, headers=None, timeout=12):
    body, status = _get(url, headers=headers, timeout=timeout)
    if body:
        try:
            return json.loads(body), status
        except Exception:
            pass
    return None, status


# ─── WHOIS ────────────────────────────────────────────────────

def whois_lookup(domain):
    """
    Lightweight WHOIS via whois.iana.org JSON + rdap.org fallback.
    Does NOT require the `whois` binary.
    """
    result = {"domain": domain, "registrar": None, "registrant": None,
              "created": None, "expires": None, "updated": None,
              "nameservers": [], "status": [], "raw": None}

    # Try RDAP first (machine-readable)
    rdap_url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
    data, status = _json_get(rdap_url)
    if data and isinstance(data, dict):
        result["status"] = data.get("status", [])
        result["nameservers"] = [
            ns.get("ldhName", "").lower()
            for ns in data.get("nameservers", [])
            if ns.get("ldhName")
        ]
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")[:10]
            if action == "registration":
                result["created"] = date
            elif action == "expiration":
                result["expires"] = date
            elif action == "last changed":
                result["updated"] = date
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])
            name = None
            if isinstance(vcard, list) and len(vcard) > 1:
                for field in vcard[1]:
                    if isinstance(field, list) and field[0] == "fn":
                        name = field[3] if len(field) > 3 else None
            if "registrar" in roles and name:
                result["registrar"] = name
            if "registrant" in roles and name:
                result["registrant"] = name
        log(f"WHOIS (RDAP): {domain} — registrar={result['registrar']} created={result['created']}")
    else:
        # Fallback: plain whois via who.is API
        api_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={urllib.parse.quote(domain)}&outputFormat=json"
        body, _ = _get(api_url)
        if body:
            result["raw"] = body[:500]
        log(f"WHOIS: RDAP unavailable for {domain}, raw fallback used", "*")

    return result


# ─── DNS RECORDS ──────────────────────────────────────────────

_DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]


def dns_records(domain):
    """Query DNS records via Google's DoH JSON API (no dnspython needed)."""
    records = {}
    base = "https://dns.google/resolve"

    def query(rtype):
        url = f"{base}?name={urllib.parse.quote(domain)}&type={rtype}"
        data, _ = _json_get(url)
        if data and "Answer" in data:
            return rtype, [a.get("data", "") for a in data["Answer"]]
        return rtype, []

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(query, t): t for t in _DNS_TYPES}
        for fut in as_completed(futures):
            rtype, vals = fut.result()
            if vals:
                records[rtype] = vals

    log(f"DNS: {domain} — types found: {list(records.keys())}")
    return records


# ─── IP GEOLOCATION / ASN ─────────────────────────────────────

def ip_info(ip_or_domain):
    """Enrich an IP or domain via ip-api.com (free, no key needed)."""
    host = ip_or_domain
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_or_domain):
        try:
            host = socket.gethostbyname(ip_or_domain)
        except Exception:
            return {"error": f"Could not resolve {ip_or_domain}"}

    data, _ = _json_get(f"http://ip-api.com/json/{host}?fields=status,country,regionName,city,isp,org,as,query")
    if data and data.get("status") == "success":
        log(f"IP info: {host} — {data.get('org','')} / {data.get('city','')}, {data.get('country','')}")
        return data
    return {"ip": host, "error": "ip-api unavailable"}


# ─── CERTIFICATE TRANSPARENCY ─────────────────────────────────

def cert_transparency(domain):
    """Fetch subdomains and SANs from crt.sh."""
    subs = set()
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    data, _ = _json_get(url, timeout=20)
    if data and isinstance(data, list):
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub.endswith(f".{domain}") or sub == domain:
                    subs.add(sub)
        log(f"Cert transparency: {len(subs)} unique names for {domain}")
    else:
        log(f"Cert transparency: no data for {domain}", "-")
    return sorted(subs)


# ─── EMAIL HARVESTING ─────────────────────────────────────────

_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

def _scrape_emails_from_url(url):
    body, _ = _get(url)
    if body:
        return set(_EMAIL_RE.findall(body))
    return set()

def harvest_emails(domain):
    """
    Harvest emails from:
      1. The domain's homepage and common contact pages
      2. Hunter.io API (if HUNTER_API_KEY is set)
    """
    emails = set()

    # Scrape common pages
    pages = [
        f"https://{domain}",
        f"https://{domain}/contact",
        f"https://{domain}/about",
        f"https://{domain}/team",
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        for found in pool.map(_scrape_emails_from_url, pages):
            emails.update(found)

    # Filter to domain emails only
    domain_emails = {e for e in emails if domain in e.lower()}
    if domain_emails:
        log(f"Email harvest (web): {len(domain_emails)} emails found for {domain}")

    # Hunter.io
    if HUNTER_API_KEY:
        url = (f"https://api.hunter.io/v2/domain-search"
               f"?domain={urllib.parse.quote(domain)}&api_key={HUNTER_API_KEY}&limit=20")
        data, _ = _json_get(url)
        if data and "data" in data:
            for entry in data["data"].get("emails", []):
                em = entry.get("value", "")
                if em:
                    domain_emails.add(em)
            log(f"Hunter.io: {len(data['data'].get('emails', []))} emails")

    return sorted(domain_emails)


# ─── BREACH CHECK ─────────────────────────────────────────────

def breach_check(email_or_domain):
    """
    Check HaveIBeenPwned for breaches.
    Requires HIBP_API_KEY for per-account lookups.
    Domain-level breach list is public.
    """
    results = []
    if "@" in email_or_domain:
        if not HIBP_API_KEY:
            return [{"note": "Set HIBP_API_KEY for account breach lookup"}]
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email_or_domain)}?truncateResponse=false"
        data, status = _json_get(url, headers={"hibp-api-key": HIBP_API_KEY, "User-Agent": UA})
        if status == 200 and data:
            for breach in data:
                results.append({
                    "name": breach.get("Name"),
                    "date": breach.get("BreachDate"),
                    "data_classes": breach.get("DataClasses", []),
                    "pwn_count": breach.get("PwnCount"),
                })
    else:
        # Domain breach — public endpoint
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={urllib.parse.quote(email_or_domain)}"
        data, status = _json_get(url)
        if status == 200 and data:
            for breach in data:
                results.append({
                    "name": breach.get("Name"),
                    "date": breach.get("BreachDate"),
                    "data_classes": breach.get("DataClasses", []),
                    "pwn_count": breach.get("PwnCount"),
                })

    if results:
        log(f"HIBP: {len(results)} breaches found for {email_or_domain}", "!")
    else:
        log(f"HIBP: no known breaches for {email_or_domain}")
    return results


# ─── GITHUB DORKING ───────────────────────────────────────────

_GITHUB_DORKS = [
    'filename:.env "{domain}"',
    'filename:config.py "{domain}"',
    'filename:database.yml "{domain}"',
    'filename:secrets.yml "{domain}"',
    'filename:.npmrc "{domain}"',
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" token',
    '"{domain}" secret',
    '"{domain}" jdbc',
]

def github_dorks(domain):
    """Return GitHub search URLs for sensitive dork queries."""
    dorks = []
    for template in _GITHUB_DORKS:
        query = template.replace("{domain}", domain)
        encoded = urllib.parse.quote(query)
        dorks.append({
            "query": query,
            "url": f"https://github.com/search?q={encoded}&type=code",
        })
    log(f"GitHub dorks: {len(dorks)} queries generated for {domain}")
    return dorks


# ─── GOOGLE DORKS ─────────────────────────────────────────────

_GOOGLE_DORKS = [
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:xls OR filetype:xlsx',
    'site:{domain} inurl:admin',
    'site:{domain} inurl:login',
    'site:{domain} inurl:config',
    'site:{domain} intext:password',
    'site:{domain} intext:username',
    '"@{domain}" email',
    'site:{domain} intitle:index.of',
    'site:{domain} ext:log',
    'site:{domain} ext:sql',
    'site:{domain} ext:bak',
    'site:{domain} ext:env',
    'site:{domain} inurl:backup',
]

def google_dorks(domain):
    """Return Google search URLs for sensitive dork queries."""
    dorks = []
    for template in _GOOGLE_DORKS:
        query = template.replace("{domain}", domain)
        encoded = urllib.parse.quote(query)
        dorks.append({
            "query": query,
            "url": f"https://www.google.com/search?q={encoded}",
        })
    log(f"Google dorks: {len(dorks)} queries generated for {domain}")
    return dorks


# ─── SHODAN ───────────────────────────────────────────────────

def shodan_lookup(ip_or_domain):
    """Lookup a host on Shodan (requires SHODAN_API_KEY)."""
    if not SHODAN_API_KEY:
        return {"note": "Set SHODAN_API_KEY for Shodan lookups"}
    host = ip_or_domain
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_or_domain):
        try:
            host = socket.gethostbyname(ip_or_domain)
        except Exception:
            return {"error": f"Could not resolve {ip_or_domain}"}
    url = f"https://api.shodan.io/shodan/host/{host}?key={SHODAN_API_KEY}"
    data, status = _json_get(url)
    if data and "ports" in data:
        summary = {
            "ip": host,
            "ports": data.get("ports", []),
            "vulns": list(data.get("vulns", {}).keys()),
            "os": data.get("os"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "country": data.get("country_name"),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
        }
        log(f"Shodan: {host} — ports={summary['ports']} vulns={summary['vulns']}", "!")
        return summary
    return {"ip": host, "note": "No Shodan data or key invalid"}


# ─── SOCIAL MEDIA FOOTPRINT ───────────────────────────────────

_SOCIAL_TEMPLATES = [
    ("LinkedIn",  "https://www.linkedin.com/company/{handle}"),
    ("LinkedIn",  "https://www.linkedin.com/in/{handle}"),
    ("Twitter/X", "https://x.com/{handle}"),
    ("GitHub",    "https://github.com/{handle}"),
    ("Facebook",  "https://www.facebook.com/{handle}"),
    ("Instagram", "https://www.instagram.com/{handle}/"),
    ("YouTube",   "https://www.youtube.com/@{handle}"),
    ("Reddit",    "https://www.reddit.com/user/{handle}"),
]

def social_footprint(handle):
    """
    Check common social platforms for a username / company handle.
    Returns live URLs (HTTP 200 or 302 responses).
    """
    found = []

    def check(platform, url):
        body, status = _get(url, timeout=8)
        if status in (200, 301, 302) and body:
            # Simple sanity: page should mention the handle
            if handle.lower() in (body or "").lower():
                return {"platform": platform, "url": url, "status": status}
        return None

    checks = []
    for platform, tmpl in _SOCIAL_TEMPLATES:
        url = tmpl.replace("{handle}", urllib.parse.quote(handle))
        checks.append((platform, url))

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(check, p, u): (p, u) for p, u in checks}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)

    log(f"Social footprint: {len(found)} profiles found for '{handle}'")
    return found


# ─── FULL OSINT PIPELINE ──────────────────────────────────────

def run_osint(target, do_whois=True, do_dns=True, do_certs=True,
              do_emails=True, do_breach=False, do_github=True,
              do_google=True, do_shodan=True, do_social=True,
              do_ip=True):
    """
    Run the full OSINT pipeline for a domain/target.
    Returns a dict of all findings and saves a JSON + Markdown report.
    """
    domain = (target.lower()
              .replace("https://", "")
              .replace("http://", "")
              .split("/")[0])
    # Derive a handle from domain (strip TLD)
    handle = domain.split(".")[0]

    log(f"OSINT starting on: {domain}", "!")
    results = {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "whois": None,
        "dns": {},
        "cert_subdomains": [],
        "ip_info": {},
        "emails": [],
        "breaches": [],
        "github_dorks": [],
        "google_dorks": [],
        "shodan": {},
        "social": [],
    }

    if do_whois:
        log("Phase 1: WHOIS", "!")
        results["whois"] = whois_lookup(domain)

    if do_dns:
        log("Phase 2: DNS records", "!")
        results["dns"] = dns_records(domain)

    if do_ip:
        log("Phase 3: IP geolocation / ASN", "!")
        results["ip_info"] = ip_info(domain)

    if do_certs:
        log("Phase 4: Certificate Transparency", "!")
        results["cert_subdomains"] = cert_transparency(domain)

    if do_emails:
        log("Phase 5: Email harvesting", "!")
        results["emails"] = harvest_emails(domain)

    if do_breach and results["emails"]:
        log("Phase 6: Breach check (HIBP)", "!")
        results["breaches"] = breach_check(domain)

    if do_github:
        log("Phase 7: GitHub dorks", "!")
        results["github_dorks"] = github_dorks(domain)

    if do_google:
        log("Phase 8: Google dorks", "!")
        results["google_dorks"] = google_dorks(domain)

    if do_shodan:
        log("Phase 9: Shodan", "!")
        results["shodan"] = shodan_lookup(domain)

    if do_social:
        log("Phase 10: Social media footprint", "!")
        results["social"] = social_footprint(handle)

    # Save JSON report
    safe = re.sub(r"[^a-zA-Z0-9]", "_", domain)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(RESULTS_DIR, f"osint_{safe}_{ts}.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log(f"JSON report: {json_path}", "+")

    # Save Markdown report
    md_path = os.path.join(REPORTS_DIR, f"osint_{safe}_{ts}.md")
    with open(md_path, "w") as f:
        f.write(_markdown_report(results))
    log(f"Markdown report: {md_path}", "+")

    return results


# ─── MARKDOWN REPORT ──────────────────────────────────────────

def _markdown_report(r):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    domain = r["target"]
    lines = [
        f"# OSINT Report — {domain}",
        f"**Generated:** {now}",
        "",
    ]

    # WHOIS
    w = r.get("whois") or {}
    lines += [
        "## WHOIS",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Registrar | {w.get('registrar', '—')} |",
        f"| Registrant | {w.get('registrant', '—')} |",
        f"| Created | {w.get('created', '—')} |",
        f"| Expires | {w.get('expires', '—')} |",
        f"| Updated | {w.get('updated', '—')} |",
        f"| Nameservers | {', '.join(w.get('nameservers', [])) or '—'} |",
        "",
    ]

    # DNS
    dns = r.get("dns") or {}
    if dns:
        lines.append("## DNS Records")
        lines.append("| Type | Records |")
        lines.append("|------|---------|")
        for rtype, vals in sorted(dns.items()):
            lines.append(f"| {rtype} | {'; '.join(str(v)[:80] for v in vals[:5])} |")
        lines.append("")

    # IP info
    ip = r.get("ip_info") or {}
    if ip and "ip" in ip:
        lines += [
            "## IP / ASN",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| IP | {ip.get('query', ip.get('ip', '—'))} |",
            f"| ISP/Org | {ip.get('org', '—')} |",
            f"| ASN | {ip.get('as', '—')} |",
            f"| Location | {ip.get('city', '—')}, {ip.get('regionName', '—')}, {ip.get('country', '—')} |",
            "",
        ]

    # Cert transparency
    subs = r.get("cert_subdomains") or []
    if subs:
        lines += [
            "## Certificate Transparency Subdomains",
            f"Found **{len(subs)}** unique names.",
            "",
            "```",
        ] + subs[:50] + ["```", ""]

    # Emails
    emails = r.get("emails") or []
    if emails:
        lines += [
            "## Email Addresses",
            ", ".join(f"`{e}`" for e in emails[:30]),
            "",
        ]

    # Breaches
    breaches = r.get("breaches") or []
    if breaches and isinstance(breaches[0], dict) and "name" in breaches[0]:
        lines += [
            "## Breaches (HIBP)",
            "| Breach | Date | Data Classes | Count |",
            "|--------|------|--------------|-------|",
        ]
        for b in breaches[:20]:
            dc = ", ".join(b.get("data_classes", [])[:4])
            lines.append(f"| {b.get('name','?')} | {b.get('date','?')} | {dc} | {b.get('pwn_count','?')} |")
        lines.append("")

    # Social
    social = r.get("social") or []
    if social:
        lines += [
            "## Social Media Footprint",
            "| Platform | URL |",
            "|----------|-----|",
        ]
        for s in social:
            lines.append(f"| {s['platform']} | {s['url']} |")
        lines.append("")

    # Shodan
    shodan = r.get("shodan") or {}
    if shodan and "ports" in shodan:
        lines += [
            "## Shodan",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| IP | {shodan.get('ip', '—')} |",
            f"| Org | {shodan.get('org', '—')} |",
            f"| OS | {shodan.get('os', '—')} |",
            f"| Open Ports | {shodan.get('ports', [])} |",
            f"| CVEs | {', '.join(shodan.get('vulns', [])) or 'none'} |",
            "",
        ]

    # GitHub dorks
    gh = r.get("github_dorks") or []
    if gh:
        lines += [
            "## GitHub Dork Queries",
            "| Query | URL |",
            "|-------|-----|",
        ]
        for d in gh:
            lines.append(f"| `{d['query']}` | {d['url']} |")
        lines.append("")

    # Google dorks
    gg = r.get("google_dorks") or []
    if gg:
        lines += [
            "## Google Dork Queries",
            "| Query | URL |",
            "|-------|-----|",
        ]
        for d in gg:
            lines.append(f"| `{d['query']}` | {d['url']} |")
        lines.append("")

    lines += ["---", f"*Generated by bb_osint.py at {now}*"]
    return "\n".join(lines)


# ─── CONSOLE SUMMARY ──────────────────────────────────────────

def print_summary(results):
    d = results["target"]
    w = results.get("whois") or {}
    dns = results.get("dns") or {}
    subs = results.get("cert_subdomains") or []
    emails = results.get("emails") or []
    social = results.get("social") or []
    shodan = results.get("shodan") or {}
    breaches = results.get("breaches") or []

    print(f"\n\033[36m{'='*60}")
    print(f"  OSINT SUMMARY: {d}")
    print(f"{'='*60}\033[0m")
    print(f"  Registrar : {w.get('registrar', '—')}")
    print(f"  Created   : {w.get('created', '—')}  Expires: {w.get('expires', '—')}")
    print(f"  DNS types : {', '.join(sorted(dns.keys())) or '—'}")
    print(f"  Subdomains: {len(subs)} via crt.sh")
    print(f"  Emails    : {len(emails)} found")
    print(f"  Breaches  : {len(breaches)}")
    print(f"  Social    : {len(social)} profiles")
    if shodan.get("ports"):
        print(f"  Shodan    : ports={shodan['ports']} vulns={shodan.get('vulns', [])}")
    gh = results.get("github_dorks") or []
    gg = results.get("google_dorks") or []
    print(f"  Dorks     : {len(gh)} GitHub, {len(gg)} Google")
    print()


# ─── MAIN ─────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python bb_osint.py <domain> [options]")
        print("Options:")
        print("  --all          Run all modules (default)")
        print("  --whois        WHOIS lookup only")
        print("  --dns          DNS records only")
        print("  --emails       Email harvesting only")
        print("  --breach       HIBP breach check (requires HIBP_API_KEY)")
        print("  --shodan       Shodan lookup (requires SHODAN_API_KEY)")
        print("  --social       Social media footprint")
        print("  --github       GitHub dork URLs")
        print("  --google       Google dork URLs")
        sys.exit(1)

    target = sys.argv[1]
    args = sys.argv[2:]

    # Parse flags
    do_all = not args or "--all" in args
    results = run_osint(
        target,
        do_whois="--whois" in args or do_all,
        do_dns="--dns" in args or do_all,
        do_certs="--certs" in args or do_all,
        do_emails="--emails" in args or do_all,
        do_breach="--breach" in args,
        do_github="--github" in args or do_all,
        do_google="--google" in args or do_all,
        do_shodan="--shodan" in args or do_all,
        do_social="--social" in args or do_all,
        do_ip=do_all,
    )
    print_summary(results)
