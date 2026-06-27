import json, os, re, sys, urllib.request, urllib.parse, urllib.error, ssl as ssl_mod
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

BB_DIR = os.path.expanduser("~\\Desktop\\BugBounty")
SSL_CTX = ssl_mod.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl_mod.CERT_NONE

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'(?i)aws.?secret.?access.?key["\']?\s*[:=]\s*["\'][A-Za-z0-9\/+=]{40}["\']', 'AWS Secret Key'),
    (r'(?i)sk_live_[0-9a-z]{32}', 'Stripe Live Key'),
    (r'(?i)pk_live_[0-9a-z]{32}', 'Stripe Live Publishable'),
    (r'(?i)sk_test_[0-9a-z]{32}', 'Stripe Test Key'),
    (r'(?i)pk_test_[0-9a-z]{32}', 'Stripe Test Publishable'),
    (r'(?i)github_token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_]{40}["\']', 'GitHub Token'),
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Token'),
    (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
    (r'ghu_[a-zA-Z0-9]{36}', 'GitHub User Token'),
    (r'(?i)api.?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'API Key'),
    (r'(?i)secret.?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Secret Key'),
    (r'(?i)password["\']?\s*[:=]\s*["\'][^\s"]+["\']', 'Password'),
    (r'(?i)token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']', 'Auth Token'),
    (r'(?i)jwt.?secret["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']', 'JWT Secret'),
    (r'(?i)mongodb(?:\+srv)?:\/\/[^\s"\']+', 'MongoDB URI'),
    (r'(?i)postgresql:\/\/[^\s"\']+', 'PostgreSQL URI'),
    (r'(?i)mysql:\/\/[^\s"\']+', 'MySQL URI'),
    (r'(?i)redis:\/\/[^\s"\']+', 'Redis URI'),
    (r'(?i)slack.?token["\']?\s*[:=]\s*["\']xox[baprs]-[a-zA-Z0-9\-]+', 'Slack Token'),
    (r'(?i)facebook.?token["\']?\s*[:=]\s*["\']EAAC[^\s"]+', 'Facebook Token'),
    (r'(?i)google.?api.?key["\']?\s*[:=]\s*["\']AIza[0-9A-Za-z\-_]{35}["\']', 'Google API Key'),
    (r'(?i)firebase.?url["\']?\s*[:=]\s*["\'][^\s"\']+', 'Firebase URL'),
    (r'(?i)db_password["\']?\s*[:=]\s*["\'][^\s"\']+["\']', 'DB Password'),
    (r'(?i)s3.?bucket["\']?\s*[:=]\s*["\'][a-z0-9\-\.]+["\']', 'S3 Bucket'),
    (r'(?i)s3.?region["\']?\s*[:=]\s*["\'][a-z\-0-9]+["\']', 'S3 Region'),
    (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key'),
    (r'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key'),
    (r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key'),
    (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Private Key'),
]

ENDPOINT_PATTERNS = [
    (r'https?://[a-zA-Z0-9\.\-]+\.(com|io|net|org|dev|app|api)[^\s"\'<>]*', 'External URL'),
    (r'/api/v[0-9]+/[a-zA-Z0-9_\-/]+', 'API Endpoint'),
    (r'https?://[a-zA-Z0-9\-\.]*amazonaws\.com[^\s"\'<>]*', 'AWS Endpoint'),
    (r'https?://[a-zA-Z0-9\-\.]*cloudfront\.net[^\s"\'<>]*', 'CloudFront'),
    (r'(?i)(graphql|gql)', 'GraphQL'),
]

def log(msg, status="+"):
    ts = datetime.now().strftime("%H:%M:%S")
    color = {"+": "32", "-": "31", "*": "33", "!": "36"}.get(status, "0")
    print(f"\033[{color}m[{status}]\033[0m {msg}")

def fetch_js(url):
    try:
        r = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        resp = urllib.request.urlopen(r, timeout=10, context=SSL_CTX)
        return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return None

def extract_js_urls(html_url):
    """Extract JS URLs from a page"""
    js_urls = set()
    try:
        r = urllib.request.Request(html_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        resp = urllib.request.urlopen(r, timeout=10, context=SSL_CTX)
        body = resp.read().decode("utf-8", errors="ignore")
        # src="..." or src='...'
        for m in re.finditer(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', body, re.IGNORECASE):
            js = m.group(1)
            if js.startswith("//"):
                js = "https:" + js
            elif js.startswith("/"):
                parsed = urllib.parse.urlparse(html_url)
                js = f"{parsed.scheme}://{parsed.netloc}{js}"
            elif not js.startswith("http"):
                parsed = urllib.parse.urlparse(html_url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                base_path = os.path.dirname(parsed.path) if '/' in parsed.path else ''
                js = base + base_path + '/' + js
            js_urls.add(js)
        # Also inline scripts
        for m in re.finditer(r'<script[^>]*>([\s\S]*?)</script>', body, re.IGNORECASE):
            yield ("inline", m.group(1))
    except Exception as e:
        log(f"Error extracting JS from {html_url}: {e}", "-")
    for js in sorted(js_urls):
        yield ("url", js)

def scan_js_content(content, source):
    findings = []
    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            match = m.group()[:80]
            findings.append({
                "source": source,
                "type": label,
                "match": match,
                "line_context": content[max(0, m.start()-50):m.end()+50].replace('\n', ' ')
            })
    return findings

def scan_js_url(js_url):
    log(f"Scanning JS: {js_url}")
    content = fetch_js(js_url)
    if not content:
        return []
    findings = scan_js_content(content, js_url)

    # Check for API endpoints in JS
    for pattern, label in ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, content):
            findings.append({
                "source": js_url,
                "type": f"Endpoint: {label}",
                "match": m.group()[:100]
            })

    if findings:
        log(f"\033[31m[!] {len(findings)} findings in {os.path.basename(js_url)}\033[0m")
    return findings

def scan_domain(domain_or_url):
    if not domain_or_url.startswith("http"):
        domain_or_url = "https://" + domain_or_url
    domain_or_url = domain_or_url.rstrip("/")

    log(f"Scanning: {domain_or_url}", "!")
    all_findings = []

    # Extract JS from HTML
    for src_type, content in extract_js_urls(domain_or_url):
        if src_type == "url":
            findings = scan_js_url(content)
            all_findings.extend(findings)
        elif src_type == "inline":
            findings = scan_js_content(content, f"{domain_or_url} (inline script)")
            all_findings.extend(findings)

    # Check source map references
    try:
        r = urllib.request.Request(domain_or_url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(r, timeout=10, context=SSL_CTX)
        body = resp.read().decode("utf-8", errors="ignore")
        for m in re.finditer(r'//# sourceMappingURL=([^\s]+)', body):
            map_url = urllib.parse.urljoin(domain_or_url, m.group(1))
            log(f"Source map found: {map_url}", "*")
    except:
        pass

    results = {"domain": domain_or_url, "findings": all_findings, "count": len(all_findings)}
    output = os.path.join(BB_DIR, "reports", f"jsleak_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(output, "w") as f:
        json.dump(results, f, indent=2, default=str)

    log(f"Report saved: {output}", "!")
    if all_findings:
        log("=== FINDINGS ===", "!")
        for f in all_findings:
            print(f"  \033[31m[{f['type']}]\033[0m {f['match'][:60]}")
    else:
        log("No secrets found (good!)")
    return results

def scan_urls_file(file_path):
    with open(file_path) as f:
        urls = [u.strip() for u in f if u.strip() and not u.startswith("#")]
    all_results = {"scanned": [], "total_findings": 0}
    for url in urls:
        res = scan_domain(url)
        all_results["scanned"].append(res)
        all_results["total_findings"] += res["count"]
    output = os.path.join(BB_DIR, "reports", f"jsleak_bulk_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(output, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    log(f"\nTotal findings across {len(urls)} pages: {all_results['total_findings']}", "!")
    return all_results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python bb_jsleak.py <url>")
        print("  python bb_jsleak.py urls_file.txt")
        sys.exit(1)
    target = sys.argv[1]
    if os.path.isfile(target):
        scan_urls_file(target)
    else:
        scan_domain(target)
