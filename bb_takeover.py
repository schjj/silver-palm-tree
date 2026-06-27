import json, os, sys, socket, urllib.request, urllib.error, dns.resolver, ssl as ssl_mod
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

BB_DIR = os.path.expanduser("~\\Desktop\\BugBounty")
SSL_CTX = ssl_mod.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl_mod.CERT_NONE

# Known fingerprints for cloud services that can be taken over
CLOUD_TK = [
    {"service": "AWS S3", "cname": ["s3.amazonaws.com", "s3-website"], "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"]},
    {"service": "AWS CloudFront", "cname": ["cloudfront.net"], "fingerprint": ["x-amz-cf-id", "error: 403", "CloudFront", "not exist"]},
    {"service": "Azure CDN", "cname": ["azureedge.net", "azurefd.net"], "fingerprint": ["404 Not Found", "no such host"]},
    {"service": "Azure VM", "cname": ["cloudapp.net"], "fingerprint": ["404 Not Found"]},
    {"service": "GitHub Pages", "cname": ["github.io"], "fingerprint": ["There isn't a GitHub Pages site"]},
    {"service": "Heroku", "cname": ["herokudns.com", "herokuapp.com"], "fingerprint": ["no such app", "There's nothing here"]},
    {"service": "Shopify", "cname": ["myshopify.com", "shopify.com"], "fingerprint": ["Sorry, this shop is currently unavailable"]},
    {"service": "Squarespace", "cname": ["squarespace.com"], "fingerprint": ["No Such Site", "Not Found"]},
    {"service": "Tumblr", "cname": ["tumblr.com"], "fingerprint": ["There's nothing here"]},
    {"service": "WordPress.com", "cname": ["wordpress.com"], "fingerprint": ["Do you want to register"]},
    {"service": "Cargo Collective", "cname": ["cargocollective.com"], "fingerprint": ["404"]},
    {"service": "Fastly", "cname": ["fastly.net", "fastlylb.net"], "fingerprint": ["Fastly error: unknown domain"]},
    {"service": "Pantheon", "cname": ["pantheonsite.io"], "fingerprint": ["The gods are angry"]},
    {"service": "Surge.sh", "cname": ["surge.sh"], "fingerprint": ["project not found"]},
    {"service": "Bitbucket", "cname": ["bitbucket.io"], "fingerprint": ["Repository not found"]},
    {"service": "Campaign Monitor", "cname": ["createsend.com"], "fingerprint": ["Trying to access"]},
    {"service": "Unbounce", "cname": ["unbouncepages.com"], "fingerprint": ["The page you requested was not found"]},
    {"service": "Intercom", "cname": ["custom.intercom.help"], "fingerprint": ["This page is reserved for"]},
    {"service": "Netlify", "cname": ["netlify.app", "netlify.com"], "fingerprint": ["Not Found", "Netlify"]},
    {"service": "Vercel", "cname": ["vercel.app", "now.sh"], "fingerprint": ["The deployment could not be found"]},
    {"service": "Render", "cname": ["onrender.com"], "fingerprint": ["Render"]},
    {"service": "Fly.io", "cname": ["fly.dev"], "fingerprint": ["404 Not Found"]},
]

def log(msg, status="+"):
    ts = datetime.now().strftime("%H:%M:%S")
    color = {"+": "32", "-": "31", "*": "33", "!": "36"}.get(status, "0")
    print(f"\033[{color}m[{status}]\033[0m {msg}")

def check_cname(hostname):
    try:
        answers = dns.resolver.resolve(hostname, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).rstrip('.')
            return cname.lower()
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        log(f"NXDOMAIN for {hostname} - already available for registration!", "!")
        return None
    except Exception:
        pass

    # Try to resolve A/AAAA
    try:
        dns.resolver.resolve(hostname, 'A')
    except dns.resolver.NXDOMAIN:
        return None
    except:
        pass
    return None

def check_fingerprint(hostname, service_name):
    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{hostname}"
            r = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            resp = urllib.request.urlopen(r, timeout=10, context=SSL_CTX)
            body = resp.read().decode("utf-8", errors="ignore")
            status = resp.status
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            status = e.code
        except Exception:
            continue

        for fp in CLOUD_TK:
            if fp["service"] == service_name:
                for indicator in fp["fingerprint"]:
                    if indicator.lower() in body.lower():
                        return {"cname": hostname, "service": service_name, "status": status, "evidence": indicator}
    return None

def check_takeover(subdomain):
    cname = check_cname(subdomain)
    if cname is None:
        return None

    log(f"{subdomain} -> CNAME: {cname}")

    for tk_info in CLOUD_TK:
        for suffix in tk_info["cname"]:
            if suffix in cname:
                result = check_fingerprint(subdomain, tk_info["service"])
                if result:
                    log(f"\033[31m[!] TAKEOVER: {subdomain} -> {tk_info['service']}\033[0m", "!")
                    return result
    return {"cname": cname, "service": "unknown", "note": "CNAME to unknown service, manual check needed"}

def run(subdomains_file=None):
    if subdomains_file:
        with open(subdomains_file) as f:
            subs = [l.strip() for l in f if l.strip()]
    else:
        subs = [l.strip() for l in sys.stdin if l.strip()]

    if not subs:
        print("Provide subdomains via file or stdin")
        return

    log(f"Checking {len(subs)} subdomains for takeover...", "!")
    results = []
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(check_takeover, sub): sub for sub in subs}
        for f in as_completed(futures):
            try:
                r = f.result()
                if r:
                    results.append(r)
            except:
                pass

    output = os.path.join(BB_DIR, "reports", f"takeover_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(output, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log(f"Report: {output}", "!")
    log(f"Potential takeovers: {len(results)}", "!")

    for r in results:
        print(f"  \033[31m[!] {r.get('service','?')}\033[0m - {r.get('cname','?')}")

    return results

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        run()
