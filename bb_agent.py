import json, os, sys, subprocess, webbrowser, time, re
from datetime import datetime

BB_DIR = os.path.expanduser("~\\Desktop\\BugBounty")
SCRIPTS = os.path.join(BB_DIR, "scripts")
TARGETS_DIR = os.path.join(BB_DIR, "targets")
REPORTS_DIR = os.path.join(BB_DIR, "reports")
PROGRAMS_DIR = os.path.join(BB_DIR, "programs")
PORTSWIGGER_FILE = os.path.join(BB_DIR, "portswigger_labs.json")
PY = r"C:\Users\salva\AppData\Local\Programs\Python\Python312\python.exe"

def clr(code, text): return f"\033[{code}m{text}\033[0m"
def G(text): return clr("32", text)
def Y(text): return clr("33", text)
def R(text): return clr("31", text)
def B(text): return clr("36", text)
def M(text): return clr("35", text)

gk = os.environ.get("GROQ_API_KEY", "")
gemini_key = os.environ.get("GEMINI_API_KEY", "")

portswigger_labs = {
    "sql": {"name": "SQL Injection", "total": 30, "done": 0, "labs": []},
    "xss": {"name": "Cross-Site Scripting", "total": 22, "done": 0, "labs": []},
    "csrf": {"name": "CSRF", "total": 14, "done": 0, "labs": []},
    "ssti": {"name": "SSTI", "total": 6, "done": 0, "labs": []},
    "lfi": {"name": "Path Traversal", "total": 8, "done": 0, "labs": []},
    "auth": {"name": "Authentication", "total": 12, "done": 0, "labs": []},
    "ssrf": {"name": "SSRF", "total": 6, "done": 0, "labs": []},
    "xxe": {"name": "XXE", "total": 6, "done": 0, "labs": []},
    "deser": {"name": "Deserialization", "total": 8, "done": 0, "labs": []},
    "race": {"name": "Race Conditions", "total": 4, "done": 0, "labs": []},
    "graphql": {"name": "GraphQL", "total": 6, "done": 0, "labs": []},
    "logic": {"name": "Logic Flaws", "total": 6, "done": 0, "labs": []},
    "dom": {"name": "DOM-Based", "total": 8, "done": 0, "labs": []},
    "oauth": {"name": "OAuth", "total": 8, "done": 0, "labs": []},
    "jwt": {"name": "JWT", "total": 6, "done": 0, "labs": []},
    "cors": {"name": "CORS", "total": 4, "done": 0, "labs": []},
    "http": {"name": "HTTP Request Smuggling", "total": 10, "done": 0, "labs": []},
    "click": {"name": "Clickjacking", "total": 4, "done": 0, "labs": []},
    "websocket": {"name": "WebSockets", "total": 4, "done": 0, "labs": []},
    "prototype": {"name": "Prototype Pollution", "total": 4, "done": 0, "labs": []},
}

SYSTEM_PROMPT = """You are an elite bug bounty AI agent. You help the user hunt vulnerabilities,
analyze targets, and learn bug bounty skills. You have direct access to their tools.

You track the user's PortSwigger Web Security Academy labs.
When they say they finished a lab, ask which category and record it.

BUG BOUNTY METHODOLOGY:
1. RECON: subdomains -> probes -> tech detection -> URL gathering
2. ANALYSIS: params -> JS files -> endpoints -> attack surface
3. ATTACK: SQLi -> XSS -> SSTI -> LFI -> SSRF -> auth bugs
4. EXPLOIT: verify -> escalate -> document -> report

AVAILABLE COMMANDS (prefix with !):
  !recon <domain>         Full recon pipeline (subs, ports, tech, URLs)
  !scan <url>             Vulnerability scan (XSS, SQLi, SSTI, LFI, Open Redirect)
  !js <url>               JS secret scanner (API keys, tokens, endpoints)
  !takeover <subdomain>   Subdomain takeover check (20+ cloud services)
  !tech <url>             Web technology detection
  !kali <tool> <args>     Run tool on Kali VM (nmap, nuclei, sqlmap, etc.)
  !hackerone              Open HackerOne in browser
  !programs               List HackerOne program configs
  !lab <category> <name>  Mark a PortSwigger lab as done
  !labs                   Show PortSwigger lab progress
  !targets                List recon target folders
  !open <url>             Open URL in browser
  !siem                   Run SIEM: ingest findings, show alerts & dashboard
  !help                   Show command reference
  exit                    Quit the agent

Keep responses concise and actionable. Suggest next recon/attack steps."""

def load_data():
    global portswigger_labs
    if os.path.exists(PORTSWIGGER_FILE):
        try:
            with open(PORTSWIGGER_FILE) as f: portswigger_labs = json.load(f)
        except: pass

def save_portswigger():
    with open(PORTSWIGGER_FILE, 'w') as f: json.dump(portswigger_labs, f, indent=2)

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(B("  ╔════════════════════════════════════════════╗"))
    print(B("  ║     BUG BOUNTY AI AGENT v1.0              ║"))
    print(B("  ║     AI Hunting + PortSwigger Tracker      ║"))
    print(B("  ╚════════════════════════════════════════════╝"))
    completed = sum(v["done"] for v in portswigger_labs.values())
    total = sum(v["total"] for v in portswigger_labs.values())
    print(f"  Portfolio: {G(str(completed))}/{total} labs | {len([d for d in os.listdir(TARGETS_DIR) if os.path.isdir(os.path.join(TARGETS_DIR, d))])} targets")

def run_script(script, args):
    cmd = [PY, os.path.join(SCRIPTS, script)] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout[-1500:] if result.stdout else "(no output)"
    except subprocess.TimeoutExpired:
        return "(timed out)"
    except Exception as e:
        return f"(error: {e})"

def list_targets():
    dirs = [d for d in os.listdir(TARGETS_DIR) if os.path.isdir(os.path.join(TARGETS_DIR, d))]
    if not dirs: return "No targets yet. Run !recon <domain>"
    return "\n".join(f"  {G(d)}" for d in dirs)

def list_programs():
    files = [f for f in os.listdir(PROGRAMS_DIR) if f.endswith('.json')]
    if not files: return "No programs yet. Use HackerOne toolkit in bugbounty.bat"
    return "\n".join(f"  {G(f.replace('.json',''))}" for f in files)

def lab_progress():
    completed = sum(v["done"] for v in portswigger_labs.values())
    total = sum(v["total"] for v in portswigger_labs.values())
    pct = (completed / total * 100) if total > 0 else 0
    lines = [f"PortSwigger Academy: {G(str(completed))}/{total} ({pct:.0f}%)\n"]
    for k, v in portswigger_labs.items():
        bar = "█" * v["done"] + "░" * (v["total"] - v["done"])
        lines.append(f"  {v['name']:30s} {G(str(v['done']))}/{v['total']} {bar}")
    return "\n".join(lines)

def find_category(text):
    text = text.lower().strip()
    for key, cat in portswigger_labs.items():
        if key in text: return key, cat["name"]
        for w in cat["name"].lower().split():
            if w in text and len(w) > 2: return key, cat["name"]
    return None, None

def call_llm(messages):
    import urllib.request as ureq

    # --- Gemini (primary) ---
    if gemini_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=gemini_key)
            system = next((m["content"] for m in messages if m["role"] == "system"), None)
            model = genai.GenerativeModel(model_name="gemini-1.5-flash", system_instruction=system)
            history = [
                {"role": "user" if m["role"] == "user" else "model", "parts": [m["content"]]}
                for m in messages if m["role"] != "system"
            ]
            if not history:
                return "(no message to send)"
            chat = model.start_chat(history=history[:-1])
            return chat.send_message(history[-1]["parts"][0]).text
        except Exception:
            pass  # fall through to Groq

    # --- Groq (fallback) ---
    if gk:
        try:
            data = json.dumps({
                "model": "llama-3.3-70b-versatile",
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": 800
            }).encode()
            req = ureq.Request(
                "https://api.groq.com/openai/v1/chat/completions",
                data=data,
                headers={"Authorization": "Bearer " + gk, "Content-Type": "application/json"}
            )
            with ureq.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())["choices"][0]["message"]["content"]
        except Exception:
            pass

    # --- Ollama (local fallback) ---
    try:
        data = json.dumps({"model": "qwen2.5:1.5b", "messages": messages, "stream": False}).encode()
        req = ureq.Request("http://localhost:11434/api/chat", data=data, headers={"Content-Type": "application/json"})
        with ureq.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())["message"]["content"]
    except Exception as e:
        return f"(LLM unavailable: {e})"

def handle_command(user_input):
    parts = user_input[1:].strip().split(None, 1)
    if not parts: return "Enter a command"
    cmd = parts[0].lower()
    args = parts[1].split() if len(parts) > 1 else []

    cmds = {
        "help": "Commands: !recon <domain> | !scan <url> | !js <url> | !takeover <subdomain> | !tech <url> | !kali <tool> | !hackerone | !programs | !lab <cat> <name> | !labs | !targets | !open <url>",
        "targets": list_targets(),
        "programs": list_programs(),
        "labs": lab_progress(),
        "hackerone": (webbrowser.open("https://hackerone.com"), "Opened HackerOne")[1],
    }

    if cmd in cmds:
        return cmds[cmd]

    if cmd == "recon" and args:
        print(Y(f"\nRunning recon on {args[0]}..."))
        out = run_script("bb_recon.py", args)
        return f"Recon done. Check targets/{args[0].replace('.','_')}/\n{out[:500]}"

    if cmd == "scan" and args:
        print(Y(f"\nScanning {args[0]} for vulns..."))
        out = run_script("bb_vulnscan.py", args)
        return f"Scan complete.\n{out[:500]}"

    if cmd == "js" and args:
        print(Y(f"\nScanning JS secrets in {args[0]}..."))
        out = run_script("bb_jsleak.py", args)
        return f"JS scan complete.\n{out[:500]}"

    if cmd == "takeover" and args:
        print(Y(f"\nChecking {args[0]} for takeover..."))
        out = run_script("bb_takeover.py", args)
        return f"Takeover check done.\n{out[:500]}"

    if cmd == "tech" and args:
        print(Y(f"\nDetecting tech for {args[0]}..."))
        out = run_script("bb_recon.py", [args[0], "--tech-only"])
        return f"Tech detection:\n{out[:500]}"

    if cmd == "kali" and args:
        tool = " ".join(args)
        print(Y(f"\nRunning on Kali: {tool}"))
        out = run_script("kali_bridge.py", args)
        return f"Kali output:\n{out[:1000]}"

    if cmd == "open" and args:
        webbrowser.open(args[0])
        return f"Opened {args[0]}"

    if cmd == "siem":
        try:
            import bb_siem
            events, alerts = bb_siem.run_siem(verbose=False)
            return bb_siem.dashboard(events, alerts)
        except Exception as e:
            return f"SIEM error: {e}"

    if cmd == "lab" and args:
        cat = args[0].lower()
        name = " ".join(args[1:]) if len(args) > 1 else args[0]
        key, cat_name = find_category(cat)
        if not key:
            cats = "\n".join(f"  {k:12s} {v['name']}" for k, v in portswigger_labs.items())
            return f"Unknown category. Use one:\n{cats}"
        portswigger_labs[key]["done"] = min(portswigger_labs[key]["done"] + 1, portswigger_labs[key]["total"])
        portswigger_labs[key]["labs"].append({"name": name, "date": datetime.now().isoformat()})
        save_portswigger()
        v = portswigger_labs[key]
        return G(f"Marked '{name}' done in {cat_name}! ({v['done']}/{v['total']})")

    return f"Unknown command !{cmd}. Try !help"

def main():
    load_data()
    print_banner()

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    print(G("  AI ready. Ask anything or use !commands.\n"))

    while True:
        try:
            user = input(B("bb> ")).strip()
        except (EOFError, KeyboardInterrupt):
            print(Y("\nHappy hunting!"))
            break

        if not user: continue
        if user.lower() in ("exit", "quit", "q"):
            print(Y("Happy hunting!"))
            save_portswigger()
            break

        if user.startswith("!"):
            print()
            result = handle_command(user)
            if result: print(result)
            print()
            continue

        messages.append({"role": "user", "content": user})
        print(f"\n{G()}Agent:{clr('0','')} ", end="", flush=True)
        response = call_llm(messages)
        print(response)
        messages.append({"role": "assistant", "content": response})
        print()

if __name__ == "__main__":
    main()
