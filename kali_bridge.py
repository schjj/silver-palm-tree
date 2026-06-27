import os, io, json, time
from datetime import datetime

KALI_HOST = "127.0.0.1"
KALI_PORT = 4444
KALI_USER = "kali"
KALI_PASS = "kali"

class KaliSSH:
    def __init__(self, host=KALI_HOST, port=KALI_PORT, user=KALI_USER, password=KALI_PASS):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.client = None
        self.sftp = None
        self._connect()

    def _connect(self):
        import paramiko
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            self.host, port=self.port,
            username=self.user, password=self.password,
            timeout=15, banner_timeout=30,
            allow_agent=False, look_for_keys=False
        )
        self.sftp = self.client.open_sftp()

    def run(self, command, timeout=60):
        """Run a command on Kali and return stdout, stderr, exit_code"""
        if not self.client:
            self._connect()
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            return out, err, exit_code
        except Exception as e:
            return "", str(e), -1

    def run_sudo(self, command, timeout=60):
        return self.run(f"echo {self.password} | sudo -S {command}", timeout)

    def put(self, local_path, remote_path):
        """Upload a file to Kali"""
        self.sftp.put(local_path, remote_path)

    def get(self, remote_path, local_path):
        """Download a file from Kali"""
        self.sftp.get(remote_path, local_path)

    def write_file(self, remote_path, content):
        """Write string content to a file on Kali"""
        with self.sftp.open(remote_path, "w") as f:
            f.write(content)

    def read_file(self, remote_path):
        """Read a file from Kali"""
        with self.sftp.open(remote_path, "r") as f:
            return f.read()

    def list_dir(self, remote_path):
        return self.sftp.listdir(remote_path)

    def close(self):
        if self.sftp:
            self.sftp.close()
        if self.client:
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

# ─── TOOL WRAPPERS ───────────────────────────────────────────

def nmap_syn(target, ports="1-1000"):
    """Full SYN scan with OS detection via Kali (requires root)"""
    with KaliSSH() as k:
        out, err, code = k.run_sudo(f"nmap -sS -Pn -p {ports} -O --osscan-guess -oG - {target} 2>&1")
        return {"output": out, "error": err, "exit_code": code}

def nmap_all(target):
    """Full aggressive scan"""
    with KaliSSH() as k:
        out, err, code = k.run_sudo(f"nmap -sS -sV -Pn -A -T4 -p- --open {target} 2>&1")
        return {"output": out, "error": err, "exit_code": code}

def tshark_live(interface="eth0", count=10, filter=""):
    """Live packet capture via Kali"""
    with KaliSSH() as k:
        cmd = f"tshark -i {interface} -c {count}"
        if filter:
            cmd += f' -f "{filter}"'
        out, err, code = k.run_sudo(cmd, timeout=120)
        return {"output": out, "error": err, "exit_code": code}

def subfinder(domain):
    """Run subfinder on Kali"""
    with KaliSSH() as k:
        out, err, code = k.run(f"subfinder -d {domain} -silent 2>&1")
        subs = [l.strip() for l in out.split("\n") if l.strip()]
        return {"output": out, "error": err, "exit_code": code, "subdomains": subs}

def httpx(urls, status_code=False):
    """Run httpx probe on Kali"""
    with KaliSSH() as k:
        urls_str = "\n".join(urls) if isinstance(urls, list) else urls
        cmd = f"echo '{urls_str}' | httpx -silent {'-sc' if status_code else ''} 2>&1"
        out, err, code = k.run(cmd)
        return {"output": out, "error": err, "exit_code": code}

def nuclei(target, severity="medium"):
    """Run nuclei vulnerability scanner on Kali"""
    with KaliSSH() as k:
        out, err, code = k.run(f"nuclei -u {target} -severity {severity} -silent 2>&1")
        return {"output": out, "error": err, "exit_code": code}

def waybackurls(domain):
    """Run waybackurls on Kali"""
    with KaliSSH() as k:
        out, err, code = k.run(f"echo {domain} | waybackurls 2>&1")
        urls = [l.strip() for l in out.split("\n") if l.strip()]
        return {"output": out, "error": err, "exit_code": code, "urls": urls}

def gau(domain):
    """Run gau (Get All URLs) on Kali"""
    with KaliSSH() as k:
        out, err, code = k.run(f"gau {domain} 2>&1")
        urls = [l.strip() for l in out.split("\n") if l.strip()]
        return {"output": out, "error": err, "exit_code": code, "urls": urls}

def katana(target):
    """Run katana crawler on Kali"""
    with KaliSSH() as k:
        out, err, code = k.run(f"katana -u {target} -silent 2>&1")
        urls = [l.strip() for l in out.split("\n") if l.strip()]
        return {"output": out, "error": err, "exit_code": code, "urls": urls}

def whatweb(target):
    """Run whatweb tech detection on Kali"""
    with KaliSSH() as k:
        out, err, code = k.run(f"whatweb -a 3 {target} 2>&1")
        return {"output": out, "error": err, "exit_code": code}

def gobuster_dir(target, wordlist="/usr/share/wordlists/dirb/common.txt"):
    """Run gobuster directory enumeration on Kali"""
    with KaliSSH() as k:
        out, err, code = k.run(f"gobuster dir -u {target} -w {wordlist} -t 50 -q 2>&1")
        return {"output": out, "error": err, "exit_code": code}

def sqlmap(target):
    """Run sqlmap on Kali"""
    with KaliSSH() as k:
        out, err, code = k.run(f"sqlmap -u {target} --batch --random-agent --output-dir=/tmp/sqlmap_out 2>&1")
        return {"output": out, "error": err, "exit_code": code}

def hydra_ssh(target_user, target_host, wordlist="/usr/share/wordlists/rockyou.txt.gz"):
    """Run hydra SSH brute force on Kali"""
    with KaliSSH() as k:
        out, err, code = k.run(f"hydra -l {target_user} -P {wordlist} ssh://{target_host} -t 4 2>&1")
        return {"output": out, "error": err, "exit_code": code}

def nikto(target):
    """Run nikto web scanner on Kali"""
    with KaliSSH() as k:
        out, err, code = k.run(f"nikto -h {target} -ssl -Format json 2>&1")
        return {"output": out, "error": err, "exit_code": code}

def install_tools():
    """Install common bug bounty tools on Kali"""
    with KaliSSH() as k:
        install_cmd = """
apt-get update -qq && apt-get install -y -qq \
    subfinder httpx nuclei waybackurls gau katana whatweb gobuster \
    dirsearch ffuf massdns dnsx naabu 2>&1 | tail -5"""
        out, err, code = k.run_sudo(install_cmd, timeout=300)
        return {"output": out, "error": err, "exit_code": code}

def system_info():
    """Get Kali system info"""
    with KaliSSH() as k:
        out1, _, _ = k.run("uname -a")
        out2, _, _ = k.run("cat /etc/os-release | head -3")
        out3, _, _ = k.run("ip addr show | grep 'inet '")
        return {
            "kernel": out1.strip(),
            "os": out2.strip(),
            "network": out3.strip()
        }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python kali_bridge.py <command> [args...]")
        print("Commands: info, nmap <target>, install, whoami")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "info":
        info = system_info()
        for k, v in info.items():
            print(f"\033[36m{k}:\033[0m {v}")
    elif cmd == "nmap":
        target = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        r = nmap_syn(target)
        print(r["output"])
    elif cmd == "tshark":
        r = tshark_live(count=10)
        print(r["output"])
    elif cmd == "install":
        r = install_tools()
        print(r["output"])
    elif cmd == "whoami":
        with KaliSSH() as k:
            out, _, _ = k.run("whoami; hostname; pwd")
            print(out)
    elif cmd == "exec":
        cmd_str = " ".join(sys.argv[2:])
        with KaliSSH() as k:
            out, err, code = k.run(cmd_str)
            print(out)
            if err:
                print(f"\033[31m{err}\033[0m")
            print(f"\033[33mExit: {code}\033[0m")
    else:
        print(f"Unknown command: {cmd}")
