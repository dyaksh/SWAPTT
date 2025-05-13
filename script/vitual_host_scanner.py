#!/usr/bin/env python3
import sys
import socket
import requests
import hashlib
import difflib
import time
import argparse
import concurrent.futures
from urllib.parse import urlparse

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class VirtualHostScanner:
    def __init__(self, target, wordlist=None):
        self.target = target
        self.protocol, self.hostname, self.ip = self.setup_target(target)
        self.wordlist = wordlist if wordlist else self.default_wordlist()
        self.session = requests.Session()
        self.baseline_content = ""
        self.baseline_hash = ""
        self.results = []

    def default_wordlist(self):
        return [
            "www", "dev", "admin", "portal", "test", "app", "mail", "api", "dashboard",
            "beta", "secure", "vpn", "internal", "staging", "backend", "server"
        ]

    def setup_target(self, target):
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            protocol = parsed.scheme
            hostname = parsed.netloc.split(':')[0]
        else:
            protocol = "http"
            hostname = target.split(':')[0]

        try:
            ip = socket.gethostbyname(hostname)
            print(f"[+] Resolved {hostname} to {ip}")
        except socket.gaierror:
            print(f"[-] Could not resolve hostname: {hostname}")
            sys.exit(1)

        return protocol, hostname, ip

    def fetch_baseline(self):
        print("[+] Fetching baseline response...")
        url = f"{self.protocol}://{self.hostname}"
        try:
            resp = self.session.get(url, headers={"Host": self.hostname}, timeout=5, verify=False)
            self.baseline_content = resp.text
            self.baseline_hash = hashlib.md5(resp.text.encode()).hexdigest()
            print(f"[+] Baseline fetched. Length: {len(resp.text)} bytes, Status: {resp.status_code}")
        except Exception as e:
            print(f"[-] Failed to fetch baseline: {e}")
            sys.exit(1)

    def extract_title(self, content):
        start = content.lower().find('<title>')
        end = content.lower().find('</title>')
        if start != -1 and end != -1:
            return content[start+7:end].strip()
        else:
            return "No title found"

    def test_vhost(self, vhost):
        url = f"{self.protocol}://{self.ip}"
        headers = {"Host": vhost}
        try:
            resp = self.session.get(url, headers=headers, timeout=5, verify=False)
        except Exception:
            return None

        content = resp.text
        content_hash = hashlib.md5(content.encode()).hexdigest()
        similarity = difflib.SequenceMatcher(None, self.baseline_content, content).ratio()

        if content_hash != self.baseline_hash and similarity < 0.95:
            return {
                "vhost": vhost,
                "status": resp.status_code,
                "length": len(content),
                "title": self.extract_title(content),
                "similarity": similarity
            }
        return None

    def scan(self):
        print(f"\n[+] Starting Virtual Host scan on {self.hostname}")
        print(f"[+] Trying {len(self.wordlist)} possible hosts...\n")

        self.fetch_baseline()
        found = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.test_vhost, vhost): vhost for vhost in self.wordlist}
            for future in concurrent.futures.as_completed(futures):
                vhost = futures[future]
                try:
                    result = future.result()
                    if result:
                        found.append(result)
                        print(f"[!] Found: {result['vhost']} | Status: {result['status']} | Title: {result['title']} | Similarity: {result['similarity']*100:.1f}%")
                    else:
                        print(f"[-] Not Found: {vhost}")
                except Exception as e:
                    print(f"[-] Error with {vhost}: {str(e)}")

        self.results = found
        self.generate_report()

    def generate_report(self):
        print("\n" + "="*60)
        print("📝 Virtual Host Scan Report")
        print("="*60)

        if not self.results:
            print("[-] No virtual hosts found.")
            print("[!] Risk Level: Low")
            return

        print(f"[+] Found {len(self.results)} potential virtual hosts:\n")
        for idx, r in enumerate(self.results, 1):
            print(f"{idx}. {r['vhost']}")
            print(f"   Status : {r['status']}")
            print(f"   Length : {r['length']} bytes")
            print(f"   Title  : {r['title']}")
            print(f"   Similarity to baseline: {r['similarity']*100:.1f}%")
            print("-" * 40)

        if len(self.results) > 5:
            print("[!] Risk Level: Medium - Many virtual hosts detected")
        else:
            print("[!] Risk Level: Low - Few virtual hosts detected")

def main():
    parser = argparse.ArgumentParser(description="Virtual Host Scanner")
    parser.add_argument("target", help="Target domain or IP (e.g. example.com)")
    parser.add_argument("--wordlist", help="Custom wordlist file", default=None)

    args = parser.parse_args()

    # Load custom wordlist if provided
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, "r") as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Error loading wordlist: {e}")
            sys.exit(1)

    scanner = VirtualHostScanner(args.target, wordlist)
    scanner.scan()

if __name__ == "__main__":
    main()
