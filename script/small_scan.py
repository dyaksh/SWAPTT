#!/usr/bin/env python3
import requests
import sys
import random
import string
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import socket

# Optional: Try setting UTF-8 (safe fallback)
try:
    sys.stdout.reconfigure(encoding='utf-8')
except:
    pass

requests.packages.urllib3.disable_warnings()

class SmallWebsiteScanner:
    def __init__(self, target):
        self.target = target if target.startswith(('http://', 'https://')) else 'http://' + target
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.results = {
            'ssl': False,
            'headers': {},
            'fuzzed_paths': [],
            'subdomains': [],
            'waf_detected': False
        }
        self.scan_id = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))

    def gather_information(self):
        print("\n[INFO] Gathering Basic Website Info...")
        try:
            resp = self.session.get(self.target, verify=False, timeout=10, allow_redirects=True)

            final_url = resp.url
            if final_url.startswith('https://'):
                print("  [✔] SSL/HTTPS is supported")
                self.results['ssl'] = True
            else:
                print("  [!] SSL/HTTPS NOT supported")
                self.results['ssl'] = False

            important_headers = ['Server', 'Content-Type', 'X-Powered-By', 'Set-Cookie']
            for header in important_headers:
                if header in resp.headers:
                    self.results['headers'][header] = resp.headers[header]
                    print(f"  [Header] {header}: {resp.headers[header]}")

        except Exception as e:
            print(f"  [-] Error gathering information: {str(e)}")

    def url_fuzzer(self):
        print("\n[INFO] Starting URL Fuzzing...")
        common_paths = ['admin', 'login', 'dashboard', 'uploads', 'config', 'api']
        for path in common_paths:
            url = f"{self.target.rstrip('/')}/{path}"
            try:
                r = self.session.get(url, verify=False, timeout=5)
                if r.status_code == 200:
                    print(f"  [FOUND] {url}")
                    self.results['fuzzed_paths'].append(url)
            except requests.RequestException:
                pass

    def subdomain_finder(self):
        print("\n[INFO] Finding Subdomains (basic)")
        common_subdomains = [
            'www', 'mail', 'ftp', 'test', 'dev', 'api', 'blog', 'admin', 'portal'
        ]
        domain = urlparse(self.target).netloc

        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                print(f"  [FOUND] {subdomain}")
                self.results['subdomains'].append(subdomain)
            except socket.error:
                continue

    def detect_waf(self):
        print("\n[INFO] Detecting WAF (Web Application Firewall)...")
        try:
            resp = self.session.get(self.target, verify=False, timeout=10)
            waf_headers = ['x-sucuri-id', 'x-fireeye', 'x-waf', 'server: cloudflare']

            for header in waf_headers:
                if any(hdr.lower() in str(resp.headers).lower() for hdr in waf_headers):
                    print("  [!] WAF Detected!")
                    self.results['waf_detected'] = True
                    return
            print("  [✔] No obvious WAF detected")
        except Exception as e:
            print(f"  [-] Error detecting WAF: {str(e)}")

    def generate_report(self):
        print("\n" + "="*60)
        print("SMALL WEBSITE SCAN REPORT")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"Scan ID: {self.scan_id}\n")

        print(f"[SSL Supported]: {'Yes' if self.results['ssl'] else 'No'}")

        print("\n[HTTP Headers]")
        if self.results['headers']:
            for header, value in self.results['headers'].items():
                print(f"  - {header}: {value}")
        else:
            print(" - No headers found")

        print("\n[Discovered Paths]")
        if self.results['fuzzed_paths']:
            for path in self.results['fuzzed_paths']:
                print(f" - {path}")
        else:
            print(" - No paths discovered")

        print("\n[Subdomains Found]")
        if self.results['subdomains']:
            for sub in self.results['subdomains']:
                print(f" - {sub}")
        else:
            print(" - No subdomains found")

        print("\n[WAF Detection]")
        print(f" - {'WAF Detected' if self.results['waf_detected'] else 'No WAF Detected'}")

        print("\n[+] Small scan complete!\n")  # <- No emoji, Windows safe

    def run_small_scan(self):
        self.gather_information()
        self.url_fuzzer()
        self.subdomain_finder()
        self.detect_waf()
        self.generate_report()

def main():
    if len(sys.argv) != 2:
        print("Usage: python small_scan.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    scanner = SmallWebsiteScanner(target)
    scanner.run_small_scan()

if __name__ == "__main__":
    main()
