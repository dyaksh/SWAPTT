#!/usr/bin/env python3
import sys
import requests
import re
from urllib.parse import urlparse

def run_waf_detector(target):
    print(f"[+] Starting WAF Detection for: {target}")
    print("-" * 60)

    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    parsed = urlparse(target)
    hostname = parsed.netloc

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    }

    # WAF Detection payloads
    payloads = [
        "/?id=1' or '1'='1",
        "/?q=<script>alert(1)</script>",
        "/admin.php",
        "/login.php' OR 1=1 --",
        "/../../../../etc/passwd"
    ]

    waf_detected = False
    detected_signatures = []

    try:
        for payload in payloads:
            url = target.rstrip('/') + payload
            response = requests.get(url, headers=headers, timeout=10, verify=False)

            # Analyze response codes
            if response.status_code in [406, 501, 999, 419, 403]:
                waf_detected = True
                detected_signatures.append(f"Blocked with status code: {response.status_code}")

            # Analyze server headers
            server = response.headers.get('Server', '')
            if re.search(r"cloudflare|akamai|sucuri|imperva|barracuda", server, re.I):
                waf_detected = True
                detected_signatures.append(f"WAF Server Header: {server}")

            # Analyze body content
            if re.search(r"access denied|blocked|firewall|secure gateway|site protected", response.text, re.I):
                waf_detected = True
                detected_signatures.append("Response body contains WAF protection keywords")

    except requests.RequestException as e:
        print(f"[-] Error making request: {str(e)}")
        return

    print("\nResults for WAF Detector:")
    print("-" * 60)
    print(f"Target       : {hostname}")
    print(f"Scan ID      : {hash(target) % 1000000}")
    print(f"Timestamp    : {time_now()}")
    print("-" * 60)

    if waf_detected:
        print("[!] WAF Detected!")
        for sig in detected_signatures:
            print(f"    - {sig}")

        print("\n[!] RISK ASSESSMENT: HIGH")
        print("[*] RECOMMENDATIONS:")
        print("    - Understand what WAF is in place")
        print("    - Plan your security assessment accordingly")
    else:
        print("[+] No obvious WAF detected.")
        print("\n[!] RISK ASSESSMENT: LOW")
        print("[*] RECOMMENDATIONS:")
        print("    - Continue standard web application security testing")

    print("-" * 60)
    print("WAF Detection Completed.\n")


def time_now():
    import datetime
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python waf_detector.py <target>")
        sys.exit(1)

    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    
    target = sys.argv[1]
    run_waf_detector(target)
