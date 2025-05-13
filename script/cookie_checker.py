#!/usr/bin/env python3
import sys
import requests
from urllib.parse import urlparse
from tabulate import tabulate

def cookie_checker(url):
    print(f"[+] Fetching cookies for: {url}\n")
    
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        session = requests.Session()
        response = session.get(url, timeout=10, verify=False)

        cookies = response.cookies

        if not cookies:
            print("[-] No cookies found on the website.")
            return

        cookie_data = []
        for cookie in cookies:
            cookie_info = {
                "Name": cookie.name,
                "Value": cookie.value,
                "Secure": cookie.secure,
                "HttpOnly": cookie._rest.get("HttpOnly", False),
                "SameSite": cookie._rest.get("SameSite", "None"),
            }
            cookie_data.append(cookie_info)

        table = tabulate(
            [[c["Name"], c["Secure"], c["HttpOnly"], c["SameSite"]] for c in cookie_data],
            headers=["Cookie Name", "Secure", "HttpOnly", "SameSite"],
            tablefmt="grid"
        )

        print(table)

        # Risk analysis
        print("\n[!] RISK ANALYSIS:")
        for c in cookie_data:
            risks = []
            if not c["Secure"]:
                risks.append("Missing Secure flag (transmitted over HTTP)")
            if not c["HttpOnly"]:
                risks.append("Missing HttpOnly flag (risk of XSS)")
            if c["SameSite"] == "None":
                risks.append("No SameSite protection (risk of CSRF)")

            if risks:
                print(f"\n- Cookie: {c['Name']}")
                for r in risks:
                    print(f"    -> {r}")

    except requests.RequestException as e:
        print(f"[-] Error fetching cookies: {str(e)}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python cookie_checker.py <url>")
        sys.exit(1)

    target = sys.argv[1]
    requests.packages.urllib3.disable_warnings()
    cookie_checker(target)

if __name__ == "__main__":
    main()
