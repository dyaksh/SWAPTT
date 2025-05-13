#!/usr/bin/env python3
import sys
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def recon_website(url):
    report = []
    
    if not url.startswith(('http://', 'https://')):
        url = "http://" + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    report.append("=" * 60)
    report.append(f"[Website Recon] Target: {url}")  # Removed emoji 🌐
    report.append("=" * 60)

    try:
        response = requests.get(url, timeout=10, verify=False)
    except requests.RequestException as e:
        return f"[-] Failed to connect to {url}: {str(e)}"

    # 1. Basic Info
    report.append("\n[+] Basic Information:")
    report.append(f"  - Status Code: {response.status_code}")
    report.append(f"  - Server: {response.headers.get('Server', 'Not disclosed')}")
    report.append(f"  - Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
    report.append(f"  - Content-Length: {len(response.content)} bytes")
    report.append(f"  - Date: {response.headers.get('Date', datetime.now(timezone.utc))}")

    # 2. Security Headers
    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy"
    ]
    report.append("\n[+] Security Headers:")
    found_sec = False
    for header in security_headers:
        value = response.headers.get(header)
        if value:
            found_sec = True
            report.append(f"  - {header}: {value}")
    if not found_sec:
        report.append("  - No important security headers found!")

    # 3. SSL/TLS Check
    if url.startswith("https://"):
        report.append("\n[+] SSL/TLS Check:")
        report.append("  - SSL/TLS is enabled")
    else:
        report.append("\n[+] SSL/TLS Check:")
        report.append("  - SSL/TLS NOT enabled (Site is HTTP only)")

    # 4. Interesting Headers
    interesting_headers = [
        "Set-Cookie", "X-Powered-By", "Via", "X-AspNet-Version", "X-Amz-Cf-Id"
    ]
    report.append("\n[+] Other Interesting Headers:")
    for header in interesting_headers:
        value = response.headers.get(header)
        if value:
            report.append(f"  - {header}: {value}")

    # 5. Redirect Info
    if len(response.history) > 0:
        report.append("\n[+] Redirects detected:")
        for resp in response.history:
            report.append(f"  - {resp.status_code} -> {resp.headers.get('Location')}")
        report.append(f"  - Final destination: {response.url}")
    else:
        report.append("\n[+] No redirects detected.")

    # 6. Cookie Flags
    if 'Set-Cookie' in response.headers:
        report.append("\n[+] Cookie Analysis:")
        cookies = response.headers.get('Set-Cookie').split(',')
        for cookie in cookies:
            cookie_flags = []
            if "Secure" in cookie:
                cookie_flags.append("Secure")
            if "HttpOnly" in cookie:
                cookie_flags.append("HttpOnly")
            if cookie_flags:
                report.append(f"  - {cookie.strip()} [{', '.join(cookie_flags)}]")
            else:
                report.append(f"  - {cookie.strip()} [No Secure/HttpOnly flags!]")

    # 7. Recommendations
    report.append("\n[+] Recommendations:")
    if not found_sec:
        report.append("  - Add missing security headers for better protection.")
    if not url.startswith("https://"):
        report.append("  - Enable HTTPS and force redirection to HTTPS.")
    if "Set-Cookie" in response.headers and "Secure" not in response.headers.get("Set-Cookie", ""):
        report.append("  - Ensure cookies have Secure and HttpOnly flags set.")

    report.append("\nScan complete.")
    return "\n".join(report)

def main():
    if len(sys.argv) != 2:
        print("Usage: python website_recon.py <url>")
        sys.exit(1)

    target = sys.argv[1]
    output = recon_website(target)
    
    try:
        print(output)
    except UnicodeEncodeError:
        print(output.encode('utf-8', errors='ignore').decode('utf-8'))

if __name__ == "__main__":
    main()
