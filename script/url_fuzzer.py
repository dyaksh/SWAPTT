#!/usr/bin/env python3
import sys
import requests
import time
from urllib.parse import urljoin
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_session():
    """Create a session with retry logic."""
    retry_strategy = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
        raise_on_status=False
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    })
    return session

def url_fuzzer(base_url):
    """Fuzz common paths on a target URL."""
    common_paths = [
        'admin', 'login', 'dashboard', 'config', 'uploads', 'backup',
        'test', 'dev', 'staging', 'server-status', 'hidden', '.git', '.env'
    ]
    
    print(f"[+] Starting URL Fuzzer on: {base_url}")
    print("-" * 50)
    
    found = []
    session = create_session()

    if not base_url.startswith(('http://', 'https://')):
        base_url = 'http://' + base_url

    for path in common_paths:
        url = urljoin(base_url.rstrip('/') + '/', path)
        try:
            response = session.get(url, timeout=30, verify=False, allow_redirects=True)  # timeout increased to 30s
            status = response.status_code

            if status == 200:
                print(f"[+] Found: {url} (Status: {status})")
                found.append({"url": url, "status_code": status})
            elif status in [301, 302]:
                print(f"[-] Redirected: {url} (Status: {status})")
            elif status == 403:
                print(f"[!] Forbidden (but exists?): {url} (Status: {status})")
                found.append({"url": url, "status_code": status})
            else:
                print(f"[ ] {url} (Status: {status})")
            
            time.sleep(0.5)  # <-- slow down requests slightly (optional but helps prevent server banning)

        except requests.RequestException as e:
            print(f"[!] Error accessing {url}: {str(e)}")
            continue

    print("-" * 50)
    print(f"[+] Fuzzing complete. {len(found)} interesting paths found.")

    return found

def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python url_fuzzer.py <target_url>")
        sys.exit(1)

    base_url = sys.argv[1]
    found_paths = url_fuzzer(base_url)

    import json
    print(json.dumps(found_paths, indent=2))

if __name__ == "__main__":
    main()
