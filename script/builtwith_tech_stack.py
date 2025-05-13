#!/usr/bin/env python3
import sys
import requests
from bs4 import BeautifulSoup
import re

def builtwith_checker(url):
    print(f"[+] BuiltWith Technology Scanner for: {url}")
    print("-" * 60)

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        response = requests.get(url, timeout=10, verify=False)
    except Exception as e:
        print(f"[-] Error fetching the website: {str(e)}")
        return

    if response.status_code != 200:
        print(f"[-] Non-200 HTTP response: {response.status_code}")
        return

    headers = response.headers
    html = response.text.lower()
    tech_found = []

    # Server Header
    server = headers.get('Server')
    if server:
        print(f"[Server] {server}")
        tech_found.append(f"Server: {server}")

    # Powered-by Header
    powered_by = headers.get('X-Powered-By')
    if powered_by:
        print(f"[X-Powered-By] {powered_by}")
        tech_found.append(f"X-Powered-By: {powered_by}")

    # Content-Type
    content_type = headers.get('Content-Type')
    if content_type:
        print(f"[Content-Type] {content_type}")
        tech_found.append(f"Content-Type: {content_type}")

    # CMS detection via meta tags
    soup = BeautifulSoup(response.text, 'html.parser')
    generator = soup.find('meta', attrs={"name": "generator"})
    if generator and generator.get('content'):
        print(f"[Meta Generator] {generator['content']}")
        tech_found.append(f"Generator: {generator['content']}")

    # Check common CMS patterns
    cms_patterns = {
        'WordPress': r'wp-content|wp-includes',
        'Drupal': r'drupal',
        'Joomla': r'joomla',
        'Magento': r'mage|magento',
        'Shopify': r'cdn\.shopify\.com',
        'Wix': r'wix\.com',
        'Squarespace': r'squarespace\.com',
        'PrestaShop': r'prestashop',
        'Blogger': r'blogger\.com'
    }

    cms_detected = []
    for cms, pattern in cms_patterns.items():
        if re.search(pattern, html):
            cms_detected.append(cms)

    if cms_detected:
        print(f"[CMS Detected] {', '.join(cms_detected)}")
        tech_found.append(f"CMS: {', '.join(cms_detected)}")

    # JavaScript Libraries
    js_libraries = {
        'jQuery': r'jquery.*\.js',
        'AngularJS': r'angular.*\.js',
        'ReactJS': r'react.*\.js',
        'VueJS': r'vue.*\.js',
        'Bootstrap': r'bootstrap.*\.js',
        'FontAwesome': r'font-awesome|fontawesome',
        'EmberJS': r'ember.*\.js'
    }

    js_detected = []
    for lib, pattern in js_libraries.items():
        if re.search(pattern, html):
            js_detected.append(lib)

    if js_detected:
        print(f"[JavaScript Libraries] {', '.join(js_detected)}")
        tech_found.append(f"JavaScript Libraries: {', '.join(js_detected)}")

    # Web server fingerprint from headers
    if 'nginx' in html:
        print("[Detected] Nginx Web Server via page source")
    if 'apache' in html:
        print("[Detected] Apache Web Server via page source")

    # Check for analytics
    analytics_found = []
    if "www.google-analytics.com" in html:
        analytics_found.append("Google Analytics")
    if "gtag/js" in html:
        analytics_found.append("Google Global Site Tag")
    if "googletagmanager.com" in html:
        analytics_found.append("Google Tag Manager")

    if analytics_found:
        print(f"[Analytics Detected] {', '.join(analytics_found)}")
        tech_found.append(f"Analytics: {', '.join(analytics_found)}")

    # CDN detection
    if "cloudflare" in headers.get('Server', '').lower() or "cloudflare" in html:
        print("[CDN Detected] Cloudflare")
        tech_found.append("CDN: Cloudflare")

    if not tech_found:
        print("\n[-] No major technologies detected.")
    else:
        print("\n[+] Total Technologies Found: ", len(tech_found))

def main():
    if len(sys.argv) != 2:
        print("Usage: python builtwith_checker.py <url>")
        sys.exit(1)

    target = sys.argv[1]
    requests.packages.urllib3.disable_warnings()
    builtwith_checker(target)

if __name__ == "__main__":
    main()
