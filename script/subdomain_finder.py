#!/usr/bin/env python3
import sys
import dns.resolver
import requests
import concurrent.futures
import re

def find_subdomains(target):
    """Find subdomains of a given domain using various techniques."""
    print(f"[+] Subdomain Finder for: {target}")
    print("-" * 60)
    
    # Clean target input
    target = target.lower().replace("http://", "").replace("https://", "").replace("www.", "")
    if "/" in target:
        target = target.split("/")[0]
    
    subdomains = set()
    found_count = 0
    
    # Common subdomain wordlist
    common_subdomains = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
        "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
        "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
        "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
        "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search",
        "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites", "proxy",
        "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info", "apps", "download"
    ]
    
    print("\n[+] Checking common subdomains...")
    
    # Function to check a single subdomain
    def check_subdomain(subdomain):
        full_domain = f"{subdomain}.{target}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            return full_domain
        except:
            pass
        return None
    
    # Use ThreadPoolExecutor for parallel subdomain checking
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in common_subdomains}
        for future in concurrent.futures.as_completed(future_to_subdomain):
            result = future.result()
            if result:
                subdomains.add(result)
                found_count += 1
                print(f"  [*] Found: {result}")
    
    # Try to find subdomains using Certificate Transparency logs (crt.sh)
    print("\n[+] Searching Certificate Transparency logs...")
    try:
        response = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=10)
        if response.status_code == 200:
            try:
                data = response.json()
                if data:
                    for item in data:
                        domain_name = item['name_value'].lower()
                        # Filter out wildcard entries and duplicates
                        if '*' not in domain_name:
                            domain_parts = domain_name.split('.')
                            # Ensure this is actually a subdomain
                            if len(domain_parts) > 2 and domain_name.endswith(target):
                                if domain_name not in subdomains:
                                    subdomains.add(domain_name)
                                    found_count += 1
                                    print(f"  [*] Found: {domain_name}")
            except Exception as e:
                print(f"  [-] Error parsing crt.sh data: {str(e)}")
    except Exception as e:
        print(f"  [-] Error accessing crt.sh: {str(e)}")
    
    print(f"\n[+] Total unique subdomains found: {found_count}")
    
    # Output summary
    if subdomains:
        print("\n[+] Summary of found subdomains:")
        for subdomain in sorted(subdomains):
            print(f"  - {subdomain}")
    
        # Analyze risk based on number of subdomains
        if found_count > 30:
            print("\n[!] RISK ASSESSMENT: Medium - Large attack surface detected")
            print("    A high number of subdomains increases the attack surface.")
            print("    Recommendation: Review all subdomains for security misconfigurations.")
        elif found_count > 10:
            print("\n[!] RISK ASSESSMENT: Low - Moderate attack surface")
            print("    Recommendation: Ensure all subdomains are properly secured.")
        else:
            print("\n[!] RISK ASSESSMENT: Low - Minimal attack surface")
    else:
        print("\n[-] No subdomains found.")
        print("[!] RISK ASSESSMENT: Info - No additional attack surface detected")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python subdomain_finder.py <domain>")
        sys.exit(1)
    
    find_subdomains(sys.argv[1])