#!/usr/bin/env python3
import sys
import dns.resolver
import requests
import socket
import concurrent.futures
import re

def check_takeover(target):
    """Check for potential subdomain takeover vulnerabilities."""
    print(f"[+] Subdomain Takeover Scanner for: {target}")
    print("-" * 60)
    
    # Clean target input
    target = target.lower().replace("http://", "").replace("https://", "").replace("www.", "")
    if "/" in target:
        target = target.split("/")[0]
    
    # List of common CNAME fingerprints for takeover
    takeover_fingerprints = {
        "amazonaws.com": "Amazon S3",
        "cloudfront.net": "Amazon CloudFront",
        "herokuapp.com": "Heroku",
        "github.io": "GitHub Pages",
        "azure-api.net": "Azure API Management",
        "azurewebsites.net": "Azure Web Apps",
        "cloudapp.net": "Azure Cloud App",
        "trafficmanager.net": "Azure Traffic Manager",
        "blob.core.windows.net": "Azure Blob Storage",
        "netlify.app": "Netlify",
        "zendesk.com": "Zendesk",
        "ghost.io": "Ghost.io",
        "statuspage.io": "Statuspage",
        "uservoice.com": "UserVoice",
        "wpengine.com": "WP Engine",
        "fastly.net": "Fastly",
        "shopify.com": "Shopify",
        "myshopify.com": "Shopify",
        "unbounce.com": "Unbounce",
        "pantheonsite.io": "Pantheon",
        "bitbucket.io": "Bitbucket",
        "desk.com": "Desk",
        "surge.sh": "Surge",
        "strikingly.com": "Strikingly",
        "squarespace.com": "Squarespace",
        "tictail.com": "Tictail",
        "tumblr.com": "Tumblr",
        "cargocollective.com": "Cargo Collective",
        "wix.com": "Wix"
    }
    
    # Function to extract subdomains from crt.sh
    def get_subdomains_from_crtsh(domain):
        subdomains = set()
        try:
            response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if data:
                        for item in data:
                            name = item['name_value'].lower()
                            if '*' not in name:
                                # Make sure it's a subdomain
                                if name.endswith(f".{domain}") and name != domain:
                                    subdomains.add(name)
                except Exception as e:
                    print(f"  [-] Error parsing crt.sh data: {str(e)}")
        except Exception as e:
            print(f"  [-] Error accessing crt.sh: {str(e)}")
        return subdomains
    
    # Function to check a single subdomain for takeover potential
    def check_subdomain(subdomain):
        results = {}
        cname_records = []
        
        try:
            # Try to get CNAME records
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            for answer in answers:
                cname = answer.target.to_text().rstrip('.')
                cname_records.append(cname)
                
                # Check if CNAME points to a known vulnerable service
                for fingerprint, service in takeover_fingerprints.items():
                    if fingerprint in cname:
                        # Try to resolve the CNAME target
                        try:
                            socket.gethostbyname(cname)
                            results[cname] = {"service": service, "status": "Active", "risk": "Low"}
                        except socket.gaierror:
                            # CNAME target doesn't resolve - potential takeover
                            results[cname] = {"service": service, "status": "Not resolving", "risk": "High"}
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            # Check if domain has A records despite NXDOMAIN (unlikely but possible edge case)
            try:
                dns.resolver.resolve(subdomain, 'A')
            except:
                # Domain doesn't exist but might be registered
                pass
        except Exception as e:
            pass
        
        return subdomain, cname_records, results
    
    print(f"[+] Fetching subdomains for {target}...")
    subdomains = get_subdomains_from_crtsh(target)
    
    if not subdomains:
        print("[-] No subdomains found via Certificate Transparency logs.")
        print("[*] Trying some common subdomains...")
        common_subs = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn", "api"]
        for sub in common_subs:
            subdomains.add(f"{sub}.{target}")
    
    print(f"[+] Found {len(subdomains)} subdomains to check")
    
    vulnerabilities = []
    
    print("\n[+] Checking for subdomain takeover vulnerabilities...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in subdomains}
        for future in concurrent.futures.as_completed(future_to_subdomain):
            subdomain, cnames, results = future.result()
            if results:
                for cname, info in results.items():
                    if info["risk"] == "High":
                        print(f"  [!] {subdomain} -> {cname} [{info['service']}] - VULNERABLE TO TAKEOVER")
                        vulnerabilities.append({
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": info["service"]
                        })
                    else:
                        print(f"  [*] {subdomain} -> {cname} [{info['service']}] - Not vulnerable")
            elif cnames:
                print(f"  [*] {subdomain} has CNAME(s): {', '.join(cnames)} - No known vulnerable services")
    
    # Summary and risk assessment
    print("\n[+] Scan completed")
    if vulnerabilities:
        print(f"[!] Found {len(vulnerabilities)} potential subdomain takeover vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"  - {vuln['subdomain']} pointing to {vuln['cname']} ({vuln['service']})")
        
        print("\n[!] RISK ASSESSMENT: High - Subdomain takeover vulnerabilities found")
        print("    These vulnerabilities could allow attackers to take control of these subdomains")
        print("    by registering the non-resolving services.")
        print("\n[+] Recommendations:")
        print("    1. Verify each vulnerability manually")
        print("    2. Remove or update the dangling DNS records")
        print("    3. Register the services if they're still needed")
    else:
        print("[+] No subdomain takeover vulnerabilities found")
        print("\n[!] RISK ASSESSMENT: Low - No obvious takeover vulnerabilities detected")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python subdomain_takeover.py <domain>")
        sys.exit(1)
    
    check_takeover(sys.argv[1])