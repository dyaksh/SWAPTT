#!/usr/bin/env python3
# Small Scan Script for SWAPTT
import sys
import time
import random
import re
from datetime import datetime

def run_small_scan(target):
    print(f"Running Small Scan on {target}")
    print("Initializing...")
    time.sleep(1)
    print("Scanning target...")
    time.sleep(1)
    print("Analyzing results...")
    time.sleep(1)
    
    # Generate some simulated output based on the tool type
    output = []
    output.append(f"SWAPTT Small Scan")
    output.append(f"Target: {target}")
    output.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    output.append("-" * 50)
    
    # Specific outputs based on tool type
    if "Small Scan" == "WHOIS":
        output.append(f"Domain Name: {target}")
        output.append(f"Registrar: Example Registrar, Inc.")
        output.append(f"Registered On: 2020-01-15")
        output.append(f"Expires On: 2025-01-15")
        output.append(f"Name Server: ns1.example.com")
        output.append(f"Name Server: ns2.example.com")
    elif "Small Scan" == "IP Lookup":
        output.append(f"IP Address: 192.168.1.{random.randint(1, 254)}")
        output.append(f"Location: New York, United States")
        output.append(f"ISP: Example ISP")
        output.append(f"Ping Results: 4 packets transmitted, 4 received, 0% packet loss")
    elif "Small Scan" in ["Port Scanner Nmap", "Nmap", "Full Scan", "Small Scan"]:
        ports = [80, 443, 22, 21, 25, 110, 143, 3306]
        for port in random.sample(ports, 3):
            status = random.choice(["open", "closed", "filtered"])
            service = {80: "http", 443: "https", 22: "ssh", 21: "ftp", 
                      25: "smtp", 110: "pop3", 143: "imap", 3306: "mysql"}[port]
            output.append(f"Port {port}/tcp: {status} ({service})")
    elif "Small Scan" == "Headers Scanner":
        output.append("HTTP/1.1 200 OK")
        output.append("Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}")
        output.append("Server: Apache/2.4.41 (Ubuntu)")
        output.append("X-Frame-Options: SAMEORIGIN")
        output.append("X-XSS-Protection: 1; mode=block")
        output.append("X-Content-Type-Options: nosniff")
        output.append("Content-Type: text/html; charset=UTF-8")
    elif "Small Scan" == "SSL/TLS Checker":
        output.append("Certificate Information:")
        output.append("  Subject: CN={target}, O=Example Inc, L=New York, ST=NY, C=US")
        output.append(f"  Issuer: CN=Example CA, O=Example Trust Network, C=US")
        output.append(f"  Validity: Not Before: Jan 1 00:00:00 2025 GMT")
        output.append(f"           Not After : Dec 31 23:59:59 2025 GMT")
        output.append(f"  Public Key Algorithm: rsaEncryption")
        output.append(f"  RSA Key Size: 2048 bit")
        output.append(f"  Signature Algorithm: sha256WithRSAEncryption")
    elif "Small Scan" in ["XSS Exploiter", "SQLi Exploiter", "LFI/RFI Tester", "Command Injection"]:
        vulnerabilities = random.randint(0, 3)
        output.append(f"Scan completed - found {vulnerabilities} potential vulnerabilities")
        if vulnerabilities > 0:
            output.append("VULNERABILITIES DETECTED:")
            if "Small Scan" == "XSS Exploiter":
                output.append("  - Reflected XSS possible in search parameter")
                output.append("  - DOM-based XSS in user profile page")
            elif "Small Scan" == "SQLi Exploiter":
                output.append("  - Possible SQL injection in login form")
                output.append("  - Error-based SQLi in product ID parameter")
            elif "Small Scan" == "LFI/RFI Tester":
                output.append("  - Local File Inclusion possible in 'page' parameter")
                output.append("  - Path traversal vulnerability detected")
            elif "Small Scan" == "Command Injection":
                output.append("  - OS Command injection in admin console")
                output.append("  - Unsanitized input in debug endpoint")
    elif "Small Scan" == "Subdomain Finder":
        subdomains = ["mail", "www", "api", "dev", "test", "admin", "blog", "shop"]
        for subdomain in random.sample(subdomains, 4):
            output.append(f"Found subdomain: {subdomain}.{target}")
    elif "Small Scan" == "WAF Detector":
        wafs = ["Cloudflare", "AWS WAF", "ModSecurity", "Imperva", "None detected"]
        detected_waf = random.choice(wafs)
        output.append(f"WAF Detection Results: {detected_waf}")
        if detected_waf != "None detected":
            output.append(f"WAF Fingerprint: {detected_waf} signatures identified")
            output.append(f"Evasion difficulty: {'High' if detected_waf in ['Cloudflare', 'Imperva'] else 'Medium'}")
    elif "Small Scan" == "DNS Resolver" or "Small Scan" == "DNS Enumeration":
        output.append(f"A Record: 192.168.1.{random.randint(1, 254)}")
        output.append(f"MX Record: mail.{target} (Priority: 10)")
        output.append(f"NS Records: ns1.{target}, ns2.{target}")
        output.append(f"TXT Record: v=spf1 include:_spf.{target} ~all")
    else:
        # Generic output for other tools
        output.append(f"Scan completed successfully")
        output.append(f"No significant issues detected")
    
    output.append("-" * 50)
    if "Small Scan" in ["XSS Exploiter", "SQLi Exploiter", "LFI/RFI Tester", "Command Injection"]:
        output.append("RISK ASSESSMENT: Potential vulnerabilities detected")
        output.append("Recommendation: Further manual testing required")
    else:
        output.append("RISK ASSESSMENT: No immediate risks detected")
        output.append("Recommendation: Continue monitoring")
    
    return "\n".join(output)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "example.com"
    result = run_small_scan(target)
    print(result)
