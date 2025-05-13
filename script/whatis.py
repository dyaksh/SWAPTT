#!/usr/bin/env python3
import sys
import socket
import subprocess
import re

def resolve_domain(domain):
    print(f"[INFO] Resolving IP Address for: {domain}")
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"[+] IP Address: {ip_address}\n")
    except Exception as e:
        print(f"[-] Error resolving IP address: {str(e)}")

def whois_lookup(domain):
    print(f"[INFO] Performing WHOIS Lookup for: {domain}\n")

    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            output = result.stdout
            print("=" * 50)
            print("WHOIS Lookup Result (Important Details)")
            print("=" * 50)

            # Extract important fields manually using regex
            fields = {
                "Domain Name": re.search(r"Domain Name:\s*(.*)", output, re.IGNORECASE),
                "Registrar": re.search(r"Registrar:\s*(.*)", output, re.IGNORECASE),
                "Creation Date": re.search(r"Creation Date:\s*(.*)", output, re.IGNORECASE),
                "Expiry Date": re.search(r"(?:Expiration|Expiry) Date:\s*(.*)", output, re.IGNORECASE),
                "Name Server": re.findall(r"Name Server:\s*(.*)", output, re.IGNORECASE),
                "Status": re.findall(r"Status:\s*(.*)", output, re.IGNORECASE)
            }

            # Display found fields
            for field, match in fields.items():
                if match:
                    if isinstance(match, list):  # multiple entries like NS or Status
                        print(f"{field}:")
                        for item in match:
                            print(f"  - {item}")
                    else:
                        print(f"{field}: {match.group(1)}")
        else:
            print("[-] Whois command failed or returned error.")

    except FileNotFoundError:
        print("[-] 'whois' command not found on system. Please install 'whois' tool.")
    except Exception as e:
        print(f"[-] Error during WHOIS lookup: {str(e)}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python whatis.py <domain>")
        sys.exit(1)

    target = sys.argv[1]

    resolve_domain(target)
    whois_lookup(target)

if __name__ == "__main__":
    main()
