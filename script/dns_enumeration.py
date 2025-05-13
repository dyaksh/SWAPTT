#!/usr/bin/env python3
import sys
import dns.resolver
import dns.exception
from tabulate import tabulate

def dns_enum(domain):
    records = []
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'SRV', 'CAA']

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            for rdata in answers:
                records.append([rtype, rdata.to_text()])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
        except Exception as e:
            records.append([rtype, f"Error: {str(e)}"])

    return records

def main():
    if len(sys.argv) != 2:
        print("Usage: python dns_enum.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    print(f"\n[+] Performing DNS Enumeration for: {domain}\n")
    
    result = dns_enum(domain)

    if result:
        table = tabulate(result, headers=["Record Type", "Value"], tablefmt="grid")
        print(table)
    else:
        print("[-] No DNS records found.")

if __name__ == "__main__":
    main()
