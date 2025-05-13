#!/usr/bin/env python3
import ssl
import socket
import sys
from datetime import datetime, timezone

def ssl_tls_check(domain):
    """Fetch SSL certificate details of the target domain."""
    try:
        if not domain.startswith(('http://', 'https://')):
            domain = 'https://' + domain
        
        hostname = domain.split("//")[1].split("/")[0]

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Print the whole SSL certificate as a dictionary
                print("\nSSL/TLS Certificate Info:")
                print("-" * 50)
                for field, value in cert.items():
                    print(f"{field}: {value}")

                # Additional Information
                issued_to = cert.get('subject', (('CommonName', ''),))[0][0][1]
                issued_by = cert.get('issuer', (('CommonName', ''),))[0][0][1]
                valid_from = cert.get('notBefore')
                valid_to = cert.get('notAfter')
                
                print("\nIssued To      : ", issued_to)
                print("Issued By      : ", issued_by)
                print("Valid From     : ", valid_from)
                print("Valid Until    : ", valid_to)

                # Expiration check
                expire_date = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z")
                now_utc = datetime.now(timezone.utc)  # Proper UTC now
                days_left = (expire_date - now_utc.replace(tzinfo=None)).days  # Remove tzinfo for safe subtraction
                
                print(f"Certificate expires in {days_left} days.")

                if days_left <= 30:
                    print("\n[!] Risk: Certificate expiring soon. Renewal recommended.")
                else:
                    print("\n[+] SSL Certificate is valid and looks good.")

    except Exception as e:
        print(f"[-] Error fetching SSL details: {str(e)}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python ssl_checker.py <domain>")
        sys.exit(1)

    target = sys.argv[1]
    ssl_tls_check(target)

if __name__ == "__main__":
    main()
