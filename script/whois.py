import whois
import sys

def run_whois(domain):
    try:
        w = whois.whois(domain)
        whois_info = f"WHOIS Information for {domain}:\n\n"
        for key, value in w.items():
            whois_info += f"{key}: {value}\n"
        return whois_info
    except Exception as e:
        return f"❌ Error fetching WHOIS data for {domain}: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python whois.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    result = run_whois(domain)
    print(result)
