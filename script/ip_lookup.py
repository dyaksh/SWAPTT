import socket

def get_ip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"IP address of {domain}: {ip}"
    except Exception as e:
        return f"Failed to lookup IP: {str(e)}"

if __name__ == "__main__":
    import sys
    print(get_ip_info(sys.argv[1]))
