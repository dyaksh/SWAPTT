import streamlit as st
import nmap  # python-nmap

def run():
    st.header("📡 Nmap Port Scanner")

    target = st.text_input("Enter target domain or IP")
    ports = st.text_input("Enter ports (e.g., 22,80,443 or 1-1000)", "1-1000")

    if st.button("Scan"):
        if not target:
            st.warning("Please enter a valid target.")
            return

        st.info(f"Scanning {target} on ports {ports}...")

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target, ports=ports, arguments='-T4 -Pn')

            # Debugging: Print scan results to check for issues
            st.write(f"Scan Results: {nm.all_hosts()}")

            if target in nm.all_hosts():
                st.success(f"Host {target} is up.")
                for proto in nm[target].all_protocols():
                    st.subheader(f"Protocol: {proto.upper()}")
                    ports = nm[target][proto].keys()
                    for port in sorted(ports):
                        state = nm[target][proto][port]['state']
                        st.write(f"Port {port}: {state}")
            else:
                st.error("Host not found or scan failed.")
                st.write(f"Scan failed or host not found for: {target}")

        except Exception as e:
            st.error(f"Error occurred: {str(e)}")
            st.write(f"Full Error: {e}")

