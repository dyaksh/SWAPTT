import streamlit as st
from PIL import Image
import subprocess
import os
import matplotlib.pyplot as plt
import tempfile
import time
import re
import platform
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import io
import base64
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

# Set page configuration
st.set_page_config(page_title="SWAPTT", page_icon="💻", layout="wide")

# Create necessary directories if they don't exist
os.makedirs("scripts", exist_ok=True)
os.makedirs("results", exist_ok=True)
os.makedirs("assets", exist_ok=True)

# Check if logo exists, otherwise create a placeholder
logo_path = "logo.png"
if not os.path.exists(logo_path):
    # Create a simple placeholder logo using matplotlib
    fig, ax = plt.subplots(figsize=(3, 1.5))
    ax.text(0.5, 0.5, 'SWAPTT', fontsize=24, ha='center', va='center', fontweight='bold')
    ax.set_facecolor('#f0f2f6')
    ax.axis('off')
    plt.tight_layout()
    plt.savefig(logo_path)
    plt.close()

# Load logo in sidebar
logo = Image.open(logo_path)
st.sidebar.image(logo, width=150)

# Initialize session state for scan results
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []
    
if 'scan_count' not in st.session_state:
    st.session_state.scan_count = 0

# Sidebar Navigation
page = st.sidebar.radio("🔎 Navigate", ["🏠 Home", "🧰 Tools", "📊 Dashboard", "📞 Contact"])

# Define categories and tools with emojis
tool_categories = {
    "🧾 Scan Tools": {
        "Full Scan": "📜",
        "Small Scan": "📄"
    },
    "🔍 Recon Tools": {
        "WHOIS": "🔍",
        "WHATIS": "❓",
        "Subdomain Finder": "🌐",
        "Subdomain Takeover": "🚧",
        "Web Crawler": "🕷️",
        "Virtual Host Scanner": "🏠",
        "Website Recon": "🧭",
        "IP Lookup": "📍",
        "DNS Enumeration": "🧱"
    },
    "💉 Exploit Tools": {
        "XSS Exploiter": "💉",
        "SQLi Exploiter": "🧬",
        "URL Fuzzer": "🧪",
        "LFI/RFI Tester": "🗂️",
        "Command Injection": "🔗"
    },
    "🛡️ Analysis Tools": {
        "Port Scanner Nmap": "📡",
        "WAF Detector": "🛡️",
        "SSL/TLS Checker": "🔒",
        "Headers Scanner": "📥",
        "Cookie Checker": "🍪",
        "BuiltWith Tech Stack": "⚙️"
    },
    "🌐 Network Tools": {
        "Network Scan": "🔌",
        "Nmap": "🛰️",
        "Ping Sweep": "📶",
        "Traceroute": "🧵",
        "DNS Resolver": "🌍"
    }
}

# Tool command mapping with script paths
tool_commands = {
    "WHOIS": {"command": "whois {target}", "script": "scripts/whois_scan.py"},
    "IP Lookup": {"command": "ping -c 4 {target}", "script": "scripts/ip_lookup.py"},
    "DNS Enumeration": {"command": "dig {target} ANY", "script": "scripts/dns_enum.py"},
    "Port Scanner Nmap": {"command": "nmap -F {target}", "script": "scripts/port_scan.py"},
    "Traceroute": {"command": "traceroute {target}", "script": "scripts/traceroute.py"},
    "Headers Scanner": {"command": "curl -I {target}", "script": "scripts/headers_scan.py"},
    "SSL/TLS Checker": {"command": "echo | openssl s_client -connect {target}:443 | openssl x509 -noout -text", "script": "scripts/ssl_check.py"},
    "Ping Sweep": {"command": "ping -c 4 {target}", "script": "scripts/ping_sweep.py"},
    "Nmap": {"command": "nmap -sV {target}", "script": "scripts/nmap_scan.py"},
    "Full Scan": {"command": "nmap -A {target}", "script": "scripts/full_scan.py"},
    "Small Scan": {"command": "nmap -F {target}", "script": "scripts/small_scan.py"},
    "WHATIS": {"command": "", "script": "scripts/whatis.py"},
    "Subdomain Finder": {"command": "", "script": "scripts/subdomain_finder.py"},
    "Subdomain Takeover": {"command": "", "script": "scripts/subdomain_takeover.py"},
    "Web Crawler": {"command": "", "script": "scripts/web_crawler.py"},
    "Virtual Host Scanner": {"command": "", "script": "scripts/vhost_scanner.py"},
    "Website Recon": {"command": "", "script": "scripts/website_recon.py"},
    "XSS Exploiter": {"command": "", "script": "scripts/xss_exploiter.py"},
    "SQLi Exploiter": {"command": "", "script": "scripts/sqli_exploiter.py"},
    "URL Fuzzer": {"command": "", "script": "scripts/url_fuzzer.py"},
    "LFI/RFI Tester": {"command": "", "script": "scripts/lfi_rfi_tester.py"},
    "Command Injection": {"command": "", "script": "scripts/command_injection.py"},
    "WAF Detector": {"command": "", "script": "scripts/waf_detector.py"},
    "Cookie Checker": {"command": "", "script": "scripts/cookie_checker.py"},
    "BuiltWith Tech Stack": {"command": "", "script": "scripts/builtwith.py"},
    "Network Scan": {"command": "", "script": "scripts/network_scan.py"},
    "DNS Resolver": {"command": "", "script": "scripts/dns_resolver.py"}
}

def ensure_scripts_exist():
    # Don't generate any scripts - only create directories
    for script_dir in set(os.path.dirname(info["script"]) for _, info in tool_commands.items()):
        os.makedirs(script_dir, exist_ok=True)
    
    # Optionally, print a message about missing scripts
    missing_scripts = [info["script"] for _, info in tool_commands.items() if not os.path.exists(info["script"])]
    if missing_scripts:
        print(f"Warning: The following scripts are missing and need to be created: {missing_scripts}")
# # Create a Python script for tools
# def create_script_file(tool_name, script_path):
#     """Create a Python script for the specified tool."""
#     os.makedirs(os.path.dirname(script_path), exist_ok=True)
    
#     with open(script_path, "w") as f:
#         clean_name = os.path.basename(script_path).replace(".py", "")
#         f.write(f'''#!/usr/bin/env python3
# # {tool_name} Script for SWAPTT
# import sys
# import time
# import random
# import re
# from datetime import datetime

# def run_{clean_name}(target):
#     print(f"Running {tool_name} on {{target}}")
#     print("Initializing...")
#     time.sleep(1)
#     print("Scanning target...")
#     time.sleep(1)
#     print("Analyzing results...")
#     time.sleep(1)
    
#     # Generate some simulated output based on the tool type
#     output = []
#     output.append(f"SWAPTT {tool_name}")
#     output.append(f"Target: {{target}}")
#     output.append(f"Timestamp: {{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}")
#     output.append("-" * 50)
    
#     # Specific outputs based on tool type
#     if "{tool_name}" == "WHOIS":
#         output.append(f"Domain Name: {{target}}")
#         output.append(f"Registrar: Example Registrar, Inc.")
#         output.append(f"Registered On: 2020-01-15")
#         output.append(f"Expires On: 2025-01-15")
#         output.append(f"Name Server: ns1.example.com")
#         output.append(f"Name Server: ns2.example.com")
#     elif "{tool_name}" == "IP Lookup":
#         output.append(f"IP Address: 192.168.1.{{random.randint(1, 254)}}")
#         output.append(f"Location: New York, United States")
#         output.append(f"ISP: Example ISP")
#         output.append(f"Ping Results: 4 packets transmitted, 4 received, 0% packet loss")
#     elif "{tool_name}" in ["Port Scanner Nmap", "Nmap", "Full Scan", "Small Scan"]:
#         ports = [80, 443, 22, 21, 25, 110, 143, 3306]
#         for port in random.sample(ports, 3):
#             status = random.choice(["open", "closed", "filtered"])
#             service = {{80: "http", 443: "https", 22: "ssh", 21: "ftp", 
#                       25: "smtp", 110: "pop3", 143: "imap", 3306: "mysql"}}[port]
#             output.append(f"Port {{port}}/tcp: {{status}} ({{service}})")
#     elif "{tool_name}" == "Headers Scanner":
#         output.append("HTTP/1.1 200 OK")
#         output.append("Date: {{datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}}")
#         output.append("Server: Apache/2.4.41 (Ubuntu)")
#         output.append("X-Frame-Options: SAMEORIGIN")
#         output.append("X-XSS-Protection: 1; mode=block")
#         output.append("X-Content-Type-Options: nosniff")
#         output.append("Content-Type: text/html; charset=UTF-8")
#     elif "{tool_name}" == "SSL/TLS Checker":
#         output.append("Certificate Information:")
#         output.append("  Subject: CN={{target}}, O=Example Inc, L=New York, ST=NY, C=US")
#         output.append(f"  Issuer: CN=Example CA, O=Example Trust Network, C=US")
#         output.append(f"  Validity: Not Before: Jan 1 00:00:00 2025 GMT")
#         output.append(f"           Not After : Dec 31 23:59:59 2025 GMT")
#         output.append(f"  Public Key Algorithm: rsaEncryption")
#         output.append(f"  RSA Key Size: 2048 bit")
#         output.append(f"  Signature Algorithm: sha256WithRSAEncryption")
#     elif "{tool_name}" in ["XSS Exploiter", "SQLi Exploiter", "LFI/RFI Tester", "Command Injection"]:
#         vulnerabilities = random.randint(0, 3)
#         output.append(f"Scan completed - found {{vulnerabilities}} potential vulnerabilities")
#         if vulnerabilities > 0:
#             output.append("VULNERABILITIES DETECTED:")
#             if "{tool_name}" == "XSS Exploiter":
#                 output.append("  - Reflected XSS possible in search parameter")
#                 output.append("  - DOM-based XSS in user profile page")
#             elif "{tool_name}" == "SQLi Exploiter":
#                 output.append("  - Possible SQL injection in login form")
#                 output.append("  - Error-based SQLi in product ID parameter")
#             elif "{tool_name}" == "LFI/RFI Tester":
#                 output.append("  - Local File Inclusion possible in 'page' parameter")
#                 output.append("  - Path traversal vulnerability detected")
#             elif "{tool_name}" == "Command Injection":
#                 output.append("  - OS Command injection in admin console")
#                 output.append("  - Unsanitized input in debug endpoint")
#     elif "{tool_name}" == "Subdomain Finder":
#         subdomains = ["mail", "www", "api", "dev", "test", "admin", "blog", "shop"]
#         for subdomain in random.sample(subdomains, 4):
#             output.append(f"Found subdomain: {{subdomain}}.{{target}}")
#     elif "{tool_name}" == "WAF Detector":
#         wafs = ["Cloudflare", "AWS WAF", "ModSecurity", "Imperva", "None detected"]
#         detected_waf = random.choice(wafs)
#         output.append(f"WAF Detection Results: {{detected_waf}}")
#         if detected_waf != "None detected":
#             output.append(f"WAF Fingerprint: {{detected_waf}} signatures identified")
#             output.append(f"Evasion difficulty: {{'High' if detected_waf in ['Cloudflare', 'Imperva'] else 'Medium'}}")
#     elif "{tool_name}" == "DNS Resolver" or "{tool_name}" == "DNS Enumeration":
#         output.append(f"A Record: 192.168.1.{{random.randint(1, 254)}}")
#         output.append(f"MX Record: mail.{{target}} (Priority: 10)")
#         output.append(f"NS Records: ns1.{{target}}, ns2.{{target}}")
#         output.append(f"TXT Record: v=spf1 include:_spf.{{target}} ~all")
#     else:
#         # Generic output for other tools
#         output.append(f"Scan completed successfully")
#         output.append(f"No significant issues detected")
    
#     output.append("-" * 50)
#     if "{tool_name}" in ["XSS Exploiter", "SQLi Exploiter", "LFI/RFI Tester", "Command Injection"]:
#         output.append("RISK ASSESSMENT: Potential vulnerabilities detected")
#         output.append("Recommendation: Further manual testing required")
#     else:
#         output.append("RISK ASSESSMENT: No immediate risks detected")
#         output.append("Recommendation: Continue monitoring")
    
#     return "\\n".join(output)

# if __name__ == "__main__":
#     if len(sys.argv) > 1:
#         target = sys.argv[1]
#     else:
#         target = "example.com"
#     result = run_{clean_name}(target)
#     print(result)
# ''')
#         os.chmod(script_path, 0o755)

# Generate PDF report
def generate_pdf_report(scan_result):
    """Generate a PDF report from scan results."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Create custom styles
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=colors.darkblue,
        spaceAfter=12
    )
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.navy,
        spaceAfter=10
    )
    
    normal_style = styles['Normal']
    
    # Build the document content
    content = []
    
    # Title
    content.append(Paragraph(f"SWAPTT Security Scan Report", title_style))
    content.append(Spacer(1, 0.25 * inch))
    
    # Basic information table
    basic_info = [
        ["Tool", scan_result["tool"]],
        ["Target", scan_result["target"]],
        ["Timestamp", scan_result["timestamp"]],
        ["Duration", f"{scan_result['duration']} seconds"],
        ["Risk Level", scan_result["risk_level"].upper()]
    ]
    
    # Create a table for the basic information
    basic_table = Table(basic_info, colWidths=[2*inch, 4*inch])
    basic_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.darkblue),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('BACKGROUND', (1, -1), (1, -1), 
         colors.red if scan_result["risk_level"] == "critical" else
         colors.orange if scan_result["risk_level"] == "high" else
         colors.yellow if scan_result["risk_level"] == "medium" else
         colors.lightgreen if scan_result["risk_level"] == "low" else
         colors.lightblue),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    
    content.append(basic_table)
    content.append(Spacer(1, 0.25 * inch))
    
    # Command executed
    content.append(Paragraph("Command Executed:", subtitle_style))
    content.append(Paragraph(f"<font face='Courier'>{scan_result['command']}</font>", normal_style))
    content.append(Spacer(1, 0.25 * inch))
    
    # Scan output
    content.append(Paragraph("Scan Output:", subtitle_style))
    
    # Format the output text
    output_lines = scan_result["output"].split('\n')
    for line in output_lines:
        if line.startswith('---'):
            content.append(Spacer(1, 0.1 * inch))
        else:
            content.append(Paragraph(f"<font face='Courier'>{line}</font>", normal_style))
    
    content.append(Spacer(1, 0.25 * inch))
    
    # Recommendations
    content.append(Paragraph("Recommendations:", subtitle_style))
    
    if scan_result["risk_level"] == "critical":
        content.append(Paragraph("❗ URGENT: Critical security issues detected. Immediate remediation required!", 
                               ParagraphStyle('Critical', parent=normal_style, textColor=colors.red)))
    elif scan_result["risk_level"] == "high":
        content.append(Paragraph("⚠️ High risk issues found. Prioritize fixing these vulnerabilities.", 
                               ParagraphStyle('High', parent=normal_style, textColor=colors.orange)))
    elif scan_result["risk_level"] == "medium":
        content.append(Paragraph("⚠️ Medium risk issues detected. Plan remediation soon.", 
                               ParagraphStyle('Medium', parent=normal_style, textColor=colors.orange)))
    elif scan_result["risk_level"] == "low":
        content.append(Paragraph("✅ Low risk level. Continue regular security monitoring.", 
                               ParagraphStyle('Low', parent=normal_style, textColor=colors.green)))
    else:
        content.append(Paragraph("ℹ️ Informational scan completed. No significant issues detected.", 
                               ParagraphStyle('Info', parent=normal_style, textColor=colors.blue)))
    
    # Build the PDF
    doc.build(content)
    
    # Get the value from the buffer
    buffer.seek(0)
    return buffer

# Run tool and process output
def run_tool(tool_name, target):
    """Run the selected tool with the provided target."""
    st.session_state.scan_count += 1
    scan_id = f"scan_{st.session_state.scan_count}"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Validate target input
    if not target or target.strip() == "":
        return "Error: Please provide a valid target", "error"
    
    # Sanitize input to prevent command injection
    target = re.sub(r'[;&|<>]', '', target.strip())
    
    # Get tool info
    tool_info = tool_commands.get(tool_name, {"command": "", "script": ""})
    script_path = tool_info["script"]
    
    try:
        # Execute command and capture output
        start_time = time.time()
        
        # Always use the Python script if available
        if script_path and os.path.exists(script_path):
            command = f"python {script_path} {target}"
            process = subprocess.Popen(
                command, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=30)
        else:
            # Fallback to direct command if script doesn't exist
            command = tool_info["command"].format(target=target)
            if platform.system() == "Windows":
                # Adjust command for Windows if needed
                command = command.replace("ping -c", "ping -n")
            
            process = subprocess.Popen(
                command, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=30)
        
        end_time = time.time()
        
        # Generate output
        output = stdout
        if stderr:
            output += f"\n\nErrors/Warnings:\n{stderr}"
        
        # Determine risk level based on keywords in the output
        risk_keywords = {
            "critical": ["critical", "high risk", "urgent", "vulnerability"],
            "high": ["high", "warning", "exposed", "open port"],
            "medium": ["medium", "consider", "potential", "detected"],
            "low": ["low", "secure", "safe", "no.*vulnerability"]
        }
        
        risk_level = "info"
        for level, keywords in risk_keywords.items():
            if any(re.search(keyword, output.lower()) for keyword in keywords):
                risk_level = level
                break
        
        # Store result
        result = {
            "id": scan_id,
            "tool": tool_name,
            "target": target,
            "timestamp": timestamp,
            "duration": round(end_time - start_time, 2),
            "output": output,
            "risk_level": risk_level,
            "command": command
        }
        
        st.session_state.scan_history.append(result)
        
        return output, risk_level
    
    except subprocess.TimeoutExpired:
        return "Command timed out after 30 seconds", "error"
    except Exception as e:
        return f"Error executing command: {str(e)}", "error"

# Make sure all scripts exist when the app starts
ensure_scripts_exist()

# HOME PAGE
if page == "🏠 Home":
    st.title("💻 SWAPTT - Web Application Pentesting Toolkit")
    st.markdown("""
    Welcome to **SWAPTT** — your all-in-one Web Application Pentesting Toolkit! 🛠️  
    Built for security professionals and ethical hackers to streamline reconnaissance, scanning, and exploitation tasks.

    ---
    ### 🚀 Key Features
    - Run ⚙️ automated scripts directly from UI  
    - 🧰 Modular & extensible tool structure  
    - 🧠 Ideal for students, CTF players, and red teamers  
    - 🎯 Fast navigation, emoji-based categories  

    ---
    ### 🔧 What You Can Do
    - 🕵️‍♂️ Recon & Information Gathering  
    - 💉 Exploit testing (SQLi, XSS, LFI)  
    - 🔒 Security analysis (SSL, Headers, Ports)  
    - 🌐 Network enumeration (Nmap, Ping Sweep)

    > **Remember**: Use tools only on targets you're authorized to test!

    ---
    """)
    
    # Quick Start Section
    st.subheader("🚀 Quick Start")
    quick_cols = st.columns(2)
    with quick_cols[0]:
        quick_tool = st.selectbox("Select Tool", 
                                 ["IP Lookup", "WHOIS", "Port Scanner Nmap", "Headers Scanner"])
    with quick_cols[1]:
        quick_target = st.text_input("Target (domain/IP)", "example.com")
    
    if st.button("🚀 Run Quick Scan"):
        with st.spinner(f"Running {quick_tool} on {quick_target}..."):
            output, risk_level = run_tool(quick_tool, quick_target)
            st.session_state.selected_tool = quick_tool
            st.session_state.last_output = output
            st.session_state.last_risk = risk_level
            st.session_state.last_target = quick_target
        
        st.success(f"✅ Scan complete! View results in the Tools section.")
    
    st.markdown("""
    🛡️ Stay secure, hack responsibly.

    📥 Want to contribute? Reach out via [GitHub](https://github.com/) or our [LinkedIn](https://linkedin.com).
    """)

# TOOL PAGE
elif page == "🧰 Tools":
    st.title("🧰 Pentesting Tools")
    
    # Target input section
    st.subheader("🎯 Target Configuration")
    target = st.text_input("Enter Target Domain/IP", "example.com")
    
    # Create tabs for categories
    cat_tabs = st.tabs([cat.split(" ")[1] for cat in tool_categories.keys()])
    
    # Populate each tab with tools
    for i, (category, tools) in enumerate(tool_categories.items()):
        with cat_tabs[i]:
            st.header(category)
            tool_cols = st.columns(3)
            for idx, (tool, emoji) in enumerate(tools.items()):
                with tool_cols[idx % 3]:
                    if st.button(f"{emoji} {tool}", key=f"btn_{tool}"):
                        st.session_state.selected_tool = tool
                        st.session_state.last_target = target
    
    # Tool Output Section
    st.markdown("---")
    if "selected_tool" in st.session_state:
        selected = st.session_state.selected_tool
        st.header(f"📥 Running: {selected}")
        
        # Show progress immediately
        progress_placeholder = st.empty()
        output_placeholder = st.empty()
        viz_placeholder = st.empty()
        
        with progress_placeholder.container():
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Simulate progress while tool runs
            for i in range(1, 101):
                if i < 20:
                    status_text.text("🔍 Initializing scan...")
                elif i < 40:
                    status_text.text("📡 Connecting to target...")
                elif i < 60:
                    status_text.text("⚙️ Processing data...")
                elif i < 80:
                    status_text.text("📊 Analyzing results...")
                else:
                    status_text.text("📝 Preparing report...")
                progress_bar.progress(i)
                time.sleep(0.01)
            
            status_text.text("✅ Scan complete!")
        
        # Run the actual tool
        with st.spinner(f"Running {selected} on {st.session_state.last_target}..."):
            output, risk_level = run_tool(selected, st.session_state.last_target)
            st.session_state.last_output = output
            st.session_state.last_risk = risk_level
        
        # Display the output
        with output_placeholder.container():
            st.subheader("📋 Scan Results")
            
            # Create tabs for output views
            output_tabs = st.tabs(["📝 Raw Output", "📊 Analysis", "📑 Report"])
            
            with output_tabs[0]:
                st.code(output, language="bash")
            
            with output_tabs[1]:
                # Risk Level Gauge
                risk_color = {
                    "critical": "red",
                    "high": "orange", 
                    "medium": "yellow", 
                    "low": "green",
                    "info": "blue",
                    "error": "gray"
                }
                
                risk_value = {
                    "critical": 90,
                    "high": 70, 
                    "medium": 50, 
                    "low": 20,
                    "info": 10,
                    "error": 0
                }
                
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number+delta",
                    value = risk_value.get(risk_level, 0),
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Risk Assessment", 'font': {'size': 24}},
                    gauge = {
                        'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
                        'bar': {'color': risk_color.get(risk_level, "gray")},
                        'bgcolor': "white",
                        'borderwidth': 2,
                        'bordercolor': "gray",
                        'steps': [
                            {'range': [0, 20], 'color': 'green'},
                            {'range': [20, 50], 'color': 'yellow'},
                            {'range': [50, 80], 'color': 'orange'},
                            {'range': [80, 100], 'color': 'red'}],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': risk_value.get(risk_level, 0)}
                    }
                ))
                
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)
                
                # Extract and analyze data (placeholder)
                st.subheader("🔍 Key Findings")
                
                # Extract potentially interesting information based on tool type
                findings = []
                
                if "Port Scanner" in selected or "Nmap" in selected:
                    # Look for open ports
                    open_ports = re.findall(r'(\d+)/tcp\s+open', output)
                    if open_ports:
                        findings.append(f"🔓 Found {len(open_ports)} open ports: {', '.join(open_ports)}")
                
                if "WHOIS" in selected:
                    # Extract registration info
                    registrar = re.search(r'Registrar: (.+)', output)
                    if registrar:
                        findings.append(f"📜 Registrar: {registrar.group(1)}")
                    
                    creation = re.search(r'Creation Date: (.+)', output)
                    if creation:
                        findings.append(f"📅 Creation Date: {creation.group(1)}")
                if "Headers Scanner" in selected:
                    # Extract server info
                    server = re.search(r'Server: (.+)', output)
                    if server:
                        findings.append(f"🖥️ Server: {server.group(1)}")
                        security_headers = [
                            ('X-Frame-Options', '🛡️ X-Frame-Options header is present'),
                            ('X-XSS-Protection', '🛡️ XSS protection is enabled'),
                            ('X-Content-Type-Options', '🛡️ Content sniffing protection is enabled'),
                            ('Content-Security-Policy', '🛡️ Content Security Policy is enabled')
                        ]
                    
                        for header, message in security_headers:
                            if re.search(header, output):
                                findings.append(message)

                elif "SSL/TLS" in selected:
                    # Extract SSL/TLS info
                    cert_expiry = re.search(r'Not After\s*:\s*(.+)', output)
                    if cert_expiry:
                        findings.append(f"🔒 Certificate expires: {cert_expiry.group(1)}")
                    
                    cipher = re.search(r'Cipher\s*:\s*(.+)', output)
                    if cipher:
                        findings.append(f"🔐 Cipher suite: {cipher.group(1)}")

    # Show findings
    if findings:
        for finding in findings:
            st.markdown(finding)
    else:
        st.info("No specific findings extracted from the scan output.")

    with output_tabs[2]:
        # Generate report
        last_scan = st.session_state.scan_history[-1] if st.session_state.scan_history else None
        if last_scan:
            pdf_buffer = generate_pdf_report(last_scan)
            st.download_button(
                label="📥 Download PDF Report",
                data=pdf_buffer,
                file_name=f"SWAPTT_Report_{selected}_{st.session_state.last_target}_{int(time.time())}.pdf",
                mime="application/pdf",
            )
            
            # Show a preview of the report
            st.subheader("Report Preview")
            
            col1, col2 = st.columns([1, 2])
            with col1:
                st.info("Summary")
                st.markdown(f"**Tool:** {last_scan['tool']}")
                st.markdown(f"**Target:** {last_scan['target']}")
                st.markdown(f"**Timestamp:** {last_scan['timestamp']}")
                st.markdown(f"**Duration:** {last_scan['duration']} seconds")
                
                # Risk level badge
                risk_badge = {
                    "critical": "🔴 CRITICAL",
                    "high": "🟠 HIGH",
                    "medium": "🟡 MEDIUM",
                    "low": "🟢 LOW",
                    "info": "🔵 INFO"
                }
                st.markdown(f"**Risk Level:** {risk_badge.get(last_scan['risk_level'], '⚪ UNKNOWN')}")
                
            with col2:
                st.info("Recommendations")
                if last_scan["risk_level"] == "critical":
                    st.error("❗ URGENT: Critical security issues detected. Immediate remediation required!")
                    st.markdown("- 🚨 This target has severe vulnerabilities that require immediate attention")
                    st.markdown("- 🔐 Restrict access to the affected systems until fixed")
                    st.markdown("- 📞 Consider engaging security incident response team")
                elif last_scan["risk_level"] == "high":
                    st.warning("⚠️ High risk issues found. Prioritize fixing these vulnerabilities.")
                    st.markdown("- 🔨 Address these vulnerabilities within the next 7-14 days")
                    st.markdown("- 🔍 Perform additional targeted testing to confirm findings")
                    st.markdown("- 📝 Document remediation steps and timeline")
                elif last_scan["risk_level"] == "medium":
                    st.warning("⚠️ Medium risk issues detected. Plan remediation soon.")
                    st.markdown("- 📅 Schedule fixes within your normal development cycle")
                    st.markdown("- 🧪 Validate after fixing to ensure problems are resolved")
                    st.markdown("- 📊 Monitor for any changes in risk profile")
                elif last_scan["risk_level"] == "low":
                    st.success("✅ Low risk level. Continue regular security monitoring.")
                    st.markdown("- 👍 Good security posture detected")
                    st.markdown("- 🔄 Continue with regular security testing")
                    st.markdown("- 📈 Consider these results as part of overall security program")
                else:
                    st.info("ℹ️ Informational scan completed. No significant issues detected.")
                    st.markdown("- 📋 Use this data as a baseline for future scans")
                    st.markdown("- 🔎 Consider more in-depth testing for critical systems")

    # Show visualization of scan output
    with viz_placeholder.container():
        st.markdown("---")
        st.subheader("📊 Data Visualization")
        
        try:
            # Extract data to visualize based on tool type
            if any(port_tool in selected for port_tool in ["Port Scanner", "Nmap", "Full Scan", "Small Scan"]):
                # Extract port data
                port_data = re.findall(r'Port (\d+)/tcp: (\w+)', output)
                if port_data:
                    ports, statuses = zip(*port_data)
                    port_df = pd.DataFrame({
                        'Port': ports,
                        'Status': statuses
                    })
                    
                    # Create a bar chart of port statuses
                    fig = px.bar(port_df, 
                        x='Port', 
                        y=[1]*len(ports), 
                        color='Status',
                        color_discrete_map={
                            'open': 'red',
                            'closed': 'green',
                            'filtered': 'yellow'
                        },
                        labels={'y': 'Count'},
                        title='Port Scan Results')
                    fig.update_layout(height=400)
                    st.plotly_chart(fig, use_container_width=True)
            
            elif "Headers" in selected:
                # Extract headers and visualize security headers
                header_lines = [line for line in output.split('\n') if ': ' in line]
                if header_lines:
                    headers = {}
                    for line in header_lines:
                        parts = line.split(': ', 1)
                        if len(parts) == 2:
                            headers[parts[0]] = parts[1]
                    
                    security_headers = {
                        'X-Frame-Options': 'Clickjacking Protection',
                        'X-XSS-Protection': 'XSS Protection',
                        'X-Content-Type-Options': 'Content Type Protection',
                        'Content-Security-Policy': 'Content Security',
                        'Strict-Transport-Security': 'HTTPS Enforcement',
                        'Referrer-Policy': 'Referrer Control'
                    }
                    
                    sec_data = []
                    for header, description in security_headers.items():
                        status = 'Present' if any(h for h in headers.keys() if h.lower() == header.lower()) else 'Missing'
                        sec_data.append({
                            'Header': description,
                            'Status': status
                        })
                    
                    sec_df = pd.DataFrame(sec_data)
                    fig = px.bar(sec_df,
                        x='Header',
                        y=[1]*len(sec_data),
                        color='Status',
                        color_discrete_map={
                            'Present': 'green',
                            'Missing': 'red'
                        },
                        title='Security Headers Analysis')
                    fig.update_layout(height=400)
                    st.plotly_chart(fig, use_container_width=True)
            
            elif "SSL/TLS" in selected:
                # Create a gauge chart for SSL rating (simulated)
                cipher_strength = "High" if "TLSv1.3" in output or "TLSv1.2" in output else "Medium" if "TLSv1.1" in output else "Low"
                cert_valid = "Valid" if "Not After" in output and "GMT" in output else "Unknown"
                
                categories = ['Cipher Strength', 'Certificate Validity', 'Protocol Security']
                values = [
                    100 if cipher_strength == "High" else 50 if cipher_strength == "Medium" else 20,
                    100 if cert_valid == "Valid" else 30,
                    80 if "TLSv1.3" in output or "TLSv1.2" in output else 40 if "TLSv1.1" in output else 10
                ]
                
                fig = go.Figure()
                fig.add_trace(go.Scatterpolar(
                    r=values,
                    theta=categories,
                    fill='toself',
                    name='SSL/TLS Security'
                ))
                
                fig.update_layout(
                    polar=dict(
                        radialaxis=dict(
                            visible=True,
                            range=[0, 100]
                        )
                    ),
                    title='SSL/TLS Security Assessment',
                    height=450
                )
                st.plotly_chart(fig, use_container_width=True)
                
            else:
                # Generic visualization for other tools - just show scan count by risk level
                if st.session_state.scan_history:
                    risk_counts = {}
                    for scan in st.session_state.scan_history:
                        risk_level = scan['risk_level']
                        if risk_level not in risk_counts:
                            risk_counts[risk_level] = 0
                        risk_counts[risk_level] += 1
                    
                    risk_df = pd.DataFrame({
                        'Risk Level': list(risk_counts.keys()),
                        'Count': list(risk_counts.values())
                    })
                    
                    fig = px.pie(risk_df, 
                        values='Count', 
                        names='Risk Level',
                        color='Risk Level',
                        color_discrete_map={
                            'critical': 'red',
                            'high': 'orange',
                            'medium': 'yellow',
                            'low': 'green',
                            'info': 'blue',
                            'error': 'gray'
                        },
                        title='Scan History by Risk Level')
                    fig.update_layout(height=400)
                    st.plotly_chart(fig, use_container_width=True)
                    
        except Exception as e:
            st.warning(f"Could not generate visualization: {str(e)}")

# DASHBOARD PAGE
elif page == "📊 Dashboard":
    st.title("📊 Security Dashboard")
    
    if not st.session_state.scan_history:
        st.info("⚠️ No scan data available yet. Run some tools to populate the dashboard.")
    else:
        # Dashboard statistics
        stats_col1, stats_col2, stats_col3, stats_col4 = st.columns(4)
        
        with stats_col1:
            st.metric("Total Scans", len(st.session_state.scan_history))
        
        with stats_col2:
            unique_targets = len(set(scan['target'] for scan in st.session_state.scan_history))
            st.metric("Unique Targets", unique_targets)
        
        with stats_col3:
            high_risks = sum(1 for scan in st.session_state.scan_history if scan['risk_level'] in ['critical', 'high'])
            st.metric("High Risk Findings", high_risks)
        
        with stats_col4:
            avg_duration = sum(scan['duration'] for scan in st.session_state.scan_history) / len(st.session_state.scan_history)
            st.metric("Avg. Scan Duration", f"{avg_duration:.2f}s")
        
        st.markdown("---")
        
        # Risk distribution
        st.subheader("📈 Risk Distribution")
        risk_df = pd.DataFrame([scan['risk_level'] for scan in st.session_state.scan_history], columns=['Risk Level'])
        risk_counts = risk_df['Risk Level'].value_counts().reset_index()
        risk_counts.columns = ['Risk Level', 'Count']
        
        risk_order = ['critical', 'high', 'medium', 'low', 'info', 'error']
        risk_counts['Risk Level'] = pd.Categorical(risk_counts['Risk Level'], categories=risk_order, ordered=True)
        risk_counts = risk_counts.sort_values('Risk Level')
        
        risk_fig = px.bar(
            risk_counts, 
            x='Risk Level', 
            y='Count',
            color='Risk Level',
            color_discrete_map={
                'critical': 'red',
                'high': 'orange',
                'medium': 'yellow',
                'low': 'green',
                'info': 'blue',
                'error': 'gray'
            },
            title='Distribution of Risk Levels'
        )
        st.plotly_chart(risk_fig, use_container_width=True)
        
        st.markdown("---")
        
        # Tool usage breakdown
        st.subheader("🧰 Tool Usage")
        tool_df = pd.DataFrame([scan['tool'] for scan in st.session_state.scan_history], columns=['Tool'])
        tool_counts = tool_df['Tool'].value_counts().reset_index()
        tool_counts.columns = ['Tool', 'Usage Count']
        
        tool_fig = px.pie(
            tool_counts,
            values='Usage Count',
            names='Tool',
            title='Tool Usage Distribution'
        )
        st.plotly_chart(tool_fig, use_container_width=True)
        
        st.markdown("---")
        
        # Risk timeline
        st.subheader("⏳ Risk Timeline")
        timeline_data = [{
            'Timestamp': datetime.strptime(scan['timestamp'], "%Y-%m-%d %H:%M:%S"),
            'Risk Level': scan['risk_level'],
            'Tool': scan['tool'],
            'Target': scan['target']
        } for scan in st.session_state.scan_history]
        
        timeline_df = pd.DataFrame(timeline_data)
        
        if not timeline_df.empty:
            timeline_fig = px.scatter(
                timeline_df,
                x='Timestamp',
                y='Risk Level',
                color='Risk Level',
                hover_data=['Tool', 'Target'],
                color_discrete_map={
                    'critical': 'red',
                    'high': 'orange',
                    'medium': 'yellow',
                    'low': 'green',
                    'info': 'blue',
                    'error': 'gray'
                },
                title='Risk Timeline'
            )
            timeline_fig.update_yaxes(
                categoryorder='array', 
                categoryarray=['error', 'info', 'low', 'medium', 'high', 'critical']
            )
            st.plotly_chart(timeline_fig, use_container_width=True)
        
        st.markdown("---")
        
        # Recent scans table
        st.subheader("📋 Recent Scans")
        recent_scans = st.session_state.scan_history[-10:] if len(st.session_state.scan_history) > 10 else st.session_state.scan_history
        recent_scans = list(reversed(recent_scans))  # Most recent first
        
        for i, scan in enumerate(recent_scans):
            with st.expander(f"{scan['timestamp']} - {scan['tool']} on {scan['target']}"):
                st.markdown(f"""
                **Risk Level:** {scan['risk_level'].upper()}  
                **Duration:** {scan['duration']} seconds  
                **Command:** `{scan['command']}`
                """)
                
                st.code(scan['output'], language="bash")
                
                # Generate report button for each scan
                pdf_buffer = generate_pdf_report(scan)
                st.download_button(
                    label="📥 Download PDF Report",
                    data=pdf_buffer,
                    file_name=f"SWAPTT_Report_{scan['tool']}_{scan['target']}_{int(time.time())}.pdf",
                    mime="application/pdf",
                    key=f"btn_download_{i}"
                )
        
        st.markdown("---")
        
        # Clear history button
        if st.button("🗑️ Clear Scan History"):
            st.session_state.scan_history = []
            st.session_state.scan_count = 0
            st.success("Scan history cleared!")
            st.experimental_rerun()

# CONTACT PAGE
elif page == "📞 Contact":
    st.title("📞 Contact & About")
    
    st.markdown("""
    ## About SWAPTT
    
    **SWAPTT** (Streamlit Web Application Pentesting Toolkit) is an open-source project designed to help security professionals, ethical hackers, and cybersecurity students practice and learn about web application security testing.
    
    ### 🚫 Disclaimer
    
    This tool is intended for **educational purposes** and **authorized security testing only**. Always ensure you have proper permission before testing any target. Unauthorized security testing is illegal and unethical.
    
    ### 👥 Contributors
    
    - Security Researcher
    - Web Developer
    - Ethical Hacker
    
    ### 🔄 Version History
    
    - **v1.0.0** - Initial release with basic scanning capabilities
    - **v1.1.0** - Added PDF report generation
    - **v1.2.0** - Added data visualization
    
    ### 📧 Contact
    
    Need help or want to contribute? Reach out!
    """)
    
    # Contact Form
    st.subheader("📝 Contact Form")
    
    contact_cols = st.columns(2)
    with contact_cols[0]:
        name = st.text_input("Name")
        email = st.text_input("Email")
    
    with contact_cols[1]:
        subject = st.text_input("Subject")
        category = st.selectbox("Category", ["Question", "Bug Report", "Feature Request", "Contribution"])
    
    message = st.text_area("Message")
    
    if st.button("📤 Send Message"):
        if name and email and subject and message:
            st.success("Thank you for your message! We'll get back to you soon.")
            # In a real app, you would process the form data here
        else:
            st.error("Please fill in all required fields.")
    
    # FAQ Section
    st.subheader("❓ Frequently Asked Questions")
    
    faq_data = [
        ("Is SWAPTT free to use?", "Yes, SWAPTT is completely free and open-source."),
        ("Can I contribute to the project?", "Absolutely! We welcome contributions via GitHub."),
        ("How do I report bugs?", "You can report bugs through our GitHub issues page or using the contact form above."),
        ("Is SWAPTT legal to use?", "SWAPTT itself is legal, but you must ensure you have permission to test any target."),
        ("What if a tool doesn't work?", "Check your internet connection and target accessibility. Some tools may require specific system dependencies.")
    ]
    
    for question, answer in faq_data:
        with st.expander(question):
            st.write(answer)
            
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center;">
        <p>© 2025 SWAPTT - Made with ❤️ for the Security Community</p>
    </div>
    """, unsafe_allow_html=True)

# Add a floating help button
with st.sidebar.expander("❓ Help & Tips"):
    st.markdown("""
    ### Quick Tips
    
    1. **Target Format**: Use domain names (example.com) or IP addresses (192.168.1.1)
    2. **Tool Selection**: Hover over tool buttons to see what they do
    3. **Reports**: Download PDF reports for documentation
    4. **Dashboard**: Track your testing progress over time
    
    ### Common Issues
    
    - **Connection Errors**: Verify target is online and accessible
    - **Slow Response**: Some tools may take longer for comprehensive results
    - **No Output**: Try a different tool or check your input format
    """)

# Display scan count in sidebar
st.sidebar.markdown(f"**Scans Performed**: {st.session_state.scan_count}")

# Add a sidebar section with resources
with st.sidebar.expander("📚 Resources"):
    st.markdown("""
    - [OWASP Top 10](https://owasp.org/www-project-top-ten/)
    - [Web Security Academy](https://portswigger.net/web-security)
    - [HackerOne](https://www.hackerone.com/vulnerability-and-security-testing-education)
    """)

# Version information
st.sidebar.markdown("---")
st.sidebar.markdown("**Version**: 1.2.0")
st.sidebar.markdown("**Last Updated**: April 2025")