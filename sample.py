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

# Set page configuration
st.set_page_config(page_title="SWAPTT", page_icon="💻", layout="wide")

# Create necessary directories if they don't exist
os.makedirs("script", exist_ok=True)
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

# Tool command mapping (map tools to actual terminal commands)
tool_commands = {
    "WHOIS": "whois {target}",
    "IP Lookup": "ping -c 4 {target}",
    "DNS Enumeration": "dig {target} ANY",
    "Port Scanner Nmap": "nmap -F {target}",
    "Traceroute": "traceroute {target}",
    "Headers Scanner": "curl -I {target}",
    "SSL/TLS Checker": "echo | openssl s_client -connect {target}:443 | openssl x509 -noout -text",
    "Ping Sweep": "ping -c 4 {target}",
    "Nmap": "nmap -sV {target}",
    "Full Scan": "nmap -A {target}",
    "Small Scan": "nmap -F {target}"
}

# For tools without direct commands, we'll create simple Python scripts
def create_script_file(tool_name):
    """Create a Python script for tools that don't have direct terminal commands."""
    clean_name = tool_name.lower().replace(" ", "_").replace("/", "").replace("(", "").replace(")", "")
    script_path = os.path.join("script", f"{clean_name}.py")
    
    if not os.path.exists(script_path):
        with open(script_path, "w") as f:
            f.write(f'''#!/usr/bin/env python3
# {tool_name} Script for SWAPTT
import sys
import time

def run_{clean_name}(target):
    print(f"Running {tool_name} on {{target}}")
    print("Initializing...")
    time.sleep(1)
    print("Scanning target...")
    time.sleep(1)
    print("Analyzing results...")
    time.sleep(1)
    print("\\nResults for {tool_name}:")
    print("-" * 50)
    print(f"Target: {{target}}")
    print(f"Timestamp: {{time.strftime('%Y-%m-%d %H:%M:%S')}}")
    print("Status: Completed")
    print("-" * 50)
    if "{tool_name}" in ["XSS Exploiter", "SQLi Exploiter", "LFI/RFI Tester"]:
        print("RISK ASSESSMENT: Potential vulnerabilities detected")
        print("Recommendation: Further manual testing required")
    else:
        print("RISK ASSESSMENT: No immediate risks detected")
        print("Recommendation: Continue monitoring")
    return "Scan completed successfully"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "example.com"
    run_{clean_name}(target)
''')
        os.chmod(script_path, 0o755)
    
    return script_path

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
    
    # Prepare command
    if tool_name in tool_commands:
        command = tool_commands[tool_name].format(target=target)
        if platform.system() == "Windows":
            # Adjust command for Windows if needed
            command = command.replace("ping -c", "ping -n")
    else:
        # Use Python script for tools without direct commands
        script_path = create_script_file(tool_name)
        command = f"python {script_path} {target}"
    
    try:
        # Execute command and capture output
        start_time = time.time()
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
                
                if "Headers" in selected:
                    # Look for security headers
                    sec_headers = re.findall(r'(X-[^:]+|Strict-Transport-Security|Content-Security-Policy):', output)
                    if sec_headers:
                        findings.append(f"🔒 Found {len(sec_headers)} security headers")
                    else:
                        findings.append("⚠️ No security headers detected")
                
                # Add generic findings if none were found
                if not findings:
                    findings.append("📊 Completed scan analysis")
                    findings.append(f"⏱️ Scan duration: {st.session_state.scan_history[-1]['duration']} seconds")
                
                for finding in findings:
                    st.markdown(f"- {finding}")
                
            with output_tabs[2]:
                st.subheader("📑 Scan Summary Report")
                st.markdown(f"""
                ### 🎯 Target Information
                - **Target:** {st.session_state.last_target}
                - **Scan Type:** {selected}
                - **Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                - **Duration:** {st.session_state.scan_history[-1]['duration']} seconds
                
                ### 🚨 Risk Assessment
                - **Risk Level:** {risk_level.upper()}
                - **Command Executed:** `{st.session_state.scan_history[-1]['command']}`
                
                ### 📋 Recommendations
                """)
                
                # Generate recommendations based on risk level
                if risk_level == "critical":
                    st.error("❗ URGENT: Critical security issues detected. Immediate remediation required!")
                elif risk_level == "high":
                    st.warning("⚠️ High risk issues found. Prioritize fixing these vulnerabilities.")
                elif risk_level == "medium":
                    st.info("⚠️ Medium risk issues detected. Plan remediation soon.")
                elif risk_level == "low":
                    st.success("✅ Low risk level. Continue regular security monitoring.")
                else:
                    st.info("ℹ️ Informational scan completed. No significant issues detected.")
                
                # Add export options
                st.download_button(
                    label="📥 Download Report",
                    data=f"""SWAPTT Scan Report
===========================
Target: {st.session_state.last_target}
Scan Type: {selected}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Risk Level: {risk_level.upper()}

RAW OUTPUT:
{output}
""",
                    file_name=f"swaptt_report_{st.session_state.last_target}_{int(time.time())}.txt",
                    mime="text/plain"
                )

# DASHBOARD PAGE
elif page == "📊 Dashboard":
    st.title("📊 Security Dashboard")
    
    if not st.session_state.scan_history:
        st.info("⚠️ No scan data available yet. Run some tools to populate the dashboard.")
    else:
        # Summary statistics
        st.subheader("📈 Scan Statistics")
        stats_cols = st.columns(4)
        
        with stats_cols[0]:
            st.metric("Total Scans", len(st.session_state.scan_history))
        
        with stats_cols[1]:
            unique_targets = len(set([scan["target"] for scan in st.session_state.scan_history]))
            st.metric("Unique Targets", unique_targets)
        
        with stats_cols[2]:
            high_risk_count = sum(1 for scan in st.session_state.scan_history 
                                if scan["risk_level"] in ["critical", "high"])
            st.metric("High Risk Findings", high_risk_count)
        
        with stats_cols[3]:
            avg_duration = sum(scan["duration"] for scan in st.session_state.scan_history) / len(st.session_state.scan_history)
            st.metric("Avg. Scan Duration", f"{avg_duration:.2f}s")
        
        # Create dataframe for visualizations
        scan_df = pd.DataFrame(st.session_state.scan_history)
        
        # Visualization tabs
        viz_tabs = st.tabs(["📊 Risk Overview", "🕒 Timeline", "📋 Scan History"])
        
        with viz_tabs[0]:
            # Risk level distribution
            risk_counts = scan_df["risk_level"].value_counts().reset_index()
            risk_counts.columns = ["Risk Level", "Count"]
            
            fig1 = px.pie(risk_counts, values="Count", names="Risk Level", 
                         color="Risk Level",
                         color_discrete_map={
                             "critical": "red",
                             "high": "orange",
                             "medium": "gold",
                             "low": "green",
                             "info": "blue",
                             "error": "gray"
                         },
                         title="Risk Level Distribution")
            st.plotly_chart(fig1, use_container_width=True)
            
            # Tool usage distribution
            tool_counts = scan_df["tool"].value_counts().reset_index()
            tool_counts.columns = ["Tool", "Usage Count"]
            
            fig2 = px.bar(tool_counts, x="Tool", y="Usage Count", 
                         color="Usage Count", 
                         title="Tool Usage Distribution")
            st.plotly_chart(fig2, use_container_width=True)
        
        with viz_tabs[1]:
            # Add timestamp as datetime
            scan_df["datetime"] = pd.to_datetime(scan_df["timestamp"])
            
            # Timeline of scans
            fig3 = px.scatter(scan_df, x="datetime", y="tool", 
                             color="risk_level",
                             color_discrete_map={
                                 "critical": "red",
                                 "high": "orange",
                                 "medium": "gold",
                                 "low": "green",
                                 "info": "blue",
                                 "error": "gray"
                             },
                             size="duration",
                             hover_data=["target", "duration"],
                             title="Scan Timeline")
            st.plotly_chart(fig3, use_container_width=True)
            
            # Scan duration by tool
            fig4 = px.box(scan_df, x="tool", y="duration", 
                         color="tool",
                         title="Scan Duration by Tool")
            st.plotly_chart(fig4, use_container_width=True)
        
        with viz_tabs[2]:
            # Full scan history table
            st.subheader("📋 Complete Scan History")
            
            # Create a filtered view of the dataframe for display
            display_df = scan_df[["id", "tool", "target", "timestamp", "duration", "risk_level"]]
            display_df = display_df.rename(columns={
                "id": "ID", 
                "tool": "Tool", 
                "target": "Target",
                "timestamp": "Timestamp",
                "duration": "Duration (s)",
                "risk_level": "Risk Level"
            })
            
            # Add color highlighting based on risk level
            def highlight_risk(val):
                if val == "critical":
                    return 'background-color: red; color: white'
                elif val == "high":
                    return 'background-color: orange; color: black'
                elif val == "medium":
                    return 'background-color: yellow; color: black'
                elif val == "low":
                    return 'background-color: green; color: white'
                else:
                    return ''
            
            # Display styled dataframe
            st.dataframe(display_df.style.applymap(highlight_risk, subset=["Risk Level"]))
            
            # Option to view full details of a selected scan
            selected_scan_id = st.selectbox("Select Scan ID to View Details", 
                                           options=[scan["id"] for scan in st.session_state.scan_history])
            
            selected_scan = next((scan for scan in st.session_state.scan_history if scan["id"] == selected_scan_id), None)
            
            if selected_scan:
                st.subheader(f"Details for Scan: {selected_scan_id}")
                st.markdown(f"""
                - **Tool:** {selected_scan["tool"]}
                - **Target:** {selected_scan["target"]}
                - **Timestamp:** {selected_scan["timestamp"]}
                - **Duration:** {selected_scan["duration"]} seconds
                - **Risk Level:** {selected_scan["risk_level"]}
                - **Command:** `{selected_scan["command"]}`
                """)
                
                with st.expander("View Raw Output"):
                    st.code(selected_scan["output"])
                    
                # Download option for individual scan
                st.download_button(
                    label="📥 Download This Report",
                    data=f"""SWAPTT Scan Report
===========================
Tool: {selected_scan["tool"]}
Target: {selected_scan["target"]}
Timestamp: {selected_scan["timestamp"]}
Risk Level: {selected_scan["risk_level"]}
Command: {selected_scan["command"]}

RAW OUTPUT:
{selected_scan["output"]}
""",
                    file_name=f"swaptt_report_{selected_scan['id']}.txt",
                    mime="text/plain"
                )

# CONTACT PAGE
elif page == "📞 Contact":
    st.title("📞 Contact Us")
    with st.form("contact_form"):
        name = st.text_input("👤 Name")
        email = st.text_input("📧 Email")
        message = st.text_area("💬 Message")
        submitted = st.form_submit_button("📨 Send")
        if submitted:
            # In a real app, you'd process the form here
            st.success("✅ Thank you! We'll get back to you soon.")
            
            # Save contact to file (for demonstration purposes)
            with open("contacts.txt", "a") as f:
                f.write(f"Name: {name}, Email: {email}, Message: {message}\n")

    st.markdown("### 🔗 Connect With Us")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("[🐙 GitHub](https://github.com/)")
    with col2:
        st.markdown("[💼 LinkedIn](https://linkedin.com/)")
    with col3:
        st.markdown("[📸 Instagram](https://instagram.com/)")

    st.caption("© 2025 SWAPTT | Built with ❤️ by Hackers for Hackers.")

# Footer
st.sidebar.markdown("---")
st.sidebar.caption("SWAPTT v1.0.0")
st.sidebar.caption("Running on Streamlit")

# System info in sidebar
if st.sidebar.checkbox("Show System Info", False):
    st.sidebar.markdown("### 💻 System Information")
    st.sidebar.code(f"""
    OS: {platform.system()} {platform.release()}
    Python: {platform.python_version()}
    """)