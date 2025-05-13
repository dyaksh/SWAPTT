import streamlit as st
from PIL import Image
import subprocess
import os
import matplotlib.pyplot as plt

# Set page configuration
st.set_page_config(page_title="SWAPTT", page_icon="💻", layout="wide")

# Load and resize logo in sidebar
logo = Image.open("logo.png")
st.sidebar.image(logo, width=150)

# Sidebar Navigation
page = st.sidebar.radio("🔎 Navigate", ["🏠 Home", "🧰 Tools", "📞 Contact"])

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

    > **Remember**: Use tools only on targets you’re authorized to test!

    ---
    🛡️ Stay secure, hack responsibly.

    📥 Want to contribute? Reach out via [GitHub](https://github.com/) or our [LinkedIn](https://linkedin.com).
    """)

# TOOL PAGE
elif page == "🧰 Tools":
    st.title("🧰 Pentesting Tools")

    for category, tools in tool_categories.items():
        st.subheader(category)
        cols = st.columns(3)
        for idx, (tool, emoji) in enumerate(tools.items()):
            with cols[idx % 3]:
                if st.button(f"{emoji} {tool}", key=tool):
                    st.session_state.selected_tool = tool
        st.markdown("---")

    # Tool Output Section with Dashboard
    if "selected_tool" in st.session_state:
        selected = st.session_state.selected_tool
        st.header(f"📥 Output: {selected}")

        # Generate the script file name by cleaning the tool name
        tool_script = selected.lower().replace(" ", "_").replace("/", "").replace("(", "").replace(")", "") + ".py"
        script_path = os.path.join("script", tool_script)

        # Check if the script exists
        if os.path.exists(script_path):
            try:
                # Run the script and capture its output
                output = subprocess.getoutput(f"python3 {script_path}")
                
                # Display the output in a code block (bash or general)
                st.code(output, language="bash")

                # Display risk level based on the output (you can adjust the logic here)
                risk_level = "Low" if "safe" in output else "High"
                st.markdown(f"### ⚠️ Risk Level: {risk_level}")

                # Display statistics or additional visualizations (e.g., graphs or charts)
                st.markdown("### 📊 Visualization")
                
                # Example: You can create a sample plot or chart based on the output
                if "safe" in output:
                    fig, ax = plt.subplots()
                    ax.barh(["Safe"], [100], color="green")
                else:
                    fig, ax = plt.subplots()
                    ax.barh(["High Risk"], [100], color="red")
                
                st.pyplot(fig)

                # You can add further interactive elements here if needed

            except Exception as e:
                st.error(f"❌ Error running {tool_script}: {e}")
        else:
            st.warning(f"⚠️ Script `{tool_script}` not found in `/script/`. Please add it.")

# CONTACT PAGE
elif page == "📞 Contact":
    st.title("📞 Contact Us")
    with st.form("contact_form"):
        name = st.text_input("👤 Name")
        email = st.text_input("📧 Email")
        message = st.text_area("💬 Message")
        submitted = st.form_submit_button("📨 Send")
        if submitted:
            st.success("✅ Thank you! We’ll get back to you soon.")

    st.markdown("### 🔗 Connect With Us")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("[🐙 GitHub](https://github.com/)")
    with col2:
        st.markdown("[💼 LinkedIn](https://linkedin.com/)")
    with col3:
        st.markdown("[📸 Instagram](https://instagram.com/)")

    st.caption("© 2025 SWAPTT | Built with ❤️ by Hackers for Hackers.")
