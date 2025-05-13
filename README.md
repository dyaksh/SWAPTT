````markdown
# 🛡️ SWAPT - Streamlit Web Application Penetration Testing Tool

**SWAPT** is a lightweight, modular **Web Application Penetration Testing** tool built using **Python** and **Streamlit**. It allows users to perform security scans on websites through an interactive interface and modular backend.

---

## 🚀 Features

- 🔍 **URL-Based Scanning**: Enter a URL and launch automated recon and vulnerability testing.
- 🧱 **Modular Design**: Run individual or batch vulnerability tests using:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Command Injection
  - LFI/RFI
  - Subdomain Takeover
  - WHOIS, DNS Recon, etc.
- 🛠️ **Scan Modes**: Choose from Full Scan or Targeted Scan.
- 🌐 **Web Reconnaissance**: Identify headers, open ports, SSL issues, technologies used, and more.
- 📊 **Streamlit UI**: Real-time results in a clean, easy-to-use web interface.

---

## 📁 Project Structure

```bash
SWAPT/
│
├── app.py                  # Main Streamlit interface
├── requirements.txt        # Python dependencies
├── assets/                 # Logos and other UI elements
├── script/                 # Core vulnerability scanning modules
├── scripts/                # Additional/legacy modules
├── README.md               # Project documentation
└── __pycache__/            # Python bytecode (ignored in version control)
````

---

## ⚙️ Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/dyaksh/SWAPTT.git
   cd SWAPTT
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Streamlit app**

   ```bash
   streamlit run app.py
   ```

---

## 📚 Module Highlights

| Module Name            | Description                            |
| ---------------------- | -------------------------------------- |
| `sql_injection.py`     | Detects SQL injection vulnerabilities  |
| `xss_exploiter.py`     | Tests for Cross-Site Scripting (XSS)   |
| `command_injection.py` | Attempts OS command injections         |
| `lfi_rfi_tester.py`    | Tests for Local/Remote File Inclusions |
| `subdomain_finder.py`  | Finds possible subdomains              |
| `ssl_checker.py`       | Checks SSL/TLS health                  |
| `nmap.py`              | Performs port scanning                 |
| `ip_lookup.py`         | Retrieves IP and location info         |
| `builtwith.py`         | Identifies technology stack            |



## ✅ Roadmap

* [ ] Export scan reports to PDF
* [ ] Add login-based access control
* [ ] Dockerize for deployment
* [ ] Add automated unit tests
* [ ] CI/CD integration

---

## 🤝 Contributing

Contributions are welcome!
Feel free to fork this repository and submit a pull request.
For major changes, open an issue first to discuss.

---

## 📄 License

This project is licensed under the **MIT License**. See the [`LICENSE`](LICENSE) file for details.

---

## 🌐 Project Link

🔗 GitHub: [https://github.com/dyaksh/SWAPTT](https://github.com/dyaksh/SWAPTT)

````
