# 🔎 CyberRecon

> A modular Python reconnaissance framework for authorized security assessments and cybersecurity research.

CyberRecon is a modular reconnaissance framework designed to organize and automate common information-gathering tasks used during authorized security assessments.

The project provides a structured command-line interface that brings multiple reconnaissance capabilities together under a single framework.

---

## 🚀 Features

- 🔌 Modular reconnaissance architecture
- 🐍 Python-based
- 💻 Command-line interface
- 🔍 TCP port scanning
- 🧩 Service detection
- 🛠️ Technology fingerprinting
- 🌐 HTTP reconnaissance
- 📡 DNS reconnaissance
- 🌎 Subdomain enumeration
- 🔗 Endpoint enumeration
- 🛡️ Vulnerability scanning
- 📊 Reconnaissance reporting
- 🧱 Extensible module structure
- 🔐 Designed for authorized security testing and research

---

## 🧰 Reconnaissance Modules

| Module | Description |
|---|---|
| Port Scanner | Discovers accessible TCP ports on a target |
| Service Detection | Identifies services associated with discovered ports |
| Technology Fingerprinting | Attempts to identify technologies used by a target |
| HTTP Recon | Collects HTTP-related reconnaissance information |
| DNS Recon | Performs DNS information gathering |
| Subdomain Enumeration | Discovers subdomains associated with a domain |
| Endpoint Enumeration | Identifies accessible web endpoints |
| Vulnerability Scanner | Performs vulnerability-oriented reconnaissance checks |
| Report | Handles reconnaissance result reporting |

---

## 📁 Project Structure

```text
CyberRecon/
│
├── main.py
├── __init__.py
├── .gitignore
├── README.md
│
└── modules/
    ├── __init__.py
    │
    ├── scanner.py
    ├── port_scanner.py
    │
    ├── service_detection.py
    ├── service_detect.py
    ├── service.py
    │
    ├── fingerprint.py
    ├── tech_fingerprint.py
    │
    ├── http_recon.py
    │
    ├── dns_recon.py
    │
    ├── subdomain_enum.py
    ├── subdomain_recon.py
    │
    ├── endpoint.py
    ├── endpoint_enum.py
    │
    ├── resolver.py
    ├── target.py
    ├── validator.py
    │
    ├── vulnerability.py
    │
    └── report.py


----------------------
⚙️ Installation

Clone the repository:

git clone https://github.com/ashwakarthik/Cyber-Recon.git
cd Cyber-Recon

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

----------------------
▶️ Usage

Run the framework:

python3 main.py

python3 main.py --help


==================================================
           ASHWA CYBERRECON
         Reconnaissance Framework
==================================================

1. Port Scanner
2. Service Detection
3. Fingerprinting
4. HTTP Recon
5. DNS Recon
6. Subdomain Enumeration
7. Endpoint Enumeration
8. Full Recon
9. Vulnerability Scanner
10. Save Report
0. Exit

==================================================
---

## 🔐 Authorization & Responsible Use

CyberRecon is intended only for systems and environments where you have
explicit authorization to perform security testing.

Use this framework responsibly and only within the scope of your
authorized security assessment.

Do not use CyberRecon to:

- Scan systems without permission
- Access unauthorized networks or services
- Circumvent security controls
- Disrupt or degrade services
- Perform unauthorized vulnerability testing

The user is responsible for complying with all applicable laws,
regulations, and authorization requirements.

---

## 🧪 Project Status

CyberRecon is currently under active development.

### Current Capabilities

- [x] Modular CLI framework
- [x] TCP port scanning
- [x] Service detection
- [x] Technology fingerprinting
- [x] HTTP reconnaissance
- [x] DNS reconnaissance
- [x] Subdomain enumeration
- [x] Endpoint enumeration
- [x] Vulnerability scanning
- [x] Full reconnaissance workflow
- [x] Basic reporting support

### In Development

- [ ] Centralized result management
- [ ] Improved logging
- [ ] Configuration management
- [ ] Structured JSON reports
- [ ] HTML report generation
- [ ] Improved CLI argument handling
- [ ] Automated testing

---

## 🗺️ Roadmap

### Phase 1 — Core Framework
- [x] Modular project structure
- [x] Interactive CLI
- [x] Port scanning
- [x] Service detection

### Phase 2 — Reconnaissance
- [x] HTTP reconnaissance
- [x] DNS reconnaissance
- [x] Subdomain enumeration
- [x] Endpoint enumeration
- [x] Technology fingerprinting

### Phase 3 — Security Analysis
- [x] Vulnerability scanning
- [ ] Improved vulnerability checks
- [ ] Finding severity classification
- [ ] Finding metadata

### Phase 4 — Reporting
- [ ] JSON reports
- [ ] HTML reports
- [ ] Recon session management
- [ ] Centralized result storage

---

## 🤝 Contributing

Contributions and suggestions are welcome.

When contributing:

1. Keep modules focused on a specific responsibility.
2. Follow consistent Python coding practices.
3. Document new functionality.
4. Avoid breaking existing modules.
5. Test changes in an authorized environment.

---

## 📜 License

License information will be added as the project develops.

---

## 👤 Author

**Ashwa Karthik**

Cybersecurity • Ethical Hacking • Python Development

---

⭐ If you find CyberRecon useful for cybersecurity learning or authorized
security research, consider starring the repository.
