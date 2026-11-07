# Advanced Cyber Security Toolkit

A Python desktop toolkit for **authorized defensive security testing, system checks, and security monitoring**. The repository also includes related learning projects for malware analysis and SOC workflows.

![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-informational)
![Focus](https://img.shields.io/badge/Focus-Defensive%20Security-blue)

## Features

- Network utilities: port scanner, ping scanner, DNS lookup, WHOIS lookup
- Web checks: HTTP checker, security headers checker, vulnerability scanner
- Monitoring: packet capture, log analyzer, basic IDS
- File integrity baseline and verification
- Password strength checker, hash generation, and verification
- SQLite history and security reports
- Related projects: [AI Malware Analyzer](AI_Malware_Analyzer/PROJECT_REPORT.md) and [Mini-SOC Workbench](Mini_SOC_Workbench/README.md)

## Screenshots

The following images are committed in the `screenshots/` folder.

### Main application
![Advanced Cyber Security Toolkit main GUI](screenshots/main_gui.png)

### Log analysis and IDS
![Log Analyzer and IDS](screenshots/log_analyzer_ids.png)

### Vulnerability scanner
![Vulnerability Scanner](screenshots/vulnerability_scanner.png)

### Database history
![Database History](screenshots/database_history.png)

## Requirements

- Python 3.x
- Tkinter (usually included with standard Windows Python; Linux may require a separate Tk package)
- SQLite (included with Python)
- Install any third-party dependencies listed in `requirements.txt`

## Installation

Clone the repository:

```bash
git clone https://github.com/Nitesh715/Advanced-Cyber-Security-Toolkit.git
cd Advanced-Cyber-Security-Toolkit
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Start the desktop interface (from the repository root):

```bash
python gui.py
```

If the project entry point or dependency setup differs in your local copy, follow the current source files and `requirements.txt`.

## Typical workflow

1. Launch the GUI.
2. Select the tool you need.
3. Enter only a target or file you own or are authorized to assess.
4. Run the check and review the result.
5. Save and inspect the generated report or database history.

## Repository layout

```text
.
├── gui.py
├── database.py
├── scanner.py
├── ping_scanner.py
├── packet_sniffer.py
├── vulnerability_scanner.py
├── log_analyzer.py
├── ids.py
├── dns_lookup.py
├── whois_lookup.py
├── http_checker.py
├── file_integrity.py
├── password_hash.py
├── screenshots/
├── AI_Malware_Analyzer/
└── Mini_SOC_Workbench/
```

This is a representative overview; see the repository tree for the complete file list.

## Responsible use

This toolkit is intended for education and authorized defensive testing only.

- Scan only systems and networks you own or have explicit permission to test.
- Do not use packet capture or monitoring against networks without authorization.
- Do not commit passwords, tokens, private logs, or personal information.
- Treat scanner output as an indicator for investigation, not proof of a vulnerability.

## Related documentation

- [AI Malware Analyzer project report](AI_Malware_Analyzer/PROJECT_REPORT.md)
- [Mini-SOC Workbench documentation](Mini_SOC_Workbench/README.md)
