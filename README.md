# AutoVulnScanner 🔍🛡️

A multi-tool vulnerability and malware scanner with an easy-to-use GUI.  
Combines network scanning, web vulnerability detection, WHOIS lookup, and malware scanning powered by YARA & VirusTotal.

---

## Features

- **Network Scanning**: Nmap, Nikto, SQLMap integration  
- **WHOIS Lookup** for domain intelligence  
- **Malware Detection** using YARA rules and VirusTotal API  
- **Export Reports** in TXT, CSV, or PDF formats  
- **Quarantine suspicious files** automatically  
- **Multi-threaded scanning** for faster results  
- **Flexible GUI** with selectable tools and save options  

---


## Installation

1. Clone this repo:

git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME

2. Install dependencies:

pip install -r requirements.txt
Make sure you have Nmap and Nikto installed on your system.

3. Configure your VirusTotal API key:

Edit the VIRUSTOTAL_API_KEY variable in the main script or set it as an environment variable.

Usage

Run the GUI application:

python3 gui_app.py

Browse and select the target directory or enter a domain/IP
Select desired tools via checkboxes
Click Run Scan
When scan completes, save your report in your preferred format

Project Structure

Autovulnscanner/
├── gui_app.py            # Main GUI application
├── main.py               # Core scanner logic
├── scanners/             # Individual scanner modules (nmap, nikto, sqlmap, whois)
├── reports/              # Report exporting utilities
├── quarantine/           # Quarantine folder for suspicious files
├── rules.yar             # YARA rules file
├── requirements.txt      # Python dependencies
└── README.md


Contributing

Contributions, issues, and feature requests are welcome!
Feel free to fork the repo and submit pull requests.

License
This project is licensed under the MIT License.

Acknowledgements:

Nmap
Nikto
SQLMap
YARA
VirusTotal API
ReportLab
