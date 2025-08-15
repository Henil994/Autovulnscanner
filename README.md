# 🔍 Autovulnscanner
**Multi-tool Vulnerability & Malware Scanner with GUI**

[![Python](https://img.shields.io/badge/Python-3.10-blue.svg)](https://www.python.org/)
[![GUI](https://img.shields.io/badge/Interface-Tkinter-green.svg)]()
[![Security Tools](https://img.shields.io/badge/Tools-Nmap%2C%20Nikto%2C%20SQLMap-orange.svg)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)]()

## 📌 Overview
Autovulnscanner is a **GUI-based vulnerability and malware scanning tool** that integrates multiple popular security scanners into a single interface.  
It’s designed for **penetration testers and QA engineers**, automating scanning, reporting, and malware detection.

## 🛠 Features
- **Integrated Tools**: Nmap, Nikto, SQLMap, WHOIS Lookup, YARA Rules, VirusTotal
- **Exportable Reports** (Markdown, PDF)
- **Parallel Execution** for faster scans
- **Tkinter GUI** for easy use

## 📂 Project Structure
Autovulnscanner/
│── src/ # Main code
│── tests/ # Automated test cases
│── result.txt # Example output
│── QA_Test_Plan.md # Manual test cases
│── requirements.txt # Dependencies
│── README.md


## 🚀 How to Run

# Clone repo
git clone https://github.com/Henil994/Autovulnscanner.git
cd Autovulnscanner

# Install dependencies
pip install -r requirements.txt

# Run app
python main.py

🧪 QA Testing

Automated tests → Run:

pytest

📊 Example Test Case

ID	     Description	        Steps             Expected Result	   Status

TC001  	Nmap scan on         Input and run Nmap 	Shows open ports      	    Pass
        scanme.nmap.org     	
TC002   VirusTotal scan      Upload test file   	Flags as malicious	    Pass
        of EICAR file	
        
📄 Sample Output

See result.txt for the latest scan output.
