from scanners.nmap_scanner import run_nmap_scan
from scanners.nikto_scanner import run_nikto_scan
from scanners.sqlmap_scanner import run_sqlmap_scan
from scanners.whois_lookup import run_whois_lookup
from reports.exporter import export_txt_report, export_pdf_report

class AutoVulnScanner:
    def __init__(self, target, tools):
        self.target = target
        self.tools = tools
        self.results = {}

    def run_scans(self):
        if "WHOIS" in self.tools:
            self.results["WHOIS"] = run_whois_lookup(self.target)
        if "Nmap" in self.tools:
            self.results["Nmap"] = run_nmap_scan(self.target)
        if "Nikto" in self.tools:
            self.results["Nikto"] = run_nikto_scan(self.target)
        if "SQLMap" in self.tools:
            self.results["SQLMap"] = run_sqlmap_scan(self.target)

    def generate_report(self, format, filename):
        if format.lower() == "txt":
            export_txt_report(self.results, filename)
        elif format.lower() == "pdf":
            export_pdf_report(self.results, filename)
        else:
            print("[!] Unsupported export format.")

def run_scan_and_report(target, report_format, output_file, tools):
    scanner = AutoVulnScanner(target, tools)
    scanner.run_scans()
    scanner.generate_report(report_format, output_file)
