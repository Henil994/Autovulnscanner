# File: autovulnscanner.py
import argparse
from modules import nmap_scanner, nuclei_scanner, dirsearch_scanner, ssl_scanner, shodan_client, report_generator

def main():
    parser = argparse.ArgumentParser(description="Auto Vulnerability Scanner")
    parser.add_argument('--target', required=True, help='Target URL or IP')
    parser.add_argument('--tools', default='nmap,nuclei,dirsearch', help='Comma-separated tools')
    parser.add_argument('--report', default='txt', choices=['txt', 'pdf'], help='Report format')
    args = parser.parse_args()

    target = args.target
    selected_tools = args.tools.split(',')
    results = {}

    if 'nmap' in selected_tools:
        results['nmap'] = nmap_scanner.scan(target)
    if 'nuclei' in selected_tools:
        results['nuclei'] = nuclei_scanner.scan(target)
    if 'dirsearch' in selected_tools:
        results['dirsearch'] = dirsearch_scanner.scan(target)
    if 'ssl' in selected_tools:
        results['ssl'] = ssl_scanner.scan(target)
    if 'shodan' in selected_tools:
        results['shodan'] = shodan_client.scan(target)

    report_path = f"reports/scan_report.{args.report}"
    if args.report == 'txt':
        report_generator.generate_txt_report(target, results, report_path)
    elif args.report == 'pdf':
        report_generator.generate_pdf_report(target, results, report_path)

if __name__ == "__main__":
    main()
