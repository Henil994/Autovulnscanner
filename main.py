import datetime
import time

def run_scan_and_get_report(target, fmt="txt", tools=None):
    """
    Run scans on the target with selected tools, generate a report in requested format,
    and return the report content (string for txt, bytes for pdf).
    
    :param target: URL or IP address string
    :param fmt: 'txt' or 'pdf'
    :param tools: dict of tool name -> bool to indicate whether to run tool
    :return: report content (str for txt, bytes for pdf)
    """
    if tools is None:
        tools = {
            "WHOIS": True,
            "Nmap": True,
            "Nikto": True,
            "SQLMap": True,
        }

    report_lines = []
    report_lines.append(f"AutoVulnScanner Report for {target}")
    report_lines.append(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("="*40)
    report_lines.append("")

    # Simulated scans for each tool
    if tools.get("WHOIS", False):
        report_lines.append("[WHOIS Scan]")
        report_lines.append(f"Whois data for {target}:")
        # Simulate WHOIS output
        report_lines.append("Registrar: Example Registrar")
        report_lines.append("Registrant Country: US")
        report_lines.append("Creation Date: 2010-01-01")
        report_lines.append("")
        time.sleep(1)

    if tools.get("Nmap", False):
        report_lines.append("[Nmap Scan]")
        report_lines.append(f"Nmap scan results for {target}:")
        # Simulate Nmap output
        report_lines.append("Open ports: 22, 80, 443")
        report_lines.append("Service versions: OpenSSH 7.6p1, Apache 2.4.29")
        report_lines.append("")
        time.sleep(1)

    if tools.get("Nikto", False):
        report_lines.append("[Nikto Scan]")
        report_lines.append(f"Nikto web server scan results for {target}:")
        # Simulate Nikto output
        report_lines.append("No critical vulnerabilities found.")
        report_lines.append("")
        time.sleep(1)

    if tools.get("SQLMap", False):
        report_lines.append("[SQLMap Scan]")
        report_lines.append(f"SQL Injection test results for {target}:")
        # Simulate SQLMap output
        report_lines.append("No SQL injection vulnerabilities detected.")
        report_lines.append("")
        time.sleep(1)

    report_lines.append("="*40)
    report_lines.append("Scan completed successfully.")

    report_text = "\n".join(report_lines)

    if fmt == "txt":
        return report_text  # return plain string report
    elif fmt == "pdf":
        # Dummy PDF bytes example (replace with real PDF generation if needed)
        # Just a very minimal PDF content for demonstration:
        pdf_bytes = (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << >> >> endobj\n"
            b"4 0 obj << /Length %d >> stream\n"
            % len(report_text.encode("utf-8"))
        )
        pdf_bytes += report_text.encode("utf-8") + b"\nendstream\nendobj\n"
        pdf_bytes += b"xref\n0 5\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n0000000117 00000 n \n0000000217 00000 n \n"
        pdf_bytes += b"trailer << /Size 5 /Root 1 0 R >>\nstartxref\n317\n%%EOF"
        return pdf_bytes
    else:
        raise ValueError(f"Unsupported format: {fmt}")

# Optional: test running main function
if __name__ == "__main__":
    target = "example.com"
    report = run_scan_and_get_report(target, "txt")
    print(report)
