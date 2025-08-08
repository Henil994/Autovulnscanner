import os
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_txt_report(target, results, output_path):
    with open(output_path, "w") as f:
        f.write(f"AutoVulnScanner Report\n")
        f.write(f"Target: {target}\n")
        f.write(f"Generated: {datetime.now()}\n\n")
        for section, items in results.items():
            f.write(f"\n--- {section.upper()} ---\n")
            for line in items:
                f.write(f"{line}\n")

def generate_pdf_report(target, results, output_path):
    doc = SimpleDocTemplate(output_path)
    styles = getSampleStyleSheet()
    flow = []

    flow.append(Paragraph(f"<b>AutoVulnScanner Report</b>", styles['Title']))
    flow.append(Paragraph(f"Target: {target}", styles['Normal']))
    flow.append(Paragraph(f"Date: {datetime.now()}", styles['Normal']))
    flow.append(Spacer(1, 12))

    for section, items in results.items():
        flow.append(Paragraph(f"<b>{section.upper()}</b>", styles['Heading2']))
        for item in items:
            flow.append(Paragraph(item, styles['Normal']))
        flow.append(Spacer(1, 12))

    doc.build(flow)
