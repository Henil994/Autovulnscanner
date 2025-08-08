# reports/exporter.py

from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

def export_txt_report(results, filename):
    with open(filename, "w") as f:
        for section, output in results.items():
            f.write(f"## {section} Scan\n{output}\n\n")

def export_pdf_report(results, filename):
    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()
    story = []

    for section, output in results.items():
        story.append(Paragraph(f"<b>{section} Scan</b>", styles["Heading2"]))
        story.append(Paragraph(f"<pre>{output.replace('<', '&lt;').replace('>', '&gt;')}</pre>", styles["Code"]))
        story.append(Paragraph("<br/><br/>", styles["Normal"]))

    doc.build(story)
