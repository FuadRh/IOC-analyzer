# utils/exporter.py
import csv
import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import colors

def _flatten_dict(d, parent_key='', sep='_'):
    """
    Flattens a nested dictionary for CSV export.
    """
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, str(v)))
    return dict(items)

def export_to_csv(report: dict, output_path: str):
    """
    Exports the analysis report to a CSV file.
    """
    try:
        flat_report = _flatten_dict(report)
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(flat_report.keys())
            writer.writerow(flat_report.values())
        print(f"[*] CSV report saved to: {output_path}")
    except IOError as e:
        print(f"[!] Error saving CSV report: {e}")

def export_to_pdf(report: dict, indicator: str, output_path: str):
    """
    Exports the analysis report to a PDF file.
    """
    try:
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # --- Title Page ---
        story.append(Paragraph("SOC Tier 1 Analysis Report", styles['h1']))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(f"<b>Indicator:</b> {indicator}", styles['h2']))
        story.append(Paragraph(f"<b>Report Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        # --- Verdict Section ---
        vt_report = report.get('virustotal_report', {})
        static_score = report.get('static_analysis_score', 0)
        vt_positives = vt_report.get('positives', 0) if 'error' not in vt_report else 0
        threat_score = static_score + (vt_positives * 2)
        verdict = "CLEAN"
        verdict_color = colors.green
        if threat_score > 20:
            verdict = "MALICIOUS"
            verdict_color = colors.red
        elif threat_score > 5:
            verdict = "SUSPICIOUS"
            verdict_color = colors.orange

        verdict_style = styles['h2']
        verdict_style.textColor = verdict_color
        story.append(Paragraph(f"Verdict: {verdict}", verdict_style))
        story.append(Paragraph(f"<b>Overall Threat Score:</b> {threat_score}", styles['Normal']))
        story.append(PageBreak())

        # --- Details Page ---
        story.append(Paragraph("Analysis Details", styles['h1']))
        story.append(Spacer(1, 0.2*inch))

        if 'file_info' in report:
            story.append(Paragraph("File Information", styles['h2']))
            story.append(Paragraph(f"<b>File Name:</b> {report['file_info'].get('file_name', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"<b>File Size:</b> {report['file_info'].get('file_size_bytes', 'N/A')} bytes", styles['Normal']))
            hashes = report.get('hashes', {})
            story.append(Paragraph(f"<b>MD5:</b> {hashes.get('md5', 'N/A')}", styles['Code']))
            story.append(Paragraph(f"<b>SHA-1:</b> {hashes.get('sha1', 'N/A')}", styles['Code']))
            story.append(Paragraph(f"<b>SHA-256:</b> {hashes.get('sha256', 'N/A')}", styles['Code']))
            story.append(Spacer(1, 0.2*inch))

        story.append(Paragraph("Static Analysis", styles['h2']))
        story.append(Paragraph(f"<b>Static Score:</b> {static_score}", styles['Normal']))
        for item in report.get('static_analysis_summary', []):
            story.append(Paragraph(f"- {item}", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        story.append(Paragraph("VirusTotal Enrichment", styles['h2']))
        if 'error' not in vt_report:
            total = vt_report.get('total_scans', 0)
            story.append(Paragraph(f"<b>Detections:</b> {vt_positives} / {total}", styles['Normal']))
            vt_link = vt_report.get('link', '#')
            story.append(Paragraph(f"<b>Link:</b> <link href='{vt_link}'>{vt_link}</link>", styles['Normal']))
        else:
            story.append(Paragraph(f"<b>Error:</b> {vt_report['error']}", styles['Normal']))

        doc.build(story)
        print(f"[*] PDF report saved to: {output_path}")
    except Exception as e:
        print(f"[!] Error saving PDF report: {e}")

def export_all_formats(report: dict, indicator: str):
    """
    NEW: Exports the report to JSON, CSV, and PDF formats.
    This function now lives in the exporter module where it belongs.
    """
    if not os.path.exists('reports'):
        os.makedirs('reports')

    safe_filename = "".join(c for c in indicator if c.isalnum() or c in ('.', '_')).rstrip()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_path = os.path.join('reports', f"report_{safe_filename}_{timestamp}")

    # JSON Export
    try:
        with open(f"{base_path}.json", 'w') as f:
            json.dump(report, f, indent=4)
        print(f"[*] JSON report saved to: {base_path}.json")
    except IOError as e:
        print(f"[!] Error saving JSON report: {e}")

    # PDF and CSV Export
    export_to_pdf(report, indicator, f"{base_path}.pdf")
    export_to_csv(report, f"{base_path}.csv")
