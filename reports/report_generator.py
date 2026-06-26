from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import cm
from database import get_all_alerts, get_alerts_count, get_alerts_by_type
from datetime import datetime
import io
import re

def generate_pdf_report():
    alerts = get_all_alerts(500)
    total = get_alerts_count()
    by_type = get_alerts_by_type()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4),
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("title", parent=styles["Title"],
        fontSize=18, textColor=colors.HexColor("#0f172a"), spaceAfter=6)
    subtitle_style = ParagraphStyle("subtitle", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#64748b"), spaceAfter=20)
    heading_style = ParagraphStyle("heading", parent=styles["Heading2"],
        fontSize=12, textColor=colors.HexColor("#0f172a"), spaceBefore=16, spaceAfter=8)

    story = []
    story.append(Paragraph("IDS Dashboard — Raport", title_style))
    story.append(Paragraph(f"Generat la: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))

    story.append(Paragraph("Sumar", heading_style))
    summary_data = [["Metrica", "Valoare"]]
    summary_data.append(["Total alerte", str(total)])
    for t, c in by_type.items():
        summary_data.append([t, str(c)])

    summary_table = Table(summary_data, colWidths=[10*cm, 6*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(summary_table)

    if alerts:
        story.append(Paragraph("Alerte detectate", heading_style))

        table_data = [["ID", "Tip", "Severitate", "IP Sursa", "Confidenta", "Timestamp"]]
        for alert in alerts:
            detail = alert.get("detail", "")
            match = re.search(r"(\d+\.\d+)%", detail)
            confidenta = match.group(0) if match else "-"

            severity = alert.get("severity", "-")
            table_data.append([
                str(alert.get("id", "")),
                alert.get("type", ""),
                severity,
                alert.get("src_ip") or "-",
                confidenta,
                str(alert.get("timestamp", ""))[:16],
            ])

        col_widths = [1.2*cm, 4*cm, 3*cm, 4*cm, 3*cm, 4.5*cm]
        alerts_table = Table(table_data, colWidths=col_widths)

        cell_styles = [
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0,0), (-1,-1), 6),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]

        for i, alert in enumerate(alerts, 1):
            severity = alert.get("severity", "")
            if severity == "CRITICAL":
                cell_styles.append(("TEXTCOLOR", (2,i), (2,i), colors.HexColor("#ef4444")))
                cell_styles.append(("FONTNAME", (2,i), (2,i), "Helvetica-Bold"))
            elif severity == "HIGH":
                cell_styles.append(("TEXTCOLOR", (2,i), (2,i), colors.HexColor("#f97316")))
                cell_styles.append(("FONTNAME", (2,i), (2,i), "Helvetica-Bold"))
            elif severity == "MEDIUM":
                cell_styles.append(("TEXTCOLOR", (2,i), (2,i), colors.HexColor("#eab308")))

        alerts_table.setStyle(TableStyle(cell_styles))
        story.append(alerts_table)

    doc.build(story)
    buffer.seek(0)
    return buffer

def generate_report():
    alerts = get_all_alerts(500)
    total = get_alerts_count()
    by_type = get_alerts_by_type()
    return {
        "alerts": alerts,
        "total_alerts": total,
        "alerts_by_type": by_type,
        "generated_at": datetime.now().isoformat(),
    }
