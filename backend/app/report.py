"""Génère un rapport PDF pour un scan (utilise reportlab)."""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#b91c1c"),
    "high": colors.HexColor("#c2410c"),
    "medium": colors.HexColor("#a16207"),
    "low": colors.HexColor("#1d4ed8"),
    "info": colors.HexColor("#4b5563"),
}

# Ordre d'affichage : les failles les plus graves en premier
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def generate_scan_pdf(scan) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title=f"VulnRadar - scan {scan.id}")
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleBig", parent=styles["Title"], fontSize=20, spaceAfter=6
    )
    small = ParagraphStyle("Small", parent=styles["Normal"], textColor=colors.grey)

    story = []
    story.append(Paragraph("Rapport de scan VulnRadar", title_style))
    story.append(Paragraph(f"Cible : {scan.target}", styles["Normal"]))
    story.append(
        Paragraph(f"Date : {scan.started_at.strftime('%d/%m/%Y %H:%M')}", small)
    )
    score = scan.score if scan.score is not None else "-"
    story.append(Paragraph(f"Score de sécurité : {score} / 100", styles["Heading2"]))
    story.append(Spacer(1, 0.5 * cm))

    findings = sorted(
        scan.findings,
        key=lambda f: SEVERITY_ORDER.index(f.severity.value)
        if f.severity.value in SEVERITY_ORDER
        else 99,
    )

    if not findings:
        story.append(Paragraph("Aucune vulnérabilité détectée.", styles["Normal"]))
    else:
        story.append(
            Paragraph(f"{len(findings)} problème(s) détecté(s)", styles["Heading2"])
        )
        story.append(Spacer(1, 0.3 * cm))

        for f in findings:
            sev = f.severity.value
            color = SEVERITY_COLORS.get(sev, colors.grey)
            header = Paragraph(
                f'<font color="{color.hexval()}"><b>[{sev.upper()}]</b></font> {f.title}',
                styles["Normal"],
            )
            rows = [[header]]
            rows.append([Paragraph(f.description, small)])
            if f.recommendation:
                rows.append([Paragraph(f"Recommandation : {f.recommendation}", small)])

            table = Table(rows, colWidths=[16 * cm])
            table.setStyle(
                TableStyle(
                    [
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 0.3 * cm))

    doc.build(story)
    return buffer.getvalue()
