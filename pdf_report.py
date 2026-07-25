"""PDF Security Report Generator for Ultron using ReportLab.

Generates a styled, multi-page PDF security report containing executive summaries,
vulnerability finding breakdowns, taint flow paths, and remediation recommendations.
"""

import os
from datetime import datetime
from typing import Optional, List, Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch


def generate_pdf_report(
    repo_name: str,
    security_graph: Dict[str, Any],
    findings: List[Dict[str, Any]],
    output_path: str
) -> Optional[str]:
    """Generate a styled PDF security report.

    Args:
        repo_name: Name of analyzed repository
        security_graph: Security graph dictionary containing flows, subgraphs, summary
        findings: List of vulnerability finding dicts
        output_path: Full destination file path for security_report.pdf

    Returns:
        Path to generated PDF file on success, None on error
    """
    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )

        styles = getSampleStyleSheet()

        # Custom Palette
        PRIMARY = colors.HexColor("#1e293b")      # Slate 800
        ACCENT_CYAN = colors.HexColor("#0284c7")  # Sky 600
        RED_HIGH = colors.HexColor("#dc2626")     # Red 600
        AMBER_MED = colors.HexColor("#d97706")    # Amber 600
        BLUE_LOW = colors.HexColor("#2563eb")     # Blue 600
        BG_LIGHT = colors.HexColor("#f8fafc")     # Slate 50
        BORDER_CLR = colors.HexColor("#cbd5e1")   # Slate 300

        # Custom Paragraph Styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=PRIMARY,
            spaceAfter=4,
        )

        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=12,
        )

        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=PRIMARY,
            spaceBefore=12,
            spaceAfter=6,
        )

        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )

        story = []

        # 1. Header Section
        story.append(Paragraph(f"<b>ULTRON Security Analysis Report</b>", title_style))
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(f"Repository: <b>{repo_name}</b> | Generated: {now_str}", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT_CYAN, spaceAfter=12))

        # 2. Executive Summary Metrics
        high_cnt = len([f for f in findings if f.get("severity") == "high"])
        med_cnt = len([f for f in findings if f.get("severity") == "medium"])
        low_cnt = len([f for f in findings if f.get("severity") == "low"])
        total_cnt = len(findings)

        summary_stats = security_graph.get("summary", {})
        total_flows = summary_stats.get("total_flows", len(security_graph.get("flows", [])))
        unsanitized_flows = summary_stats.get("unvalidated_flows", len([f for f in security_graph.get("flows", []) if not f.get("validated")]))
        sanitized_flows = max(0, total_flows - unsanitized_flows)

        metrics_data = [
            [
                Paragraph("<b>Total Vulnerabilities</b>", body_style),
                Paragraph("<b>High Severity</b>", body_style),
                Paragraph("<b>Medium Severity</b>", body_style),
                Paragraph("<b>Low Severity</b>", body_style),
            ],
            [
                Paragraph(f"<font size=14 color='#1e293b'><b>{total_cnt}</b></font>", body_style),
                Paragraph(f"<font size=14 color='#dc2626'><b>{high_cnt}</b></font>", body_style),
                Paragraph(f"<font size=14 color='#d97706'><b>{med_cnt}</b></font>", body_style),
                Paragraph(f"<font size=14 color='#2563eb'><b>{low_cnt}</b></font>", body_style),
            ]
        ]

        metrics_table = Table(metrics_data, colWidths=[1.85 * inch] * 4)
        metrics_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 1, BORDER_CLR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_CLR),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        story.append(metrics_table)
        story.append(Spacer(1, 10))

        # Flow summary banner
        flow_summary_text = (
            f"<b>Static Data-Flow Metrics:</b> Analyzed <b>{total_flows}</b> total paths "
            f"(<b>{unsanitized_flows}</b> unsanitized, <b>{sanitized_flows}</b> sanitized/validated)."
        )
        story.append(Paragraph(flow_summary_text, body_style))
        story.append(Spacer(1, 12))

        # 3. Detailed Vulnerability Findings
        story.append(Paragraph("<b>Vulnerability Findings</b>", h2_style))

        if not findings:
            no_vuln_box = Table(
                [[Paragraph("<font color='#166534'><b>No vulnerabilities detected. Clean analysis run.</b></font>", body_style)]],
                colWidths=[7.4 * inch]
            )
            no_vuln_box.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#bbf7d0")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(no_vuln_box)
        else:
            for idx, finding in enumerate(findings, start=1):
                sev = finding.get("severity", "medium").lower()
                sev_color = RED_HIGH if sev == "high" else (AMBER_MED if sev == "medium" else BLUE_LOW)
                sev_label = sev.upper()

                title = finding.get("title") or finding.get("rule") or "Vulnerability Finding"
                rule_name = finding.get("rule", "security-rule")
                description = finding.get("description", "No description provided.")
                recommendation = finding.get("recommendation", "Review and sanitize input.")

                source = finding.get("source", "")
                sink = finding.get("sink", "")
                path = finding.get("path", [])
                file_name = finding.get("file", "") or finding.get("location", "")

                card_content = []

                # Header row: Title + Severity badge
                header_p = Paragraph(
                    f"<b>#{idx}. {title}</b> (<font color='{sev_color.hexval()}'><b>{sev_label}</b></font>)",
                    ParagraphStyle("FindHeader", parent=body_style, fontName="Helvetica-Bold", fontSize=10, leading=13)
                )
                card_content.append([header_p])

                # Details
                desc_text = f"<b>Rule:</b> {rule_name}<br/><b>Description:</b> {description}"
                if file_name:
                    desc_text += f"<br/><b>Location:</b> {file_name}"
                if source and sink:
                    desc_text += f"<br/><b>Flow:</b> {source} &rarr; {sink}"
                if path:
                    path_str = " &rarr; ".join(str(p) for p in path)
                    desc_text += f"<br/><b>Path Trace:</b> <font face='Courier' size=7.5>{path_str}</font>"

                card_content.append([Paragraph(desc_text, body_style)])

                # Recommendation
                recom_p = Paragraph(
                    f"<b>Recommendation:</b> {recommendation}",
                    ParagraphStyle("RecomText", parent=body_style, textColor=colors.HexColor("#1e293b"))
                )
                card_content.append([recom_p])

                item_table = Table(card_content, colWidths=[7.4 * inch])
                item_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
                    ("BOX", (0, 0), (-1, -1), 1, BORDER_CLR),
                    ("LINEBELOW", (0, 0), (-1, 0), 1, sev_color),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ]))

                story.append(KeepTogether([item_table, Spacer(1, 8)]))

        # 4. Subgraph & Architecture Breakdown
        story.append(Spacer(1, 10))
        story.append(Paragraph("<b>Architecture & Subgraph Summary</b>", h2_style))

        subgraphs = security_graph.get("subgraphs", {})
        auth_sg = subgraphs.get("auth", {})
        db_sg = subgraphs.get("database", {})
        net_sg = subgraphs.get("network", {})

        unprotected_routes = auth_sg.get("unprotected", [])
        db_ops = db_sg.get("operations", [])
        net_ops = net_sg.get("operations", [])

        arch_text = (
            f"<b>Authentication Subgraph:</b> {len(unprotected_routes)} unprotected API route(s) identified.<br/>"
            f"<b>Database Subgraph:</b> {len(db_ops)} database operation(s) tracked.<br/>"
            f"<b>Network Subgraph:</b> {len(net_ops)} external network request call site(s) tracked."
        )
        story.append(Paragraph(arch_text, body_style))
        story.append(Spacer(1, 14))

        # Footer HR
        story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER_CLR, spaceAfter=8))
        story.append(Paragraph("<font size=7 color='#94a3b8'>Generated automatically by Ultron Multi-Agent Static Analysis Engine.</font>", body_style))

        doc.build(story)
        return output_path
    except Exception as e:
        print(f"Error generating PDF report: {e}")
        return None
