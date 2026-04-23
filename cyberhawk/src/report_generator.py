from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Dict, Iterable, List, Optional

from fpdf import FPDF


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _report_path(prefix: str) -> str:
    reports_dir = os.path.join(BASE_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(reports_dir, f"{prefix}_{timestamp}.pdf")


def _ascii(value) -> str:
    text = str(value)
    text = text.replace("\u2022", "-")
    text = text.encode("latin-1", errors="replace").decode("latin-1")
    # FPDF cannot wrap one very long token, so give URLs/hashes safe breakpoints.
    tokens = []
    for token in text.split(" "):
        if len(token) > 70:
            token = " ".join(token[i : i + 70] for i in range(0, len(token), 70))
        tokens.append(token)
    return " ".join(tokens)


def _clean_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("_")


class CyberHawkPDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 18)
        self.set_text_color(25, 42, 86)
        self.cell(0, 10, "CyberHawk Threat Intelligence Report", ln=True)
        self.set_font("Arial", "", 9)
        self.set_text_color(90, 90, 90)
        self.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        self.set_draw_color(25, 42, 86)
        self.line(10, self.get_y() + 2, 200, self.get_y() + 2)
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"CyberHawk educational security report | Page {self.page_no()}", align="C")

    def section(self, title: str):
        self.ln(2)
        self.set_x(self.l_margin)
        self.set_font("Arial", "B", 12)
        self.set_text_color(25, 42, 86)
        self.cell(0, 8, _ascii(title), ln=True)
        self.set_text_color(0, 0, 0)

    def key_value(self, key: str, value):
        self.set_x(self.l_margin)
        self.set_font("Arial", "B", 9)
        self.cell(0, 5, _ascii(f"{key}:"), ln=True)
        self.set_font("Arial", "", 9)
        text = _ascii(value if value not in (None, "") else "N/A")
        self.set_x(self.l_margin)
        self.multi_cell(0, 5, text)
        self.ln(1)

    def bullet_list(self, items: Iterable[str]):
        self.set_font("Arial", "", 9)
        for item in items:
            self.set_x(self.l_margin)
            self.multi_cell(0, 5, _ascii(f"- {item}"))


def _risk_fill(pdf: FPDF, risk_level: str):
    colors = {
        "Critical": (196, 49, 75),
        "High": (226, 125, 47),
        "Medium": (235, 177, 52),
        "Low": (56, 142, 60),
        "Unknown": (120, 120, 120),
    }
    pdf.set_fill_color(*colors.get(risk_level, colors["Unknown"]))
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 10)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 8, _ascii(f"Risk Level: {risk_level}"), ln=True, fill=True)
    pdf.set_x(pdf.l_margin)
    pdf.set_text_color(0, 0, 0)


def generate_network_report(info: Dict, output_path: Optional[str] = None) -> str:
    if output_path is None:
        output_path = _report_path("network_threat_report")

    pdf = CyberHawkPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.section("Network Detection Summary")
    for field in [
        "Attack Type",
        "Confidence Score",
        "Risk Score",
        "Risk Level",
        "MITRE Technique",
        "CVE References",
        "Description",
        "Input Features",
    ]:
        if field in info:
            pdf.key_value(field, info[field])

    _risk_fill(pdf, info.get("Risk Level", "Unknown"))

    if info.get("Recommendations"):
        pdf.section("Mitigation Recommendations")
        pdf.bullet_list(info["Recommendations"])

    pdf.section("Presentation Flow")
    pdf.bullet_list(
        [
            "Feature values are preprocessed using the saved scaler.",
            "The Random Forest model classifies the traffic pattern.",
            "The class is mapped to MITRE ATT&CK, CVE references, and mitigations.",
            "Risk is calculated from model confidence, severity, and exploitability.",
        ]
    )

    pdf.output(output_path)
    return output_path


def _write_website_detail(pdf: CyberHawkPDF, site: Dict, index: int):
    pdf.section(f"Website #{index}")
    pdf.key_value("URL", site.get("url", "N/A"))
    pdf.key_value("Final URL", site.get("final_url", "N/A"))
    pdf.key_value("Domain", site.get("domain", "N/A"))
    pdf.key_value("IP Address", site.get("ip_address", "N/A"))
    pdf.key_value("Hosting", site.get("hosting_provider", "N/A"))
    pdf.key_value("SSL Valid", site.get("ssl_valid", "N/A"))
    pdf.key_value("Blacklist Status", site.get("blacklist_status", "N/A"))
    pdf.key_value("Attack Type", site.get("threat_type", "N/A"))
    pdf.key_value("Confidence Score", f"{site.get('confidence_score', 0)}%")
    pdf.key_value("Risk Score", f"{site.get('risk_score', 0)}/10")
    pdf.key_value("Risk Level", site.get("risk_level", "Unknown"))

    mitre = site.get("mitre") or site.get("threat_intelligence", {}).get("mitre", {})
    if mitre:
        pdf.key_value("MITRE Mapping", f"{mitre.get('technique_id', 'N/A')} - {mitre.get('technique', 'N/A')}")
    pdf.key_value("CVE References", ", ".join(site.get("cves", [])) or "N/A")

    if site.get("detected_threats"):
        pdf.section("Detected Signals")
        pdf.bullet_list(site["detected_threats"])

    behavior = site.get("browser_behavior", {})
    if behavior:
        pdf.section("Captured Behavior")
        pdf.key_value("Scripts", behavior.get("script_count", 0))
        pdf.key_value("Forms", behavior.get("form_count", 0))
        pdf.key_value("Hidden Iframes", behavior.get("hidden_iframes", 0))
        pdf.key_value("API Calls", len(behavior.get("api_calls", [])))
        pdf.key_value("Suspicious Downloads", len(behavior.get("suspicious_downloads", [])))

    if site.get("recommendations"):
        pdf.section("Mitigation Recommendations")
        pdf.bullet_list(site["recommendations"])


def generate_website_report(website_analysis: Dict, output_path: Optional[str] = None) -> str:
    if output_path is None:
        output_path = _report_path("website_threat_report")

    pdf = CyberHawkPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.section("Executive Summary")
    pdf.key_value("URLs Analyzed", website_analysis.get("urls_analyzed", 0))
    pdf.key_value("Threats Found", website_analysis.get("threats_found", 0))
    pdf.key_value("Critical", website_analysis.get("critical_count", 0))
    pdf.key_value("High", website_analysis.get("high_count", 0))
    pdf.key_value("Medium", website_analysis.get("medium_count", 0))
    pdf.key_value("Low", website_analysis.get("low_count", 0))
    pdf.key_value("Summary", website_analysis.get("summary", "N/A"))

    pdf.section("End-to-End Pipeline")
    pdf.bullet_list(
        [
            "User submits one or more URLs.",
            "CyberHawk performs passive URL, DNS, SSL, and reputation checks.",
            "A controlled HTTP request captures headers, redirects, cookies, links, and page signals.",
            "Behavior is converted into ML-friendly network features.",
            "The saved ML model predicts the likely attack pattern.",
            "Threat intelligence maps the result to MITRE ATT&CK, CVEs, risk, and mitigation guidance.",
        ]
    )

    for idx, site in enumerate(website_analysis.get("analysis_results", []), 1):
        if pdf.get_y() > 230:
            pdf.add_page()
        _write_website_detail(pdf, site, idx)

    pdf.output(output_path)
    return output_path


def generate_report(info: Dict, output_path: Optional[str] = None) -> str:
    return generate_network_report(info, output_path)
