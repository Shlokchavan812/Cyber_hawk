from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "threat_logs.jsonl"

from src.predict import predict
from src.report_generator import generate_report, generate_website_report
from src.threat_intel import get_threat
from src.website_threat_analyzer import analyze_multiple_urls


st.set_page_config(
    page_title="CyberHawk - AI Cybersecurity Threat Intelligence",
    page_icon="CH",
    layout="wide",
)


def init_state():
    defaults = {
        "network_report_path": None,
        "network_result": None,
        "website_report_path": None,
        "website_analysis": None,
        "urls_text": "https://example.com\nhttp://192.168.1.1\nhttps://login-secure-paypal.fake.xyz",
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def write_log(event_type: str, payload: dict):
    LOG_DIR.mkdir(exist_ok=True)
    record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        **payload,
    }
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, default=str) + "\n")


def read_logs(limit: int = 100):
    if not LOG_FILE.exists():
        return []
    with LOG_FILE.open("r", encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    return list(reversed(rows[-limit:]))


def download_pdf(path: str | None, label: str, key: str):
    if path and os.path.exists(path):
        with open(path, "rb") as pdf_file:
            st.download_button(
                label=label,
                data=pdf_file.read(),
                file_name=os.path.basename(path),
                mime="application/pdf",
                use_container_width=True,
                key=key,
            )


def risk_color(risk: str) -> str:
    return {
        "Critical": "#c4314b",
        "High": "#e27d2f",
        "Medium": "#d6a21f",
        "Low": "#388e3c",
        "Unknown": "#68707d",
    }.get(risk, "#68707d")


def metric_card(label: str, value, color: str = "#ffffff"):
    st.markdown(
        f"""
        <div class="metric-card" style="border-top-color:{color};">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_css():
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.5rem; }
        .hero {
            background: linear-gradient(135deg, #132238 0%, #24536f 52%, #2f6f5e 100%);
            color: white;
            padding: 26px 30px;
            border-radius: 8px;
            margin-bottom: 18px;
        }
        .hero h1 {
            font-size: 34px;
            margin: 0 0 6px 0;
            letter-spacing: 0;
        }
        .hero p {
            margin: 0;
            color: rgba(255,255,255,0.86);
            font-size: 14px;
        }
        .metric-card {
            background: #ffffff;
            border: 1px solid #e5e9f0;
            border-top: 4px solid #24536f;
            border-radius: 8px;
            padding: 16px;
            min-height: 94px;
            box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
        }
        .metric-label {
            color: #68707d;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .metric-value {
            color: #172033;
            font-size: 22px;
            font-weight: 800;
            line-height: 1.15;
            overflow-wrap: anywhere;
        }
        .result-card {
            border: 1px solid #e5e9f0;
            border-radius: 8px;
            padding: 18px;
            margin: 12px 0;
            background: white;
        }
        .risk-pill {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 999px;
            color: white;
            font-weight: 700;
            font-size: 12px;
        }
        .pipeline {
            border-left: 3px solid #24536f;
            padding-left: 14px;
            margin: 10px 0;
            color: #243044;
            line-height: 1.55;
        }
        .small-muted { color: #68707d; font-size: 13px; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def build_network_report_data(values, threat):
    mitre = threat.get("mitre", {})
    return {
        "Attack Type": threat["type"],
        "Confidence Score": f"{threat.get('confidence', 0) * 100:.2f}%",
        "Risk Score": f"{threat.get('risk_score', 0)}/10",
        "Risk Level": threat["risk"],
        "MITRE Technique": f"{mitre.get('technique_id', 'N/A')} - {mitre.get('technique', 'N/A')}",
        "CVE References": ", ".join(threat.get("cves", [])) or "N/A",
        "Description": threat.get("description", "N/A"),
        "Input Features": ", ".join(str(v) for v in values),
        "Recommendations": threat.get("recommendations", []),
    }


def render_network_tab():
    st.subheader("ML Attack Detection Engine")
    st.caption("Enter 9 network-flow features. The saved Random Forest model classifies the flow, then CyberHawk maps it to risk, MITRE ATT&CK, CVEs, and mitigation guidance.")

    samples = {
        "Normal": "100, 5000, 10, 6, 0, 1023, 80, 10, 500",
        "DoS": "500, 25000, 2, 6, 0, 1027, 9200, 250, 12500",
        "Brute Force": "300, 15000, 15, 6, 0, 1031, 22, 20, 1000",
        "Port Scan": "200, 10000, 20, 6, 0, 1035, 80, 10, 500",
        "Malware": "600, 30000, 8, 6, 0, 1043, 80, 75, 3750",
    }

    with st.form("network_form"):
        input_data = st.text_input(
            "Network feature values",
            value=samples["Port Scan"],
            help="packet_count, byte_count, duration, protocol, flags, source_port, dest_port, packet_rate, data_rate",
        )
        col_a, col_b = st.columns([1, 2])
        analyze_clicked = col_a.form_submit_button("Detect Threat", type="primary", use_container_width=True)
        selected_sample = col_b.selectbox("Reference sample", list(samples.keys()), index=3)

    st.caption(f"Selected reference: {samples[selected_sample]}")

    if analyze_clicked:
        try:
            values = [float(x.strip()) for x in input_data.split(",")]
            if len(values) != 9:
                st.error(f"Expected 9 features, received {len(values)}.")
                return

            prediction, confidence = predict(values)
            threat = get_threat(prediction, confidence)
            report_data = build_network_report_data(values, threat)
            st.session_state.network_result = report_data

            write_log(
                "network_scan",
                {
                    "target": "network_flow",
                    "attack_type": threat["type"],
                    "risk_level": threat["risk"],
                    "risk_score": threat["risk_score"],
                    "confidence_score": round(confidence * 100, 2),
                },
            )
        except ValueError:
            st.error("Enter numeric values separated by commas.")
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")

    if st.session_state.network_result:
        data = st.session_state.network_result
        cols = st.columns(4)
        with cols[0]:
            metric_card("Attack Type", data["Attack Type"])
        with cols[1]:
            metric_card("Risk Level", data["Risk Level"], risk_color(data["Risk Level"]))
        with cols[2]:
            metric_card("Risk Score", data["Risk Score"])
        with cols[3]:
            metric_card("Confidence", data["Confidence Score"])

        st.markdown("#### Threat Intelligence")
        st.write(data["Description"])
        st.write(f"MITRE ATT&CK: {data['MITRE Technique']}")
        st.write(f"CVE references: {data['CVE References']}")

        st.markdown("#### Recommended Mitigation")
        for item in data["Recommendations"]:
            st.write(f"- {item}")

        col_a, col_b = st.columns(2)
        if col_a.button("Generate Network PDF", type="primary", use_container_width=True):
            path = generate_report(data)
            st.session_state.network_report_path = path
            st.success("Network PDF report generated.")
        download_pdf(st.session_state.network_report_path, "Download Network PDF", "download_network_pdf")
        if col_b.button("Show Network JSON", use_container_width=True):
            st.json(data)


def render_site_summary(analysis: dict):
    cols = st.columns(5)
    metrics = [
        ("URLs", analysis["urls_analyzed"], "#24536f"),
        ("Critical", analysis["critical_count"], risk_color("Critical")),
        ("High", analysis["high_count"], risk_color("High")),
        ("Medium", analysis["medium_count"], risk_color("Medium")),
        ("Low", analysis["low_count"], risk_color("Low")),
    ]
    for col, (label, value, color) in zip(cols, metrics):
        with col:
            metric_card(label, value, color)

    chart_data = pd.DataFrame(
        {
            "Risk": ["Critical", "High", "Medium", "Low"],
            "Count": [
                analysis["critical_count"],
                analysis["high_count"],
                analysis["medium_count"],
                analysis["low_count"],
            ],
        }
    ).set_index("Risk")
    st.bar_chart(chart_data)


def normalize_website_analysis(analysis):
    if not isinstance(analysis, dict):
        return None

    results = analysis.get("analysis_results")
    if not isinstance(results, list):
        results = []

    normalized = {
        "urls_analyzed": analysis.get("urls_analyzed", len(results)),
        "threats_found": analysis.get(
            "threats_found",
            sum(1 for item in results if item.get("risk_level") in ("Medium", "High", "Critical")),
        ),
        "critical_count": analysis.get(
            "critical_count", sum(1 for item in results if item.get("risk_level") == "Critical")
        ),
        "high_count": analysis.get(
            "high_count", sum(1 for item in results if item.get("risk_level") == "High")
        ),
        "medium_count": analysis.get(
            "medium_count", sum(1 for item in results if item.get("risk_level") == "Medium")
        ),
        "low_count": analysis.get(
            "low_count", sum(1 for item in results if item.get("risk_level") == "Low")
        ),
        "analysis_results": results,
        "summary": analysis.get(
            "summary",
            f"Analyzed {len(results)} website(s).",
        ),
    }
    return normalized


def render_website_result(site: dict, index: int):
    risk = site.get("risk_level", "Unknown")
    color = risk_color(risk)
    st.markdown(
        f"""
        <div class="result-card">
            <div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-start;">
                <div>
                    <div class="small-muted">URL #{index}</div>
                    <strong>{site.get('url', 'Unknown')}</strong>
                </div>
                <span class="risk-pill" style="background:{color};">{risk}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Threat Type", site.get("threat_type", "Unknown"))
    c2.metric("Risk Score", f"{site.get('risk_score', 0)}/10")
    c3.metric("Confidence", f"{site.get('confidence_score', 0)}%")
    c4.metric("Status Code", site.get("status_code") or "N/A")

    info_cols = st.columns(2)
    with info_cols[0]:
        st.write(f"Domain: {site.get('domain', 'N/A')}")
        st.write(f"IP: {site.get('ip_address', 'N/A')}")
        st.write(f"Hosting: {site.get('hosting_provider', 'N/A')}")
        st.write(f"Blacklist: {site.get('blacklist_status', 'N/A')}")
    with info_cols[1]:
        mitre = site.get("mitre", {})
        st.write(f"MITRE: {mitre.get('technique_id', 'N/A')} - {mitre.get('technique', 'N/A')}")
        st.write(f"CVEs: {', '.join(site.get('cves', [])) or 'N/A'}")
        st.write(f"SSL valid: {site.get('ssl_valid', 'N/A')}")
        st.write(f"Final URL: {site.get('final_url', 'N/A')}")

    tabs = st.tabs(["Signals", "Traffic Capture", "ML Features", "Timeline", "Mitigation"])
    with tabs[0]:
        signals = site.get("detected_threats") or ["No suspicious URL or page signals detected."]
        for signal in signals:
            st.write(f"- {signal}")
    with tabs[1]:
        st.json(site.get("network_interaction", {}))
    with tabs[2]:
        st.json(
            {
                "extracted_features": site.get("extracted_features", {}),
                "ml_detection": site.get("ml_detection", {}),
                "browser_behavior": site.get("browser_behavior", {}),
            }
        )
    with tabs[3]:
        for step in site.get("timeline", []):
            st.markdown(f"<div class='pipeline'>{step}</div>", unsafe_allow_html=True)
    with tabs[4]:
        for rec in site.get("recommendations", []):
            st.write(f"- {rec}")


def render_website_tab():
    st.subheader("URL Intelligence and Website Threat Analysis")
    st.caption("This is the full user URL input to AI-powered report flow: passive intelligence, controlled HTTP capture, feature extraction, ML detection, threat mapping, risk scoring, and recommendations.")

    with st.form("website_form"):
        urls_text = st.text_area(
            "Website URLs",
            key="urls_text",
            height=140,
            help="Enter one URL per line. The scanner performs a safe, bounded HTTP request only.",
        )
        scan_clicked = st.form_submit_button("Scan Websites", type="primary", use_container_width=True)

    if scan_clicked:
        urls = [line.strip() for line in urls_text.splitlines() if line.strip()]
        if not urls:
            st.warning("Enter at least one URL.")
            return
        with st.spinner("Running passive intelligence, traffic capture, ML detection, and risk scoring..."):
            analysis = analyze_multiple_urls(urls)
        st.session_state.website_analysis = analysis
        st.session_state.website_report_path = None
        write_log(
            "website_scan",
            {
                "target": ", ".join(urls[:3]),
                "attack_type": "multiple_url_analysis",
                "risk_level": "Mixed",
                "risk_score": max((item.get("risk_score", 0) for item in analysis["analysis_results"]), default=0),
                "confidence_score": max((item.get("confidence_score", 0) for item in analysis["analysis_results"]), default=0),
            },
        )

    analysis = normalize_website_analysis(st.session_state.website_analysis)
    if not analysis:
        st.info("Run a scan to see URL intelligence, ML detection, and report output here.")
        return

    st.session_state.website_analysis = analysis

    if analysis.get("threats_found", 0) == 0:
        st.success(analysis.get("summary", "Scan completed successfully."))
    else:
        st.warning(analysis.get("summary", "Scan completed with findings."))
    render_site_summary(analysis)

    if st.button("Generate Website PDF", type="primary", use_container_width=True):
        path = generate_website_report(analysis)
        st.session_state.website_report_path = path
        st.success("Website PDF report generated.")
    download_pdf(st.session_state.website_report_path, "Download Website PDF", "download_website_pdf")

    st.markdown("### Detailed Results")
    for idx, site in enumerate(analysis.get("analysis_results", []), 1):
        with st.expander(f"{idx}. {site.get('url', 'Unknown')} - {site.get('risk_level', 'Unknown')}", expanded=idx == 1):
            render_website_result(site, idx)


def render_logs_tab():
    st.subheader("Scan Logs")
    logs = read_logs()
    if not logs:
        st.info("No scans have been logged yet.")
        return
    df = pd.DataFrame(logs)
    st.dataframe(df, use_container_width=True, hide_index=True)

    risk_counts = df.get("risk_level")
    if risk_counts is not None:
        st.bar_chart(risk_counts.value_counts())


def render_design_tab():
    st.subheader("Final-Year System Design Flow")
    flow = [
        "User enters a URL or network-flow features.",
        "URL intelligence scanner extracts the domain and checks DNS, SSL, blacklist, and reputation signals.",
        "Controlled interaction captures headers, redirects, cookies, page links, forms, scripts, downloads, and API-like calls.",
        "Feature engineering converts raw observations into model-ready traffic features.",
        "The ML attack detection engine predicts Normal, DoS, Brute Force, Port Scan, Botnet, or Malware Communication.",
        "Threat intelligence maps the result to MITRE ATT&CK techniques and CVE examples.",
        "Risk scoring combines attack probability, severity, exploitability, and URL signals.",
        "The AI recommendation layer produces practical mitigation steps.",
        "The dashboard shows results, logs the event, and generates a PDF report.",
    ]
    for step in flow:
        st.markdown(f"<div class='pipeline'>{step}</div>", unsafe_allow_html=True)

    st.markdown("#### Viva One-Liner")
    st.info(
        "This system takes a URL, analyzes its network behavior, detects cyber threats using machine learning, maps them to global threat intelligence frameworks, calculates risk, and automatically generates actionable mitigation reports."
    )


def main():
    init_state()
    render_css()

    st.markdown(
        """
        <div class="hero">
            <h1>CyberHawk AI Threat Intelligence</h1>
            <p>URL intelligence, ML attack detection, MITRE/CVE mapping, risk scoring, PDF reporting, and mitigation recommendations.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_url, tab_network, tab_logs, tab_design = st.tabs(
        ["URL Analysis", "Network ML", "Logs", "System Design"]
    )
    with tab_url:
        render_website_tab()
    with tab_network:
        render_network_tab()
    with tab_logs:
        render_logs_tab()
    with tab_design:
        render_design_tab()


if __name__ == "__main__":
    main()
