import streamlit as st
import os
import sys
from pathlib import Path

# Add the parent directory to the path to import src modules
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.predict import predict
from src.threat_intel import get_threat
from src.report_generator import generate_report, generate_website_report
from src.website_threat_analyzer import analyze_website, analyze_multiple_urls

st.set_page_config(page_title="CyberHawk - Cyber Threat Intelligence System", layout="wide")

# Initialize session state
if "last_report_path" not in st.session_state:
    st.session_state.last_report_path = None
if "last_report_data" not in st.session_state:
    st.session_state.last_report_data = None
if "report_generated" not in st.session_state:
    st.session_state.report_generated = False
if "website_report_path" not in st.session_state:
    st.session_state.website_report_path = None
if "website_analysis_result" not in st.session_state:
    st.session_state.website_analysis_result = None

# Professional CSS for the entire app
st.markdown("""
<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 25px;
        border-radius: 12px;
        margin-bottom: 25px;
        box-shadow: 0 6px 15px rgba(0,0,0,0.1);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    .header-left {
        flex: 1;
    }
    
    .header-title {
        color: white;
        font-size: 36px;
        font-weight: 900;
        margin: 0;
        letter-spacing: 1px;
    }
    
    .header-subtitle {
        color: rgba(255,255,255,0.9);
        font-size: 13px;
        margin-top: 8px;
        font-weight: 500;
    }
    
    .header-right {
        display: flex;
        gap: 10px;
        align-items: center;
    }
    
    .input-section {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
    }
    
    .section-title {
        font-size: 18px;
        font-weight: 700;
        color: #333;
        margin-bottom: 15px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        box-shadow: 0 2px 6px rgba(0,0,0,0.05);
    }
    
    .metric-label {
        font-size: 12px;
        color: #666;
        font-weight: 600;
        text-transform: uppercase;
        margin-bottom: 8px;
    }
    
    .metric-value {
        font-size: 24px;
        color: #333;
        font-weight: bold;
    }
    
    .threat-item {
        background: #f8f9fa;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #dc3545;
        margin: 10px 0;
    }
    
    .threat-item.safe {
        border-left-color: #28a745;
        background: #f0f8f5;
    }
    
    .threat-item.warning {
        border-left-color: #ffc107;
        background: #fffbf0;
    }
    
    .threat-item.danger {
        border-left-color: #dc3545;
        background: #ffe5e5;
    }
    
    .threat-title {
        font-weight: 700;
        font-size: 14px;
        margin-bottom: 8px;
    }
    
    .threat-detail {
        font-size: 13px;
        color: #555;
        margin: 4px 0;
    }
    
    .url-result-card {
        background: white;
        border: 2px solid #e0e0e0;
        padding: 18px;
        border-radius: 10px;
        margin: 15px 0;
    }
    
    .url-header {
        display: flex;
        justify-content: space-between;
        align-items: start;
        margin-bottom: 12px;
        flex-wrap: wrap;
        gap: 10px;
    }
    
    .url-name {
        font-weight: 700;
        color: #333;
        word-break: break-all;
        flex: 1;
        min-width: 200px;
    }
    
    .risk-badge {
        display: inline-block;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        white-space: nowrap;
    }
    
    .risk-badge.critical {
        background: #dc3545;
        color: white;
    }
    
    .risk-badge.high {
        background: #fd7e14;
        color: white;
    }
    
    .risk-badge.medium {
        background: #ffc107;
        color: black;
    }
    
    .risk-badge.low {
        background: #28a745;
        color: white;
    }
    
    .threat-score-bar {
        width: 100%;
        height: 8px;
        background: #e0e0e0;
        border-radius: 4px;
        margin: 12px 0;
        overflow: hidden;
    }
    
    .threat-score-fill {
        height: 100%;
        background: linear-gradient(90deg, #28a745 0%, #ffc107 50%, #dc3545 100%);
        transition: width 0.3s ease;
    }
    
    .footer {
        text-align: center;
        color: #888;
        font-size: 12px;
        margin-top: 50px;
        padding-top: 20px;
        border-top: 1px solid #e0e0e0;
    }
    
    @media (max-width: 768px) {
        .main-header {
            flex-direction: column;
            gap: 15px;
        }
        
        .header-title {
            font-size: 28px;
        }
        
        .metric-card {
            min-width: 140px;
        }
    }
</style>
""", unsafe_allow_html=True)

# Main Header
col1, col2 = st.columns([4, 1])

with col1:
    st.markdown("""
    <div class="main-header">
        <div class="header-left">
            <div class="header-title">🛡️ CyberHawk</div>
            <div class="header-subtitle">Advanced Cyber Threat Intelligence System</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)
    if st.session_state.report_generated and st.session_state.last_report_path:
        try:
            with open(st.session_state.last_report_path, "rb") as pdf_file:
                st.download_button(
                    label="📥 Network Report",
                    data=pdf_file.read(),
                    file_name=os.path.basename(st.session_state.last_report_path),
                    mime="application/pdf",
                    use_container_width=True,
                    key="header_download_network"
                )
        except:
            pass
    
    if st.session_state.website_report_path:
        try:
            with open(st.session_state.website_report_path, "rb") as pdf_file:
                st.download_button(
                    label="📥 Website Report",
                    data=pdf_file.read(),
                    file_name=os.path.basename(st.session_state.website_report_path),
                    mime="application/pdf",
                    use_container_width=True,
                    key="header_download_website"
                )
        except:
            pass

# Create tabs
tab1, tab2 = st.tabs(["🔗 Network Threat Analysis", "🌐 Website Threat Analysis"])

# ==================== TAB 1: NETWORK ANALYSIS ====================
with tab1:
    st.markdown("""
    <div class="input-section">
        <div class="section-title">📊 Enter Network Features</div>
        <p style="color: #666; font-size: 13px; margin: 0;">
        Analyze network traffic by entering 9 comma-separated feature values.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        input_data = st.text_input(
            "Network feature values:",
            placeholder="100, 5000, 10, 6, 0, 1023, 80, 10, 500",
            help="Features: packet_count, byte_count, duration, protocol, flags, source_port, dest_port, packet_rate, data_rate",
            label_visibility="collapsed"
        )
    
    with col2:
        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
        analyze_btn = st.button("🔍 Detect Threat", use_container_width=True, type="primary", key="network_analyze")
    
    # Display sample values
    with st.expander("📋 Sample Network Features"):
        col1, col2, col3 = st.columns(3)
        with col1:
            st.info("""**Normal Traffic**
            100, 5000, 10, 6, 0, 1023, 80, 10, 500""")
        with col2:
            st.warning("""**DoS Attack**
            500, 25000, 2, 6, 0, 1027, 9200, 250, 12500""")
        with col3:
            st.error("""**Malware**
            600, 30000, 8, 6, 0, 1043, 80, 75, 3750""")
    
    # Analyze Network Threats
    if analyze_btn:
        if input_data.strip():
            try:
                values = [float(x.strip()) for x in input_data.split(",")]
                
                if len(values) != 9:
                    st.error(f"❌ Error: Expected 9 features, got {len(values)}")
                else:
                    with st.spinner("🔍 Analyzing network traffic..."):
                        pred = predict(values)
                        threat = get_threat(pred)
                    
                    # Display Metrics
                    st.markdown("<div class='section-title'>📊 Analysis Results</div>", unsafe_allow_html=True)
                    
                    metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
                    
                    with metric_col1:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-label">Threat Type</div>
                            <div class="metric-value">{threat["type"]}</div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with metric_col2:
                        risk_color = {"Low": "#28a745", "Medium": "#ffc107", "High": "#fd7e14", "Critical": "#dc3545"}
                        risk_icon = {"Low": "🟢", "Medium": "🟡", "High": "🔴", "Critical": "🔴🔴"}
                        risk_emoji = risk_icon.get(threat["risk"], "❓")
                        st.markdown(f"""
                        <div class="metric-card" style="background: {risk_color.get(threat['risk'], '#6c757d')}40;">
                            <div class="metric-label">Risk Level</div>
                            <div class="metric-value">{risk_emoji} {threat['risk']}</div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with metric_col3:
                        status = "✅ Safe" if threat["risk"] == "Low" else "🚨 Detected"
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-label">Status</div>
                            <div class="metric-value">{status}</div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with metric_col4:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-label">Prediction ID</div>
                            <div class="metric-value">{int(pred)}</div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    # Display Threat Details
                    st.markdown("<div class='section-title' style='margin-top: 25px;'>📋 Threat Details</div>", unsafe_allow_html=True)
                    
                    threat_class = "safe" if threat["risk"] == "Low" else "warning" if threat["risk"] == "Medium" else "danger"
                    st.markdown(f"""
                    <div class="threat-item {threat_class}">
                        <div class="threat-title">{threat['type']}</div>
                        <div class="threat-detail"><strong>Risk Level:</strong> {threat['risk']}</div>
                        <div class="threat-detail"><strong>Description:</strong> {threat.get('description', 'N/A')}</div>
                        <div class="threat-detail"><strong>Input Features:</strong> {', '.join(str(v) for v in values)}</div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Generate Report
                    st.markdown("<div class='section-title' style='margin-top: 25px;'>📄 Generate Report</div>", unsafe_allow_html=True)
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.button("📝 Generate PDF Report", use_container_width=True, type="primary"):
                            try:
                                report_data = {
                                    "Attack Type": threat["type"],
                                    "Risk Level": threat["risk"],
                                    "Description": threat.get("description", "N/A"),
                                    "Input Features": ", ".join(str(v) for v in values),
                                    "Prediction Score": str(int(pred))
                                }
                                
                                with st.spinner("📄 Generating PDF report..."):
                                    report_path = generate_report(report_data)
                                    st.session_state.last_report_path = report_path
                                    st.session_state.last_report_data = report_data
                                    st.session_state.report_generated = True
                                
                                st.success("✅ Report generated successfully!")
                                
                                with open(report_path, "rb") as pdf_file:
                                    st.download_button(
                                        label="💾 Download Network Report PDF",
                                        data=pdf_file.read(),
                                        file_name=os.path.basename(report_path),
                                        mime="application/pdf",
                                        use_container_width=True,
                                        key="network_download"
                                    )
                            except Exception as e:
                                st.error(f"❌ Error generating report: {e}")
                    
                    with col2:
                        if st.button("📋 View Report Data (JSON)", use_container_width=True):
                            st.json(report_data)
            
            except ValueError:
                st.error("❌ Error: Please enter valid numbers separated by commas")
            except Exception as e:
                st.error(f"❌ Error during analysis: {e}")
                st.info("ℹ️ Make sure the model files are trained and available")
        else:
            st.warning("⚠️ Please enter feature values to analyze")

# ==================== TAB 2: WEBSITE ANALYSIS ====================
with tab2:
    st.markdown("""
    <div class="input-section">
        <div class="section-title">🌐 Enter Website URLs</div>
        <p style="color: #666; font-size: 13px; margin: 0;">
        Enter website URLs (one per line) to analyze for threats and vulnerabilities.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    urls_input = st.text_area(
        "Website URLs:",
        placeholder="https://example.com\nhttps://website.com\nhttp://another-site.org",
        height=120,
        help="Enter one URL per line. URLs can start with http:// or https://",
        label_visibility="collapsed"
    )
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        analyze_website_btn = st.button("🔍 Scan Websites", use_container_width=True, type="primary", key="website_analyze")
    
    with col2:
        if st.button("📋 Paste Example URLs", use_container_width=True):
            st.info("""
            Example URLs to test:
            - https://google.com (Safe)
            - https://example-phishing.com (Suspicious)
            - http://192.168.1.1 (IP-based, suspicious)
            """)
    
    # Analyze Websites
    if analyze_website_btn:
        if urls_input.strip():
            url_list = [url.strip() for url in urls_input.split("\n") if url.strip()]
            
            if url_list:
                with st.spinner("🔍 Scanning websites for threats..."):
                    website_analysis = analyze_multiple_urls(url_list)
                    st.session_state.website_analysis_result = website_analysis
                
                # Display Summary
                st.markdown("<div class='section-title'>📊 Scan Summary</div>", unsafe_allow_html=True)
                
                col1, col2, col3, col4, col5 = st.columns(5)
                
                with col1:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-label">URLs Analyzed</div>
                        <div class="metric-value">{website_analysis['urls_analyzed']}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    st.markdown(f"""
                    <div class="metric-card" style="background: #dc354540;">
                        <div class="metric-label">Critical</div>
                        <div class="metric-value">{website_analysis['critical_count']}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col3:
                    st.markdown(f"""
                    <div class="metric-card" style="background: #fd7e1440;">
                        <div class="metric-label">High</div>
                        <div class="metric-value">{website_analysis['high_count']}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col4:
                    st.markdown(f"""
                    <div class="metric-card" style="background: #ffc10740;">
                        <div class="metric-label">Medium</div>
                        <div class="metric-value">{website_analysis['medium_count']}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col5:
                    st.markdown(f"""
                    <div class="metric-card" style="background: #28a74540;">
                        <div class="metric-label">Low</div>
                        <div class="metric-value">{website_analysis['low_count']}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Overall Summary
                summary_msg = website_analysis.get("summary", "")
                if "No threats" in summary_msg:
                    st.success(f"✅ {summary_msg}")
                else:
                    st.warning(f"⚠️ {summary_msg}")
                
                # Display Individual Results
                st.markdown("<div class='section-title' style='margin-top: 25px;'>🔍 Detailed Results</div>", unsafe_allow_html=True)
                
                for idx, analysis in enumerate(website_analysis["analysis_results"], 1):
                    risk_level = analysis.get("risk_level", "Unknown").lower()
                    risk_class = "low" if risk_level == "low" else "medium" if risk_level == "medium" else "high" if risk_level == "high" else "critical"
                    
                    st.markdown(f"""
                    <div class="url-result-card">
                        <div class="url-header">
                            <div class="url-name">#{idx} {analysis.get('url', 'Unknown')}</div>
                            <span class="risk-badge {risk_class}">{risk_level}</span>
                        </div>
                    """, unsafe_allow_html=True)
                    
                    # Threat Type
                    st.markdown(f"""
                    <div class="threat-detail"><strong>🎯 Threat Type:</strong> {analysis.get('threat_type', 'Unknown')}</div>
                    """, unsafe_allow_html=True)
                    
                    # Threat Score
                    if "threat_score" in analysis:
                        score = analysis["threat_score"]
                        st.markdown(f"""
                        <div class="threat-detail"><strong>📊 Threat Score:</strong> {score}/100</div>
                        <div class="threat-score-bar">
                            <div class="threat-score-fill" style="width: {min(score, 100)}%"></div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    # Detected Threats
                    if analysis.get("detected_threats"):
                        st.markdown("<div class='threat-detail'><strong>🚨 Detected Threats:</strong></div>", unsafe_allow_html=True)
                        for threat in analysis["detected_threats"]:
                            st.markdown(f"<div class='threat-detail' style='margin-left: 20px;'>• {threat}</div>", unsafe_allow_html=True)
                    
                    # Error handling
                    if "error" in analysis:
                        st.markdown(f"""
                        <div class="threat-detail" style="color: #dc3545;"><strong>⚠️ Error:</strong> {analysis['error']}</div>
                        """, unsafe_allow_html=True)
                    
                    st.markdown("</div>", unsafe_allow_html=True)
                
                # Generate Website Report
                st.markdown("<div class='section-title' style='margin-top: 25px;'>📄 Generate Report</div>", unsafe_allow_html=True)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    if st.button("📝 Generate Website Threat Report", use_container_width=True, type="primary"):
                        try:
                            with st.spinner("📄 Generating PDF report..."):
                                report_path = generate_website_report(website_analysis)
                                st.session_state.website_report_path = report_path
                            
                            st.success("✅ Website threat report generated successfully!")
                            
                            with open(report_path, "rb") as pdf_file:
                                st.download_button(
                                    label="💾 Download Website Report PDF",
                                    data=pdf_file.read(),
                                    file_name=os.path.basename(report_path),
                                    mime="application/pdf",
                                    use_container_width=True,
                                    key="website_download"
                                )
                        except Exception as e:
                            st.error(f"❌ Error generating report: {e}")
                
                with col2:
                    if st.button("📋 View Report Data (JSON)", use_container_width=True):
                        st.json(website_analysis)
            else:
                st.warning("⚠️ Please enter at least one URL to analyze")
        else:
            st.warning("⚠️ Please enter website URLs to analyze")

# Footer
st.markdown("""
<div class="footer">
    <p><strong>🛡️ CyberHawk Threat Intelligence System</strong></p>
    <p>Advanced network and website threat detection powered by machine learning</p>
    <p style="margin-top: 15px; font-size: 11px;">
    ℹ️ This system analyzes network traffic patterns and website characteristics to identify potential security threats. 
    Always consult with security professionals before taking action on detected threats.
    </p>
</div>
""", unsafe_allow_html=True)
