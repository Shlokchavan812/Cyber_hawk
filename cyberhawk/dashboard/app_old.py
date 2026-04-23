import streamlit as st
import os
import sys
from pathlib import Path

# Add the parent directory to the path to import src modules
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.predict import predict
from src.threat_intel import get_threat
from src.report_generator import generate_report

st.set_page_config(page_title="CyberHawk - Cyber Threat Intelligence System", layout="wide")

# Initialize session state
if "last_report_path" not in st.session_state:
    st.session_state.last_report_path = None
if "last_report_data" not in st.session_state:
    st.session_state.last_report_data = None
if "report_generated" not in st.session_state:
    st.session_state.report_generated = False

# Custom CSS for responsive design
st.markdown("""
<style>
    .header-container {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 20px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 10px;
        margin-bottom: 30px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    .header-title {
        color: white;
        font-size: 32px;
        font-weight: bold;
        margin: 0;
        flex: 1;
    }
    
    .header-subtitle {
        color: rgba(255,255,255,0.9);
        font-size: 12px;
        font-weight: normal;
        margin-top: 5px;
    }
    
    .download-section {
        display: flex;
        align-items: center;
        gap: 10px;
        background: rgba(255,255,255,0.1);
        padding: 12px 20px;
        border-radius: 8px;
        backdrop-filter: blur(10px);
    }
    
    .status-badge {
        display: inline-block;
        padding: 6px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: bold;
        color: white;
    }
    
    .status-safe {
        background-color: #4CAF50;
    }
    
    .status-warning {
        background-color: #FF9800;
    }
    
    .status-danger {
        background-color: #f44336;
    }
    
    .threat-card {
        padding: 20px;
        border-radius: 10px;
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        margin: 15px 0;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    .metric-card {
        text-align: center;
        padding: 15px;
        border-radius: 8px;
        background: white;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    
    .pdf-button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 10px 20px;
        border-radius: 6px;
        border: none;
        cursor: pointer;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    
    .pdf-button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }
</style>
""", unsafe_allow_html=True)

# Header with Download Section
col1, col2 = st.columns([3, 1])

with col1:
    st.markdown("""
    <div class="header-container">
        <div>
            <div class="header-title">🛡️ CyberHawk</div>
            <div class="header-subtitle">Cyber Threat Intelligence System</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)
    if st.session_state.report_generated and st.session_state.last_report_path:
        try:
            with open(st.session_state.last_report_path, "rb") as pdf_file:
                st.download_button(
                    label="📥 Download PDF Report",
                    data=pdf_file.read(),
                    file_name=os.path.basename(st.session_state.last_report_path),
                    mime="application/pdf",
                    use_container_width=True,
                    key="header_download"
                )
        except:
            pass

st.markdown("""
---
**Analyze network traffic patterns to detect and classify cyber threats.**  
Enter the network feature values separated by commas to analyze the traffic.
""")

# Create responsive layout
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("🔧 Network Features Input")
    input_data = st.text_input(
        "Enter comma-separated feature values:",
        placeholder="100, 5000, 10, 6, 0, 1023, 80, 10, 500",
        help="Features: packet_count, byte_count, duration, protocol, flags, source_port, dest_port, packet_rate, data_rate"
    )

with col2:
    st.subheader("📋 Sample Values")
    st.info("""
    **Normal Traffic:**
    100, 5000, 10, 6, 0, 1023, 80, 10, 500
    
    **DoS Attack:**
    500, 25000, 2, 6, 0, 1027, 9200, 250, 12500
    
    **Malware:**
    600, 30000, 8, 6, 0, 1043, 80, 75, 3750
    """)

# Analyze Button
if st.button("🔍 Detect Threat", type="primary", use_container_width=True):
    if input_data.strip():
        try:
            values = [float(x.strip()) for x in input_data.split(",")]
            
            if len(values) != 9:
                st.error(f"❌ Error: Expected 9 features, got {len(values)}")
            else:
                # Make prediction
                with st.spinner("🔍 Analyzing threat..."):
                    pred = predict(values)
                    threat = get_threat(pred)
                
                # Display results in metrics
                st.markdown("### 📊 Threat Analysis Results")
                metric_col1, metric_col2, metric_col3 = st.columns(3)
                
                with metric_col1:
                    st.metric(label="🎯 Threat Type", value=threat["type"])
                
                with metric_col2:
                    risk_color = {"Low": "🟢", "Medium": "🟡", "High": "🔴", "Critical": "🔴🔴"}
                    risk_emoji = risk_color.get(threat["risk"], "❓")
                    st.metric(label="⚠️ Risk Level", value=f"{risk_emoji} {threat['risk']}")
                
                with metric_col3:
                    status = "✅ Safe" if threat["risk"] == "Low" else "🚨 Detected"
                    status_class = "status-safe" if threat["risk"] == "Low" else "status-danger"
                    st.metric(label="📍 Status", value=status)
                
                st.divider()
                
                # Detailed threat information in responsive cards
                st.markdown("### 📋 Detailed Threat Information")
                threat_col1, threat_col2 = st.columns(2)
                
                with threat_col1:
                    st.markdown(f"""
                    <div class="threat-card">
                        <h4>📖 Description</h4>
                        <p>{threat.get('description', 'No description available')}</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                with threat_col2:
                    st.markdown(f"""
                    <div class="threat-card">
                        <h4>🔢 Analysis Data</h4>
                        <p><strong>Classification ID:</strong> {int(pred)}</p>
                        <p><strong>Risk Level:</strong> {threat['risk']}</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.divider()
                
                # Generate and display report
                st.markdown("### 📄 Generate PDF Report")
                
                report_data = {
                    "Attack Type": threat["type"],
                    "Risk Level": threat["risk"],
                    "Description": threat.get("description", "N/A"),
                    "Input Features": ", ".join(str(v) for v in values),
                    "Prediction Score": str(int(pred))
                }
                
                col_btn1, col_btn2 = st.columns(2)
                
                with col_btn1:
                    if st.button("📝 Generate & Download PDF", use_container_width=True, type="primary"):
                        try:
                            with st.spinner("📄 Generating PDF report..."):
                                report_path = generate_report(report_data)
                                st.session_state.last_report_path = report_path
                                st.session_state.last_report_data = report_data
                                st.session_state.report_generated = True
                            
                            # Show success message
                            st.success(f"✅ Report generated successfully!")
                            st.info(f"📁 Report saved as: `{os.path.basename(report_path)}`")
                            
                            # Provide download button
                            with open(report_path, "rb") as pdf_file:
                                st.download_button(
                                    label="💾 Click to Download Report",
                                    data=pdf_file.read(),
                                    file_name=os.path.basename(report_path),
                                    mime="application/pdf",
                                    use_container_width=True,
                                    key="result_download"
                                )
                        except Exception as e:
                            st.error(f"❌ Error generating report: {e}")
                
                with col_btn2:
                    if st.button("📋 View Report Data (JSON)", use_container_width=True):
                        st.json(report_data)
        
        except ValueError:
            st.error("❌ Error: Please enter valid numbers separated by commas")
        except Exception as e:
            st.error(f"❌ Error during analysis: {e}")
            st.info("ℹ️ Make sure the model files are trained and available in the models/ directory")
    else:
        st.warning("⚠️ Please enter feature values to analyze")

st.divider()

# Footer information
st.markdown("""
<div style="text-align: center; color: #888; font-size: 12px; margin-top: 50px;">
    <p><strong>CyberHawk Threat Intelligence System</strong></p>
    <p>Advanced network threat detection and analysis powered by machine learning</p>
    <p style="margin-top: 10px; font-size: 11px;">For more information about this system, check the documentation or contact your security administrator.</p>
</div>
""", unsafe_allow_html=True)
