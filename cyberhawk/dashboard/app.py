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

st.title("🛡️ CyberHawk - Cyber Threat Intelligence System")

st.markdown("""
This system analyzes network traffic patterns to detect and classify cyber threats.
Enter the network feature values separated by commas to analyze the traffic.
""")

# Create columns for better layout
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Network Features")
    input_data = st.text_input(
        "Enter comma-separated feature values:",
        placeholder="100, 5000, 10, 6, 0, 1023, 80, 10, 500",
        help="Features: packet_count, byte_count, duration, protocol, flags, source_port, dest_port, packet_rate, data_rate"
    )

with col2:
    st.subheader("Sample Feature Values")
    st.info("""
    **Normal Traffic:**
    100, 5000, 10, 6, 0, 1023, 80, 10, 500
    
    **DoS Attack:**
    500, 25000, 2, 6, 0, 1027, 9200, 250, 12500
    
    **Malware:**
    600, 30000, 8, 6, 0, 1043, 80, 75, 3750
    """)

if st.button("🔍 Detect Threat", type="primary", use_container_width=True):
    if input_data.strip():
        try:
            values = [float(x.strip()) for x in input_data.split(",")]
            
            if len(values) != 9:
                st.error(f"❌ Error: Expected 9 features, got {len(values)}")
            else:
                # Make prediction
                pred = predict(values)
                threat = get_threat(pred)
                
                # Display results
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric(label="Threat Type", value=threat["type"])
                
                with col2:
                    risk_color = {"Low": "🟢", "Medium": "🟡", "High": "🔴", "Critical": "🔴🔴"}
                    risk_emoji = risk_color.get(threat["risk"], "❓")
                    st.metric(label="Risk Level", value=f"{risk_emoji} {threat['risk']}")
                
                with col3:
                    st.metric(label="Status", value="⚠️ Detected" if threat["risk"] != "Low" else "✅ Safe")
                
                st.divider()
                
                # Detailed information
                st.subheader("📋 Threat Details")
                detail_col1, detail_col2 = st.columns(2)
                
                with detail_col1:
                    st.write("**Description:**")
                    st.write(threat.get("description", "No description available"))
                
                with detail_col2:
                    st.write("**Prediction Score:**")
                    st.write(f"Classification ID: {int(pred)}")
                
                # Generate report
                st.divider()
                report_data = {
                    "Attack Type": threat["type"],
                    "Risk Level": threat["risk"],
                    "Description": threat.get("description", "N/A"),
                    "Input Features": ", ".join(str(v) for v in values)
                }
                
                if st.button("📄 Generate PDF Report", use_container_width=True):
                    try:
                        report_path = generate_report(report_data)
                        st.success(f"✅ Report generated successfully: {os.path.basename(report_path)}")
                        
                        # Provide download link
                        with open(report_path, "rb") as pdf_file:
                            st.download_button(
                                label="📥 Download Report",
                                data=pdf_file,
                                file_name=os.path.basename(report_path),
                                mime="application/pdf"
                            )
                    except Exception as e:
                        st.error(f"❌ Error generating report: {e}")
        
        except ValueError:
            st.error("❌ Error: Please enter valid numbers separated by commas")
        except Exception as e:
            st.error(f"❌ Error during analysis: {e}")
            st.info("Make sure the model files are trained and available in the models/ directory")
    else:
        st.warning("⚠️ Please enter feature values to analyze")
