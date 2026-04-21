import streamlit as st
from scanner.engine import ScanEngine
from scanner.reporter import Reporter
import json

# Page config
st.set_page_config(page_title="Cyber Hawk | Web Vulnerability Scanner", layout="wide")

# Custom CSS for aesthetics
st.markdown("""
<style>
    .main {
        background-color: #0e1117;
        color: #ffffff;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
        background-color: #ff4b4b;
        color: white;
        font-weight: bold;
    }
    .stTextInput>div>div>input {
        background-color: #262730;
        color: white;
    }
    .card {
        padding: 20px;
        border-radius: 10px;
        background-color: #262730;
        margin-bottom: 20px;
        border-left: 5px solid #ff4b4b;
    }
    .risk-high { border-left-color: #ff4b4b; }
    .risk-medium { border-left-color: #ffa500; }
    .risk-low { border-left-color: #00ff00; }
</style>
""", unsafe_allow_html=True)

def main():
    st.title("🦅 Cyber Hawk")
    st.subheader("MVP Web Vulnerability Scanner")
    
    st.sidebar.header("Scan Settings")
    url = st.sidebar.text_input("Target URL", placeholder="https://example.com")
    depth = st.sidebar.slider("Crawl Depth", 0, 3, 1)
    
    scan_button = st.sidebar.button("Launch Scan")

    if scan_button:
        if not url.startswith("http"):
            st.error("Please enter a valid URL (including http/https)")
        else:
            with st.spinner(f"Scanning {url}... This may take a minute."):
                try:
                    engine = ScanEngine(url, depth)
                    results = engine.run()
                    
                    st.success(f"Scan complete! Found {len(results)} vulnerabilities.")
                    
                    # Store results in session state for downloading
                    st.session_state['results'] = results
                    st.session_state['target_url'] = url
                    
                    # Display metrics
                    high = len([r for r in results if r['risk'] == "High"])
                    medium = len([r for r in results if r['risk'] == "Medium"])
                    low = len([r for r in results if r['risk'] == "Low"])
                    
                    col1, col2, col3 = st.columns(3)
                    col1.metric("High Risk", high)
                    col2.metric("Medium Risk", medium)
                    col3.metric("Low Risk", low)
                    
                    # Display findings
                    st.write("---")
                    for res in results:
                        risk_class = f"risk-{res['risk'].lower()}"
                        with st.container():
                            st.markdown(f"""
                            <div class="card {risk_class}">
                                <h3>{res['type']}</h3>
                                <p><strong>URL:</strong> {res['url']}</p>
                                <p><strong>Risk Level:</strong> {res['risk']}</p>
                                <p><strong>Description:</strong> {res['description']}</p>
                                <p><strong>Suggested Fix:</strong> {res['fix']}</p>
                                {"<p><strong>Payload:</strong> <code>" + res['payload'] + "</code></p>" if 'payload' in res else ""}
                            </div>
                            """, unsafe_allow_html=True)
                            
                except Exception as e:
                    st.error(f"An error occurred during scan: {e}")

    # Export section
    if 'results' in st.session_state and st.session_state['results']:
        st.write("---")
        st.subheader("Export Results")
        
        col_json, col_pdf = st.columns(2)
        
        # JSON Download
        json_data = Reporter.to_json(st.session_state['results'])
        col_json.download_button(
            label="Download JSON Report",
            data=json_data,
            file_name="cyberhawk_report.json",
            mime="application/json"
        )
        
        # PDF Download (using a simple placeholder or actual generator)
        try:
            pdf_data = Reporter.to_pdf(st.session_state['results'], st.session_state['target_url'])
            col_pdf.download_button(
                label="Download PDF Report",
                data=pdf_data,
                file_name="cyberhawk_report.pdf",
                mime="application/pdf"
            )
        except Exception as e:
            col_pdf.error(f"Error generating PDF: {e}")

if __name__ == "__main__":
    main()
