from fpdf import FPDF
import os
from datetime import datetime
from typing import Dict, List, Optional


def generate_network_report(info, output_path=None):
    """
    Generate a professional PDF report for the threat analysis.
    
    Args:
        info: Dictionary containing threat information
        output_path: Path to save the report (default: report_TIMESTAMP.pdf in project root)
    """
    if output_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(base_dir, f"reports")
        os.makedirs(output_path, exist_ok=True)
        output_path = os.path.join(output_path, f"threat_report_{timestamp}.pdf")
    
    pdf = FPDF()
    pdf.add_page()
    
    # Set margins
    pdf.set_margins(15, 15, 15)
    
    # Header Section
    pdf.set_font("Arial", style="B", size=24)
    pdf.set_text_color(220, 53, 69)  # Red color
    pdf.cell(0, 15, txt="🛡️ CyberHawk", ln=True)
    
    pdf.set_font("Arial", style="", size=11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, txt="Cyber Threat Intelligence System", ln=True)
    pdf.ln(3)
    
    # Horizontal line
    pdf.set_draw_color(220, 53, 69)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(5)
    
    # Report Metadata
    pdf.set_font("Arial", style="B", size=12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 8, txt="Report Details", ln=True)
    
    pdf.set_font("Arial", size=10)
    pdf.set_text_color(80, 80, 80)
    generated_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 7, txt=f"Generated: {generated_time}", ln=True)
    pdf.cell(0, 7, txt=f"Report Type: Network Threat Analysis", ln=True)
    pdf.ln(3)
    
    # Threat Analysis Section
    pdf.set_font("Arial", style="B", size=12)
    pdf.set_text_color(220, 53, 69)
    pdf.cell(0, 10, txt="Threat Analysis Results", ln=True)
    pdf.ln(2)
    
    # Content
    pdf.set_font("Arial", size=10)
    pdf.set_text_color(0, 0, 0)
    
    # Define field order for better readability
    field_order = ["Attack Type", "Risk Level", "Description", "Input Features", "Prediction Score"]
    
    for field in field_order:
        if field in info:
            pdf.set_font("Arial", style="B", size=10)
            pdf.set_text_color(50, 50, 50)
            pdf.cell(50, 8, txt=f"{field}:", ln=False)
            
            pdf.set_font("Arial", style="", size=10)
            pdf.set_text_color(0, 0, 0)
            
            value = str(info[field])
            # Handle long text wrapping
            if len(value) > 80:
                pdf.multi_cell(0, 6, txt=value, align='L')
            else:
                pdf.cell(0, 8, txt=value, ln=True)
            pdf.ln(1)
    
    # Risk Level Color Indicator
    pdf.ln(3)
    pdf.set_font("Arial", style="B", size=10)
    pdf.set_text_color(220, 53, 69)
    pdf.cell(0, 8, txt="Risk Level Summary", ln=True)
    
    risk_level = info.get("Risk Level", "Unknown").upper()
    if "CRITICAL" in risk_level:
        color = (220, 53, 69)  # Red
    elif "HIGH" in risk_level:
        color = (255, 193, 7)  # Orange
    elif "MEDIUM" in risk_level:
        color = (255, 152, 0)  # Yellow
    else:
        color = (76, 175, 80)  # Green
    
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", style="B", size=11)
    pdf.cell(0, 10, txt=f"  {risk_level}", ln=True, fill=True)
    
    # Recommendations
    pdf.ln(5)
    pdf.set_font("Arial", style="B", size=10)
    pdf.set_text_color(220, 53, 69)
    pdf.cell(0, 8, txt="Recommendations", ln=True)
    
    pdf.set_font("Arial", size=9)
    pdf.set_text_color(0, 0, 0)
    
    risk = info.get("Risk Level", "").lower()
    if "critical" in risk or "high" in risk:
        recommendations = [
            "• Immediately isolate affected systems from the network",
            "• Initiate incident response procedures",
            "• Notify security operations center (SOC)",
            "• Begin forensic analysis and logging",
            "• Review access logs for compromise indicators"
        ]
    elif "medium" in risk:
        recommendations = [
            "• Monitor affected systems closely",
            "• Review recent system activity and logs",
            "• Update security policies if needed",
            "• Schedule security assessment"
        ]
    else:
        recommendations = [
            "• Continue normal monitoring",
            "• Maintain security best practices",
            "• Keep systems updated and patched"
        ]
    
    for rec in recommendations:
        pdf.multi_cell(0, 6, txt=rec, align='L')
    
    # Footer
    pdf.ln(5)
    pdf.set_draw_color(220, 53, 69)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(3)
    
    pdf.set_font("Arial", style="I", size=8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, txt="This report was automatically generated by the Cyber Threat Intelligence System (CyberHawk).", align='C', ln=True)
    pdf.cell(0, 6, txt="For more information, visit: cyberhawk.security", align='C', ln=True)
    
    pdf.output(output_path)
    return output_path


def generate_website_report(website_analysis, output_path=None):
    """
    Generate a professional PDF report for website threat analysis.
    
    Args:
        website_analysis: Dictionary containing website threat analysis results
        output_path: Path to save the report
    """
    if output_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(base_dir, f"reports")
        os.makedirs(output_path, exist_ok=True)
        output_path = os.path.join(output_path, f"website_threat_report_{timestamp}.pdf")
    
    pdf = FPDF()
    pdf.add_page()
    
    # Set margins
    pdf.set_margins(15, 15, 15)
    
    # Header Section
    pdf.set_font("Arial", style="B", size=24)
    pdf.set_text_color(220, 53, 69)  # Red color
    pdf.cell(0, 15, txt="🛡️ CyberHawk", ln=True)
    
    pdf.set_font("Arial", style="", size=11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, txt="Website Threat Intelligence Report", ln=True)
    pdf.ln(3)
    
    # Horizontal line
    pdf.set_draw_color(220, 53, 69)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(5)
    
    # Report Metadata
    pdf.set_font("Arial", style="B", size=12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 8, txt="Report Details", ln=True)
    
    pdf.set_font("Arial", size=10)
    pdf.set_text_color(80, 80, 80)
    generated_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 7, txt=f"Generated: {generated_time}", ln=True)
    pdf.cell(0, 7, txt=f"Report Type: Website Threat Analysis", ln=True)
    
    # Summary Section
    if "urls_analyzed" in website_analysis:
        pdf.ln(2)
        pdf.cell(0, 7, txt=f"URLs Analyzed: {website_analysis['urls_analyzed']}", ln=True)
        pdf.cell(0, 7, txt=f"Threats Found: {website_analysis['threats_found']}", ln=True)
    
    pdf.ln(3)
    
    # Threat Summary Statistics
    if "critical_count" in website_analysis:
        pdf.set_font("Arial", style="B", size=11)
        pdf.set_text_color(220, 53, 69)
        pdf.cell(0, 8, txt="Threat Summary", ln=True)
        
        pdf.set_font("Arial", size=10)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 7, txt=f"🔴 Critical: {website_analysis.get('critical_count', 0)}", ln=True)
        pdf.cell(0, 7, txt=f"🟠 High: {website_analysis.get('high_count', 0)}", ln=True)
        pdf.cell(0, 7, txt=f"🟡 Medium: {website_analysis.get('medium_count', 0)}", ln=True)
        pdf.cell(0, 7, txt=f"🟢 Low: {website_analysis.get('low_count', 0)}", ln=True)
        pdf.ln(3)
    
    # Individual Website Analysis Results
    pdf.set_font("Arial", style="B", size=11)
    pdf.set_text_color(220, 53, 69)
    pdf.cell(0, 8, txt="Website Analysis Results", ln=True)
    pdf.ln(2)
    
    if "analysis_results" in website_analysis:
        for idx, site_analysis in enumerate(website_analysis["analysis_results"], 1):
            pdf.set_font("Arial", style="B", size=10)
            pdf.set_text_color(50, 50, 50)
            pdf.cell(0, 8, txt=f"Website #{idx}", ln=True)
            
            pdf.set_font("Arial", size=9)
            pdf.set_text_color(0, 0, 0)
            
            # URL
            pdf.cell(30, 7, txt="URL: ", ln=False)
            url = site_analysis.get("url", "N/A")
            if len(url) > 80:
                pdf.multi_cell(0, 5, txt=url, align='L')
            else:
                pdf.cell(0, 7, txt=url, ln=True)
            
            # Threat Type and Risk Level
            pdf.cell(0, 7, txt=f"Threat Type: {site_analysis.get('threat_type', 'Unknown')}", ln=True)
            
            # Risk Level with color
            risk_level = site_analysis.get("risk_level", "Unknown")
            pdf.cell(0, 7, txt=f"Risk Level: {risk_level}", ln=True)
            
            # Threat Score
            if "threat_score" in site_analysis:
                pdf.cell(0, 7, txt=f"Threat Score: {site_analysis['threat_score']}/100", ln=True)
            
            # Detected Threats
            if site_analysis.get("detected_threats"):
                pdf.set_font("Arial", style="B", size=9)
                pdf.cell(0, 7, txt="Detected Threats:", ln=True)
                pdf.set_font("Arial", size=9)
                for threat in site_analysis["detected_threats"]:
                    pdf.cell(0, 6, txt=f"  • {threat}", ln=True)
            
            # Error handling
            if "error" in site_analysis:
                pdf.set_text_color(220, 53, 69)
                pdf.cell(0, 7, txt=f"Error: {site_analysis['error']}", ln=True)
                pdf.set_text_color(0, 0, 0)
            
            pdf.ln(2)
    
    # Recommendations
    pdf.ln(3)
    pdf.set_font("Arial", style="B", size=10)
    pdf.set_text_color(220, 53, 69)
    pdf.cell(0, 8, txt="Recommendations", ln=True)
    
    pdf.set_font("Arial", size=9)
    pdf.set_text_color(0, 0, 0)
    
    threat_found = website_analysis.get("threats_found", 0) > 0
    if threat_found:
        if website_analysis.get("critical_count", 0) > 0:
            recommendations = [
                "• DO NOT visit these websites",
                "• Block these domains at your firewall/proxy level",
                "• Implement email filters to prevent links to these sites",
                "• Alert users about the detected threats",
                "• Run security awareness training"
            ]
        elif website_analysis.get("high_count", 0) > 0:
            recommendations = [
                "• Exercise caution before visiting these websites",
                "• Consider blocking at network level",
                "• Monitor any systems that have accessed these sites",
                "• Update security awareness policies",
                "• Schedule periodic security audits"
            ]
        else:
            recommendations = [
                "• Monitor these websites for changes",
                "• Review access logs for these domains",
                "• Maintain standard security measures",
                "• Update security policies as needed"
            ]
    else:
        recommendations = [
            "• Continue regular security monitoring",
            "• Maintain current security measures",
            "• Review this report periodically",
            "• Keep security systems updated"
        ]
    
    for rec in recommendations:
        pdf.multi_cell(0, 6, txt=rec, align='L')
    
    # Footer
    pdf.ln(5)
    pdf.set_draw_color(220, 53, 69)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(3)
    
    pdf.set_font("Arial", style="I", size=8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, txt="This report was automatically generated by the Cyber Threat Intelligence System (CyberHawk).", align='C', ln=True)
    pdf.cell(0, 6, txt="For more information, visit: cyberhawk.security", align='C', ln=True)
    
    pdf.output(output_path)
    return output_path


def generate_report(info, output_path=None):
    """
    Legacy function - redirects to network report for backward compatibility
    """
    return generate_network_report(info, output_path)
