import json
from fpdf import FPDF
import datetime

class Reporter:
    @staticmethod
    def to_json(results):
        """Converts results to a JSON string."""
        return json.dumps(results, indent=4)

    @staticmethod
    def to_pdf(results, target_url):
        """Generates a PDF report from the results."""
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="Cyber Hawk - Vulnerability Scan Report", ln=True, align='C')
        
        # Meta info
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt=f"Target URL: {target_url}", ln=True)
        pdf.cell(200, 10, txt=f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.ln(10)
        
        if not results:
            pdf.cell(200, 10, txt="No vulnerabilities found.", ln=True)
        else:
            for i, result in enumerate(results):
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(200, 10, txt=f"{i+1}. {result['type']}", ln=True)
                
                pdf.set_font("Arial", size=10)
                pdf.cell(200, 8, txt=f"URL: {result['url']}", ln=True)
                pdf.cell(200, 8, txt=f"Risk: {result['risk']}", ln=True)
                
                pdf.multi_cell(0, 8, txt=f"Description: {result['description']}")
                pdf.multi_cell(0, 8, txt=f"Fix: {result['fix']}")
                
                if 'payload' in result:
                    pdf.cell(200, 8, txt=f"Payload: {result['payload']}", ln=True)
                
                pdf.ln(5)
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
                pdf.ln(5)

        return pdf.output()
