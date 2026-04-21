import requests
from urllib.parse import urljoin

class VulnScanner:
    def __init__(self):
        # Payloads for testing
        self.sqli_payloads = ["' OR '1'='1", "'--", '" OR "1"="1']
        self.xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        
    def check_security_headers(self, url):
        """Checks for missing security headers."""
        findings = []
        try:
            response = requests.get(url, timeout=5)
            headers = response.headers
            
            header_info = {
                "Content-Security-Policy": {
                    "desc": "Missing Content-Security-Policy (CSP) header. CSP is a security layer that helps detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.",
                    "fix": "Implement a strong CSP header that restricts the sources from which scripts, styles, and other resources can be loaded."
                },
                "X-Frame-Options": {
                    "desc": "Missing X-Frame-Options header. This header protects users against 'Clickjacking' attacks by ensuring that your content is not embedded into other sites via frames.",
                    "fix": "Set the X-Frame-Options header to 'DENY' or 'SAMEORIGIN' to prevent malicious embedding."
                },
                "X-Content-Type-Options": {
                    "desc": "Missing X-Content-Type-Options header. This prevents the browser from 'sniffing' the MIME type, which can lead to the browser executing malicious files as scripts.",
                    "fix": "Set the X-Content-Type-Options header to 'nosniff'."
                },
                "Strict-Transport-Security": {
                    "desc": "Missing Strict-Transport-Security (HSTS) header. HSTS tells the browser that it should only interact with the site using HTTPS, preventing protocol downgrade attacks.",
                    "fix": "Add the 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header to enforce HTTPS."
                }
            }

            missing_headers = []
            if "Content-Security-Policy" not in headers:
                missing_headers.append("Content-Security-Policy")
            if "X-Frame-Options" not in headers:
                missing_headers.append("X-Frame-Options")
            if "X-Content-Type-Options" not in headers:
                missing_headers.append("X-Content-Type-Options")
            if "Strict-Transport-Security" not in headers:
                missing_headers.append("Strict-Transport-Security")

            for header in missing_headers:
                info = header_info.get(header, {
                    "desc": f"The security header '{header}' is missing, which can expose the site to various attacks.",
                    "fix": f"Add the '{header}' header to your server configuration."
                })
                findings.append({
                    "url": url,
                    "type": "Missing Security Header",
                    "vulnerability": header,
                    "risk": "Low",
                    "description": info["desc"],
                    "fix": info["fix"]
                })
        except Exception as e:
            print(f"Error checking headers for {url}: {e}")
        return findings

    def test_sqli(self, form):
        """Tests a form for basic SQL Injection."""
        findings = []
        target_url = urljoin(form["url"], form["action"])
        
        for payload in self.sqli_payloads:
            data = {}
            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "search", "password"]:
                    data[input_field["name"]] = payload
                else:
                    data[input_field["name"]] = "test"
            
            try:
                if form["method"] == "post":
                    response = requests.post(target_url, data=data, timeout=5)
                else:
                    response = requests.get(target_url, params=data, timeout=5)
                
                # Check for common database errors in the response
                errors = [
                    "you have an error in your sql syntax",
                    "warning: mysql_fetch",
                    "unclosed quotation mark after the character string",
                    "postgresql query failed",
                ]
                
                for error in errors:
                    if error in response.text.lower():
                        findings.append({
                            "url": form["url"],
                            "type": "SQL Injection (SQLi)",
                            "payload": payload,
                            "risk": "High",
                            "description": f"A potential SQL Injection vulnerability was discovered. Cyber Hawk injected '{payload}' and the server responded with a database error message. This suggests that user input is being directly concatenated into a database query, allowing an attacker to manipulate or steal sensitive data from your database.",
                            "fix": "Use parameterized queries or prepared statements (using tools like PDO for PHP, or placeholders in Python/Node.js). Never trust user input and ensure all data is correctly escaped."
                        })
                        return findings # Found one, move on
            except Exception as e:
                print(f"Error testing SQLi on {target_url}: {e}")
                
        return findings

    def test_xss(self, form):
        """Tests a form for Cross-Site Scripting (XSS)."""
        findings = []
        target_url = urljoin(form["url"], form["action"])
        
        for payload in self.xss_payloads:
            data = {}
            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "search"]:
                    data[input_field["name"]] = payload
                else:
                    data[input_field["name"]] = "test"
            
            try:
                if form["method"] == "post":
                    response = requests.post(target_url, data=data, timeout=5)
                else:
                    response = requests.get(target_url, params=data, timeout=5)
                
                if payload in response.text:
                    findings.append({
                        "url": form["url"],
                        "type": "Cross-Site Scripting (XSS)",
                        "payload": payload,
                        "risk": "High",
                        "description": f"A Reflected Cross-Site Scripting (XSS) vulnerability was found. The payload '{payload}' was successfully injected into a form and rendered back in the response page. An attacker could use this to execute malicious JavaScript in a victim's browser, potentially stealing session cookies, redirecting users, or performing actions on their behalf.",
                        "fix": "Sanitize and encode all user-supplied data before it is rendered on the page. Use context-aware output encoding libraries and implement Content Security Policy (CSP) as a secondary defense."
                    })
                    return findings
            except Exception as e:
                print(f"Error testing XSS on {target_url}: {e}")
                
        return findings

    def check_ssl(self, url):
        """Basic check for HTTP vs HTTPS."""
        findings = []
        if url.startswith("http://"):
            findings.append({
                "url": url,
                "type": "Insecure Protocol (HTTP)",
                "risk": "Medium",
                "description": "The website is using the unencrypted HTTP protocol. All data transmitted between the client and the server (including passwords and personal info) is sent in plain text and can be easily intercepted by an attacker using a 'Man-in-the-Middle' (MITM) attack.",
                "fix": "Obtain and install an SSL/TLS certificate (e.g., via Let's Encrypt) and configure your web server to redirect all HTTP traffic to HTTPS."
            })
        return findings
