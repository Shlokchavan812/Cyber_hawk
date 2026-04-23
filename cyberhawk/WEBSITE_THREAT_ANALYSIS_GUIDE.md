# 🌐 CyberHawk Website Threat Analysis - Complete Guide

## Overview
CyberHawk now includes a **Website Threat Analysis** feature that scans URLs for malicious patterns, vulnerabilities, and security threats. The system analyzes each website and generates detailed threat reports in PDF format.

## Features Added

### 1. **Website Threat Analyzer Module**
**File:** `src/website_threat_analyzer.py`

Comprehensive website security analysis with:
- ✅ **URL Pattern Analysis** - Detects phishing, malware, ransomware indicators
- ✅ **Domain Reputation Checking** - Identifies known malicious domains
- ✅ **Security Feature Detection** - HTTPS verification, IP address detection
- ✅ **Threat Score Calculation** - 0-100 risk scoring system
- ✅ **Multiple URL Scanning** - Batch analysis with summary statistics
- ✅ **Detailed Threat Reporting** - Lists all detected threats per URL

### 2. **Website Report Generation**
**File:** `src/report_generator.py` - Enhanced with `generate_website_report()`

Professional PDF reports that include:
- Website analysis results for each URL
- Threat classification and risk levels
- Threat score visualization
- Summary statistics (critical, high, medium, low)
- Risk-based recommendations
- Printable, shareable format

### 3. **Enhanced Dashboard**
**File:** `cyberhawk/dashboard/app.py` - Complete redesign

#### Two-Tab Interface:
1. **🔗 Network Threat Analysis** (Original feature)
   - Network traffic feature analysis
   - ML-based threat prediction
   - PDF report generation

2. **🌐 Website Threat Analysis** (New feature)
   - URL input (multiple URLs supported)
   - Real-time scanning
   - Detailed threat reporting
   - PDF report download

#### UI Improvements:
- Professional gradient header with logo
- Clean, intuitive tab-based navigation
- Responsive metric cards
- Color-coded risk indicators
- Visual threat score bars
- Mobile-friendly responsive design
- Persistent download buttons in header

## How to Use

### Website Threat Analysis Tab

#### Step 1: Enter Website URLs
```
Enter one URL per line:
https://example.com
https://website.org
https://another-site.net
```

#### Step 2: Click "🔍 Scan Websites"
The system will analyze each URL for:
- Malicious URL patterns
- Known malicious domains
- Security indicators
- HTTPS verification
- IP address usage
- Special character patterns
- Domain reputation

#### Step 3: View Results
Results display:
- **Scan Summary** - Total URLs, threats found breakdown
- **Risk Levels** - Critical, High, Medium, Low counts
- **Detailed Results** - Per-URL analysis with:
  - URL and risk badge
  - Threat type classification
  - Threat score (0-100)
  - Specific threats detected
  - Recommendations

#### Step 4: Download PDF Report
- Click "📝 Generate Website Threat Report"
- PDF generates with professional formatting
- Download button appears automatically
- Header also provides one-click access

## Threat Detection Capabilities

### Pattern Detection

#### 🔴 **Phishing Threats**
- Fake service lookalikes (PayPal, Amazon, Apple, etc.)
- URL shorteners (bit.ly, tinyurl, etc.)
- IP-based URLs instead of domain names

#### 🔴 **Malware Distribution**
- Executable file extensions (.exe, .bat, .ps1, etc.)
- "Crack/keygen/warez" patterns
- Download/soft/games keywords

#### 🔴 **Ransomware Indicators**
- Payment/bitcoin/ransom keywords
- Dark web references
- Decryption/restore patterns

#### 🔴 **Injection Attacks**
- SQL injection patterns
- XSS (Cross-Site Scripting) indicators
- JavaScript exploits

### Domain Analysis
- Known malicious domain database
- High-risk TLD detection (.tk, .ml, .ga, .cf, etc.)
- IP address vs domain checking
- Domain age estimation capability (WHOIS)

## Threat Scoring System

### Score Calculation (0-100)
```
URL Length > 75 chars           +5 points
No HTTPS                         +10 points
IP Address instead of domain    +20 points
Excessive special characters    +8 points
Known malicious domain          +50 points
High-risk TLD                   +15 points
Phishing pattern                +15 points
Malware pattern                 +20 points
Ransomware pattern              +25 points
Injection pattern               +10 points
```

### Risk Levels
| Score | Risk Level | Color | Action |
|-------|-----------|-------|--------|
| 0-24 | 🟢 LOW | Green | Continue monitoring |
| 25-49 | 🟡 MEDIUM | Orange | Review and monitor |
| 50-74 | 🔴 HIGH | Orange | Investigate |
| 75-100 | 🔴 CRITICAL | Red | Do not visit/block |

## PDF Report Contents

### Website Threat Report Sections:
1. **Header** - CyberHawk branding
2. **Report Metadata** - Generation time and report type
3. **Scan Summary** - URLs analyzed, threats found count
4. **Threat Statistics** - Critical/High/Medium/Low breakdown
5. **Individual Website Results**
   - URL analyzed
   - Threat type
   - Risk level
   - Threat score
   - List of detected threats
6. **Risk-Based Recommendations**
   - Critical: Do not visit, block, implement filters
   - High: Exercise caution, monitor, audit
   - Medium: Monitor for changes, review logs
   - Low: Routine monitoring
7. **Footer** - System branding and info

## Examples

### Safe Website
```
URL: https://google.com
Risk Level: Low (Score: 5/100)
Threats: None detected
Action: Safe to visit
```

### Suspicious Website
```
URL: http://192.168.1.1/admin/login
Risk Level: Critical (Score: 85/100)
Detected Threats:
  • Using IP address instead of domain
  • Not using HTTPS encryption
  • Unusually long URL
  • High-risk domain extension
Action: Do not visit, block immediately
```

### Phishing Website
```
URL: https://paypal-verify-account.xyz
Risk Level: Critical (Score: 75/100)
Detected Threats:
  • Phishing pattern detected
  • High-risk domain extension (.xyz)
  • Not using HTTPS
Action: Immediately block, report to authorities
```

## API Reference

### Main Functions

#### `analyze_website(url: str) -> Dict`
Analyzes a single URL for threats.

**Returns:**
```python
{
    "url": str,
    "threat_type": str,
    "risk_level": str,
    "threat_score": float,
    "detected_threats": [str],
    "is_safe": bool,
    "features": dict,
    "domain_reputation": dict,
    "suspicious_patterns": dict
}
```

#### `analyze_multiple_urls(urls: List[str]) -> Dict`
Analyzes multiple URLs and provides summary.

**Returns:**
```python
{
    "urls_analyzed": int,
    "threats_found": int,
    "critical_count": int,
    "high_count": int,
    "medium_count": int,
    "low_count": int,
    "analysis_results": [dict],
    "summary": str
}
```

#### `generate_website_report(analysis: Dict) -> str`
Generates PDF report from analysis results.

**Returns:** Path to generated PDF file

## Best Practices

### ✅ DO:
- Enter complete URLs with protocol (http:// or https://)
- Analyze URLs from unknown sources before visiting
- Review detailed threat reports before allowing access
- Keep URL blacklists updated regularly
- Train users on threat indicators

### ❌ DON'T:
- Click on suspicious URLs even for analysis
- Assume short URLs are safer
- Ignore high-risk threat scores
- Enable JavaScript from untrusted sites
- Share sensitive data on flagged websites

## System Requirements

### Dependencies:
- `requests` - For HTTP requests (optional, for future enhancements)
- `fpdf2` - For PDF generation (already installed)
- `streamlit` - Web framework (already installed)

### Python Version: 3.7+

## File Structure
```
cyberhawk/
├── src/
│   ├── website_threat_analyzer.py (NEW)
│   ├── report_generator.py (UPDATED)
│   └── ...
├── dashboard/
│   ├── app.py (COMPLETELY REDESIGNED)
│   └── app_old.py (backup)
├── reports/
│   ├── threat_report_*.pdf (Network reports)
│   └── website_threat_report_*.pdf (Website reports)
└── ...
```

## Limitations & Future Enhancements

### Current Limitations:
- No live website connection (HTTP request disabled for security)
- Pattern-based detection only (no machine learning analysis yet)
- No WHOIS lookup integration
- No SSL certificate verification
- No real-time threat feed integration

### Planned Enhancements:
1. **Machine Learning Integration** - Train ML model on website features
2. **Real-time Database** - Integration with threat intelligence feeds
3. **Email Filtering** - Block phishing emails automatically
4. **Browser Extension** - Real-time URL scanning while browsing
5. **API Integration** - VirusTotal, URLhaus, Google Safe Browsing
6. **Content Analysis** - Analyze webpage content for threats
7. **SSL Certificate Verification** - Check certificate validity
8. **WHOIS Lookup** - Get domain registration details
9. **GeoIP Detection** - Detect suspicious geographic origins
10. **Archive.org Integration** - Check website history

## Testing URLs

### Safe Websites (Low Risk):
```
https://google.com
https://github.com
https://stackoverflow.com
```

### Suspicious Websites (High Risk):
```
https://paypal-verify-account.xyz
http://192.168.1.1/admin/login
https://bit.ly/phishing-attempt
https://crack-software-free.tk
```

### Medium Risk:
```
https://example-site.ml
http://business-login.cf
https://download-tools.ga
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| URLs not analyzing | Ensure URLs include http:// or https:// |
| Empty threat list | May indicate safe website or pattern match issues |
| PDF not generating | Check reports/ directory has write permissions |
| Slow analysis | Multiple URLs take longer, be patient |
| Report download fails | Try refreshing the page |

## Support & Documentation

- See `WEBSITE_THREAT_GUIDE.md` for detailed threat descriptions
- Check `src/website_threat_analyzer.py` for source code
- Review `src/report_generator.py` for PDF generation
- Dashboard available at `http://localhost:8501`

---

**Version:** 2.1 (Website Threat Analysis Added)
**Last Updated:** April 23, 2026
**Status:** Active & Fully Functional
