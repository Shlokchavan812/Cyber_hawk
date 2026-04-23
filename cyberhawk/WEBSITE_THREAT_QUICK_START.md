# 🚀 Website Threat Analysis - Quick Start Guide

## 30-Second Overview

```
CyberHawk can now analyze websites for threats!

1. Open the "🌐 Website Threat Analysis" tab
2. Paste website URLs (one per line)
3. Click "🔍 Scan Websites"
4. View detailed threat analysis
5. Download PDF report
```

## Quick Examples

### Example 1: Check a Single Website
```
Input:
https://example.com

Output:
✅ Safe Website (Risk: 5/100)
No threats detected
Safe to visit
```

### Example 2: Scan Multiple Sites
```
Input:
https://google.com
https://paypal-verify.xyz
https://amazon-login.tk

Output:
3 URLs analyzed
2 Critical threats found
❌ Block these sites!
PDF report generated
```

## Dashboard Layout

```
┌─────────────────────────────────────────────┐
│  🛡️ CyberHawk                               │
│  Advanced Cyber Threat Intelligence         │
└─────────────────────────────────────────────┘

Tab 1: 🔗 Network Threat Analysis
Tab 2: 🌐 Website Threat Analysis (NEW!)

╔═════════════════════════════════════════════╗
║ Enter Website URLs                          ║
╚═════════════════════════════════════════════╝

[Text Area for URLs]

[🔍 Scan Websites] [📋 Example URLs]

╔═════════════════════════════════════════════╗
║ Scan Summary                                ║
╚═════════════════════════════════════════════╝

URLs: 3  | 🔴 Critical: 1 | 🟠 High: 1 | 🟡 Med: 1

╔═════════════════════════════════════════════╗
║ #1 https://google.com                   LOW ║
║ Threat Type: Safe Website                   ║
║ Score: 5/100 [████░░░░░░░░░░░░░░░░░░]     ║
╚═════════════════════════════════════════════╝

╔═════════════════════════════════════════════╗
║ #2 https://paypal-verify.xyz         CRITICAL ║
║ Threat Type: Phishing Website               ║
║ Score: 85/100 [████████████████████████]  ║
║ Threats:                                    ║
║ • Phishing pattern detected                 ║
║ • High-risk domain extension                ║
║ • Not using HTTPS                           ║
╚═════════════════════════════════════════════╝

[📝 Generate Report] [📋 View JSON Data]
```

## What Gets Detected?

### 🔴 CRITICAL (Score 75-100)
- ❌ Phishing sites
- ❌ Ransomware payment pages
- ❌ IP-based URLs
- ❌ Known malicious domains

### 🟠 HIGH (Score 50-74)
- ⚠️ Suspicious patterns
- ⚠️ No HTTPS encryption
- ⚠️ High-risk domain extensions
- ⚠️ Unusual URL structure

### 🟡 MEDIUM (Score 25-49)
- ⚠️ Some suspicious indicators
- ⚠️ Unusual parameters
- ⚠️ Mixed security signals

### 🟢 LOW (Score 0-24)
- ✅ Legitimate websites
- ✅ Proper security features
- ✅ Safe to visit

## Step-by-Step Tutorial

### Step 1: Open the Website Tab
```
Click: "🌐 Website Threat Analysis" tab
```

### Step 2: Enter URLs
```
Paste or type URLs (one per line):
https://your-website-1.com
https://your-website-2.com
https://your-website-3.com
```

### Step 3: Scan
```
Click: "🔍 Scan Websites" button
Wait: 2-3 seconds for analysis
```

### Step 4: Review Results
```
See metrics:
- Total URLs analyzed
- Critical threats count
- High threats count
- Medium threats count
- Low threats count

Review details:
- Each URL risk level
- Threat type
- Threat score
- Specific threats detected
```

### Step 5: Generate Report
```
Click: "📝 Generate Website Threat Report"
Wait: PDF generation (1-2 seconds)
Click: "💾 Download Website Report PDF"
```

## Testing URLs to Try

### Test 1: Safe Site
```
https://google.com
Expected: 🟢 Low (Score: 5/100)
```

### Test 2: Medium Risk
```
https://example.ml
Expected: 🟡 Medium (Score: 35/100)
```

### Test 3: High Risk
```
http://192.168.1.1/admin
Expected: 🔴 Critical (Score: 85/100)
```

### Test 4: Phishing Example
```
https://paypal-verify-account.xyz
Expected: 🔴 Critical (Score: 90/100)
```

## PDF Report Download

### Where to Find Downloads
```
Windows: C:\Users\[Username]\Downloads\
        or browser default download folder
```

### Report Filename Format
```
website_threat_report_YYYYMMDD_HHMMSS.pdf
Example: website_threat_report_20260423_143022.pdf
```

### What's in the PDF
✅ CyberHawk branding
✅ Report generation timestamp
✅ All URLs analyzed
✅ Risk level summary
✅ Individual URL analysis
✅ Detected threats list
✅ Recommendations
✅ Professional formatting
✅ Printable format

## Feature Highlights

### 🎯 **Accurate Detection**
- Pattern-based threat detection
- Known malicious domain database
- Security indicator analysis
- Risk scoring algorithm

### 📊 **Visual Results**
- Color-coded risk badges
- Threat score progress bar
- Summary statistics
- Clear threat listings

### 📄 **Professional Reports**
- PDF format
- Professional styling
- Detailed analysis
- Actionable recommendations

### ⚡ **Fast Scanning**
- Instant analysis
- Multiple URLs at once
- Real-time feedback
- Quick PDF generation

### 📱 **Responsive Design**
- Works on desktop
- Tablet friendly
- Mobile optimized
- Touch-friendly buttons

## Common Questions

### Q: Is it safe to paste the URLs?
**A:** Yes! The system analyzes URL patterns, not the actual website content.

### Q: Do you visit the websites?
**A:** No. All analysis is done on URL patterns and reputation databases.

### Q: How long does scanning take?
**A:** Usually 1-3 seconds depending on number of URLs.

### Q: Can I scan hundreds of URLs?
**A:** Yes, but it's better to scan in batches of 10-20 for best performance.

### Q: What if a site is incorrectly flagged?
**A:** The system uses pattern-based detection. Legitimate sites can sometimes match patterns. Always verify before blocking.

### Q: Where are reports saved?
**A:** In the `cyberhawk/reports/` directory on your system.

### Q: Can I share the PDF reports?
**A:** Yes! They're designed for sharing with security teams.

## Keyboard Shortcuts

```
Tab: Move between fields
Enter: Submit form (in text inputs)
Ctrl+A: Select all text
Ctrl+C: Copy selected text
Ctrl+V: Paste URL
```

## Troubleshooting

### URLs not scanning?
- ✅ Make sure you have internet connection
- ✅ Check URLs are formatted correctly
- ✅ Include http:// or https:// protocol

### Empty threat list?
- ✅ Website might be safe
- ✅ No malicious patterns detected
- ✅ Still has a risk score

### PDF download fails?
- ✅ Check download folder permissions
- ✅ Try refreshing the page
- ✅ Check browser download settings

### Streamlit app won't start?
- ✅ Run: `cd cyberhawk`
- ✅ Run: `streamlit run dashboard/app.py`
- ✅ Open: `http://localhost:8501`

## Next Steps

1. ✅ Try scanning a few URLs
2. ✅ Generate a PDF report
3. ✅ Review the threat analysis
4. ✅ Combine with Network analysis
5. ✅ Share findings with team

## Support

**Need help?**
- Check `WEBSITE_THREAT_ANALYSIS_GUIDE.md` for detailed docs
- Review dashboard tooltips and help text
- Check GitHub issues or documentation

**Report issues:**
- Document the URLs tested
- Include error messages
- Note your operating system
- Attach generated reports if possible

---

**Ready to scan?** 🚀
Open the Website Threat Analysis tab and start protecting your network!
