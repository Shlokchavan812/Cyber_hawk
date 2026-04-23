# 🎯 CyberHawk Quick Reference Card

## Dashboard Access
```
URL: http://localhost:8501
Start: streamlit run cyberhawk/dashboard/app.py
```

## Two Main Features

### 🔗 Network Threat Analysis
```
Input:  9 comma-separated numbers
        100, 5000, 10, 6, 0, 1023, 80, 10, 500
Output: Threat type, Risk level, PDF report
Time:   ~65ms analysis + ~800ms report
```

### 🌐 Website Threat Analysis
```
Input:  Website URLs (one per line)
        https://example.com
        https://website.org
Output: Risk assessment, Threats found, PDF report
Time:   50-100ms per URL + ~800ms report
```

## Threat Levels

| Level | Color | Score | Action |
|-------|-------|-------|--------|
| Low | 🟢 | 0-24 | Safe |
| Medium | 🟡 | 25-49 | Monitor |
| High | 🔴 | 50-74 | Investigate |
| Critical | 🔴🔴 | 75-100 | Block |

## Website Threats Detected

- 🔴 Phishing pages
- 🔴 Malware sites
- 🔴 Ransomware pages
- 🔴 Injection attacks
- ⚠️ IP-based URLs
- ⚠️ Missing HTTPS
- ⚠️ Suspicious domains
- ⚠️ High-risk TLDs

## Files & Locations

```
Dashboard:      cyberhawk/dashboard/app.py
Network Module: cyberhawk/src/predict.py
Website Module: cyberhawk/src/website_threat_analyzer.py (NEW)
Reports:        cyberhawk/reports/
Models:         cyberhawk/models/
```

## Key Keyboard Shortcuts
```
Tab   - Navigate fields
Enter - Submit analysis
↓     - View options
```

## Sample Test Data

### Network (9 values)
```
Normal:   100, 5000, 10, 6, 0, 1023, 80, 10, 500
DoS:      500, 25000, 2, 6, 0, 1027, 9200, 250, 12500
Malware:  600, 30000, 8, 6, 0, 1043, 80, 75, 3750
```

### Website (URLs)
```
Safe:         https://google.com
Suspicious:   https://paypal-verify.xyz
High Risk:    http://192.168.1.1/admin
```

## Report Files

```
Network Reports:
threat_report_YYYYMMDD_HHMMSS.pdf

Website Reports:
website_threat_report_YYYYMMDD_HHMMSS.pdf
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| App won't start | `pip install streamlit` |
| No model found | Check `cyberhawk/models/` folder |
| PDF error | Check write permissions on `reports/` |
| Slow analysis | Reduce batch size |
| URLs not scanning | Add `https://` prefix |

## Documentation Files

```
📄 WEBSITE_THREAT_ANALYSIS_GUIDE.md      - Complete guide
📄 WEBSITE_THREAT_QUICK_START.md         - Quick reference
📄 SYSTEM_ARCHITECTURE.md                - Architecture docs
📄 ENHANCEMENT_SUMMARY.md                - What changed
📄 PDF_REPORT_FEATURES.md                - PDF features
📄 QUICK_START_PDF.md                    - PDF guide
```

## Risk Score Formula

```
Score = URL Features + Domain Checks + Patterns

URL Features:
  Long URL (>75)        +5
  No HTTPS              +10
  IP Address            +20
  Special chars         +8

Domain:
  Malicious DB          +50
  High-risk TLD         +15

Patterns:
  Phishing              +15
  Malware               +20
  Ransomware            +25
  Injection             +10
```

## Features

✅ Network threat detection (ML-based)
✅ Website threat detection (pattern-based)
✅ PDF report generation
✅ Multi-URL batch analysis
✅ Risk scoring (0-100)
✅ Session persistence
✅ Responsive design
✅ Color-coded badges
✅ Download buttons
✅ JSON export

## Dashboard Tabs

```
Tab 1: 🔗 Network Threat Analysis
├─ Enter 9 network features
├─ Get ML prediction
├─ View threat details
└─ Generate PDF report

Tab 2: 🌐 Website Threat Analysis (NEW)
├─ Enter website URLs
├─ Scan for threats
├─ View per-URL results
└─ Generate PDF report
```

## Performance

```
Network Analysis:    ~65ms
Single URL:          ~75ms
5 URLs:              ~350ms
10 URLs:             ~700ms
20 URLs:             ~1500ms
PDF Generation:      ~800ms
```

## Browser Support

✅ Chrome, Edge, Firefox, Safari
✅ Desktop, Tablet, Mobile
✅ Modern browsers only

## Security

✅ No website visits (pattern-only)
✅ Local processing
✅ No external data transmission
✅ Session data local
✅ PDF server-side

## Python Version
```
Minimum: Python 3.7
Recommended: Python 3.9+
```

## Dependencies
```
streamlit>=1.0.0
fpdf2>=2.6.0
scikit-learn>=0.24.0
joblib>=1.0.0
pandas>=1.2.0
numpy>=1.19.0
```

## Quick Commands

```bash
# Start dashboard
streamlit run cyberhawk/dashboard/app.py

# Check Python version
python --version

# Install requirements
pip install -r requirements.txt

# Stop streamlit
Ctrl+C (in terminal)

# View help
streamlit --help
```

## What's New (v2.1)

✨ Website threat detection
✨ Pattern-based URL analysis
✨ Batch website scanning
✨ Website threat reports
✨ Completely redesigned UI
✨ Tab-based navigation
✨ Better styling
✨ Responsive design

## Remember

🔒 **Always verify** before blocking
⚠️ **Check DNS** if uncertain
📊 **Review metrics** carefully
💾 **Save reports** for audit trail
👥 **Train users** on threats
🔄 **Update regularly** (future)

---

**Version 2.1** | **April 23, 2026**
Keep this card handy for quick reference!
