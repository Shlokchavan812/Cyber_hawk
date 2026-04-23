"""
Website Threat Analyzer - Analyzes URLs and websites for potential security threats
"""
import re
from urllib.parse import urlparse
import requests
from typing import Dict, List, Tuple

# Malicious URL patterns
SUSPICIOUS_PATTERNS = {
    "phishing": [
        r"(paypal|amazon|apple|google|microsoft|bank|login|account|verify|confirm).*fake",
        r"bit\.ly|tinyurl|short\.link|goo\.gl",  # URL shorteners (suspicious in security context)
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses instead of domain
    ],
    "malware": [
        r"(exe|scr|bat|cmd|ps1|vbs|js)$",  # Executable extensions
        r"(crack|keygen|serial|patch|warez)",
        r"(download|soft|games).*crack",
    ],
    "ransomware": [
        r"(payment|bitcoin|ransom|decrypt|restore)",
        r"darkweb|tor\.onion|hidden",
    ],
    "injection": [
        r"(\?|&)(id|uid|user|admin)=.*(\<|\'|\"|\;|\||`)",  # SQL injection patterns
        r"javascript:|onerror=|onload=",  # XSS patterns
    ],
}

# Known malicious domains (sample)
KNOWN_MALICIOUS_DOMAINS = {
    "malwaresite.com",
    "phishingpage.net",
    "ransomware-payments.info",
    "exploit-kit.ru",
}

# High-risk TLDs
HIGH_RISK_TLDS = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".download", ".zip"]

# Safe domain indicators
SAFE_INDICATORS = [
    "https://",  # HTTPS over HTTP
    "padlock",  # SSL certificate indicator
]


def extract_url_features(url: str) -> Dict:
    """
    Extract security-relevant features from a URL
    """
    features = {
        "url": url,
        "domain": "",
        "protocol": "",
        "uses_https": False,
        "has_ip": False,
        "url_length": len(url),
        "special_chars": 0,
        "dots_count": url.count("."),
        "hyphens_count": url.count("-"),
        "underscores_count": url.count("_"),
        "numbers_count": sum(1 for c in url if c.isdigit()),
        "slashes_count": url.count("/"),
    }
    
    try:
        parsed = urlparse(url)
        features["domain"] = parsed.netloc
        features["protocol"] = parsed.scheme
        features["uses_https"] = parsed.scheme == "https"
        
        # Check for IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", parsed.netloc):
            features["has_ip"] = True
        
        # Count special characters
        special_chars = len(re.findall(r"[^a-zA-Z0-9\-_\./:]", url))
        features["special_chars"] = special_chars
        
    except Exception as e:
        pass
    
    return features


def check_suspicious_patterns(url: str) -> Dict[str, List[str]]:
    """
    Check URL against known suspicious patterns
    """
    suspicious_found = {}
    
    for threat_type, patterns in SUSPICIOUS_PATTERNS.items():
        matches = []
        for pattern in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                matches.append(pattern)
        if matches:
            suspicious_found[threat_type] = matches
    
    return suspicious_found


def check_domain_reputation(domain: str) -> Dict:
    """
    Check domain reputation and characteristics
    """
    reputation = {
        "domain": domain,
        "is_known_malicious": domain.lower() in KNOWN_MALICIOUS_DOMAINS,
        "is_ip_address": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain)),
        "has_high_risk_tld": any(domain.lower().endswith(tld) for tld in HIGH_RISK_TLDS),
        "age_in_days": None,  # Would require WHOIS lookup
        "registrar": None,  # Would require WHOIS lookup
    }
    
    return reputation


def calculate_threat_score(url: str) -> Tuple[float, List[str]]:
    """
    Calculate overall threat score for a URL (0-100)
    Returns: (score, threat_list)
    """
    threats = []
    score = 0
    
    # Extract features
    features = extract_url_features(url)
    suspicious = check_suspicious_patterns(url)
    reputation = check_domain_reputation(url.split('/')[2] if '://' in url else url.split('/')[0])
    
    # URL Length check (very long URLs can be suspicious)
    if features["url_length"] > 75:
        score += 5
        threats.append("Unusually long URL")
    
    # HTTPS check
    if not features["uses_https"]:
        score += 10
        threats.append("Not using HTTPS encryption")
    
    # IP address check
    if features["has_ip"]:
        score += 20
        threats.append("Using IP address instead of domain")
    
    # Special characters check
    if features["special_chars"] > 5:
        score += 8
        threats.append("Excessive special characters in URL")
    
    # Known malicious domain
    if reputation["is_known_malicious"]:
        score += 50
        threats.append("Known malicious domain detected")
    
    # High-risk TLD
    if reputation["has_high_risk_tld"]:
        score += 15
        threats.append("High-risk domain extension detected")
    
    # Suspicious pattern matches
    for threat_type, patterns in suspicious.items():
        score += (15 if threat_type == "phishing" else 20 if threat_type == "malware" else 25 if threat_type == "ransomware" else 10)
        threats.append(f"{threat_type.capitalize()} pattern detected")
    
    # Normalize score to 0-100
    score = min(score, 100)
    
    return score, list(set(threats))  # Remove duplicates


def analyze_website(url: str) -> Dict:
    """
    Comprehensive website threat analysis
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    try:
        threat_score, threats = calculate_threat_score(url)
        
        # Determine risk level
        if threat_score >= 75:
            risk_level = "Critical"
        elif threat_score >= 50:
            risk_level = "High"
        elif threat_score >= 25:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        # Get threat type
        if "phishing" in str(threats).lower():
            threat_type = "Phishing Website"
        elif "malware" in str(threats).lower():
            threat_type = "Malware Distribution"
        elif "ransomware" in str(threats).lower():
            threat_type = "Ransomware Site"
        elif not threats:
            threat_type = "Safe Website"
        else:
            threat_type = "Suspicious Website"
        
        analysis_result = {
            "url": url,
            "threat_type": threat_type,
            "risk_level": risk_level,
            "threat_score": round(threat_score, 2),
            "detected_threats": threats,
            "is_safe": risk_level == "Low",
            "features": extract_url_features(url),
            "domain_reputation": check_domain_reputation(url.split('/')[2]),
            "suspicious_patterns": check_suspicious_patterns(url),
        }
        
        return analysis_result
    
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "threat_type": "Analysis Error",
            "risk_level": "Unknown",
            "threat_score": 0,
            "detected_threats": ["Failed to analyze URL"],
        }


def analyze_multiple_urls(urls: List[str]) -> Dict:
    """
    Analyze multiple URLs and provide summary
    """
    results = {
        "urls_analyzed": len(urls),
        "threats_found": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "analysis_results": [],
        "summary": ""
    }
    
    for url in urls:
        analysis = analyze_website(url.strip())
        results["analysis_results"].append(analysis)
        
        if analysis.get("risk_level") == "Critical":
            results["critical_count"] += 1
            results["threats_found"] += 1
        elif analysis.get("risk_level") == "High":
            results["high_count"] += 1
            results["threats_found"] += 1
        elif analysis.get("risk_level") == "Medium":
            results["medium_count"] += 1
            results["threats_found"] += 1
        elif analysis.get("risk_level") == "Low" and analysis.get("detected_threats"):
            results["low_count"] += 1
    
    # Generate summary
    if results["threats_found"] == 0:
        results["summary"] = f"✅ All {len(urls)} website(s) analyzed - No threats detected"
    else:
        results["summary"] = f"⚠️ {results['threats_found']} out of {len(urls)} website(s) contain threats"
    
    return results
