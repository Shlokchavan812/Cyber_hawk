"""
URL-to-threat intelligence pipeline for CyberHawk.

The scanner is intentionally safe for a student/demo environment: it performs
passive DNS/SSL checks and one bounded HTTP request. It does not exploit,
brute-force, fuzz, or perform intrusive vulnerability testing.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse

import requests

from src.predict import predict
from src.threat_intel import (
    THREAT_KNOWLEDGE,
    calculate_risk_score,
    classify_risk,
    get_recommendations,
    get_threat,
)


REQUEST_TIMEOUT = 6
USER_AGENT = "CyberHawk-Educational-Scanner/1.0"

SUSPICIOUS_PATTERNS = {
    "phishing": [
        r"(paypal|amazon|apple|google|microsoft|bank|login|account|verify|confirm).*fake",
        r"(secure|verify|account|signin|login).*\.(tk|ml|ga|cf|xyz|top)",
        r"bit\.ly|tinyurl|short\.link|goo\.gl|t\.co",
        r"\d{1,3}(\.\d{1,3}){3}",
    ],
    "malware": [
        r"\.(exe|scr|bat|cmd|ps1|vbs|jar|apk|msi)(\?|#|$)",
        r"(crack|keygen|serial|patch|warez)",
        r"(download|soft|games).*crack",
    ],
    "ransomware": [
        r"(payment|bitcoin|ransom|decrypt|restore)",
        r"darkweb|tor\.onion|hiddenservice",
    ],
    "injection": [
        r"(\?|&)(id|uid|user|admin)=.*(<|'|\"|;|\||`)",
        r"javascript:|onerror=|onload=",
    ],
}

KNOWN_MALICIOUS_DOMAINS = {
    "malwaresite.com",
    "phishingpage.net",
    "ransomware-payments.info",
    "exploit-kit.ru",
}

HIGH_RISK_TLDS = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".download", ".zip"]
DOWNLOAD_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".apk", ".msi")
API_HINTS = ("/api/", "/graphql", "/oauth", "/token", "/login", "/admin")
SCRIPT_RISK_KEYWORDS = ("eval(", "document.write", "atob(", "fromcharcode", "powershell", "base64")


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("URL is empty")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def extract_url_features(url: str) -> Dict:
    parsed = urlparse(url)
    domain = parsed.netloc.split("@")[-1].split(":")[0].lower()
    return {
        "url": url,
        "domain": domain,
        "protocol": parsed.scheme,
        "path": parsed.path or "/",
        "uses_https": parsed.scheme == "https",
        "has_ip": bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain)),
        "url_length": len(url),
        "special_chars": len(re.findall(r"[^a-zA-Z0-9\-_\./:?=&%#]", url)),
        "dots_count": url.count("."),
        "hyphens_count": url.count("-"),
        "underscores_count": url.count("_"),
        "numbers_count": sum(1 for c in url if c.isdigit()),
        "slashes_count": url.count("/"),
        "query_length": len(parsed.query),
    }


def check_suspicious_patterns(url: str) -> Dict[str, List[str]]:
    matches: Dict[str, List[str]] = {}
    for threat_type, patterns in SUSPICIOUS_PATTERNS.items():
        found = [pattern for pattern in patterns if re.search(pattern, url, re.IGNORECASE)]
        if found:
            matches[threat_type] = found
    return matches


def dns_lookup(domain: str) -> Dict:
    result = {
        "domain": domain,
        "ip_addresses": [],
        "reverse_dns": None,
        "hosting_provider": "Unknown",
        "error": None,
    }
    try:
        _, _, addresses = socket.gethostbyname_ex(domain)
        result["ip_addresses"] = sorted(set(addresses))
        if addresses:
            try:
                result["reverse_dns"] = socket.gethostbyaddr(addresses[0])[0]
                result["hosting_provider"] = result["reverse_dns"]
            except OSError:
                result["hosting_provider"] = "Resolved IP, reverse DNS unavailable"
    except OSError as exc:
        result["error"] = str(exc)
    return result


def check_ssl_certificate(domain: str, port: int = 443) -> Dict:
    result = {
        "valid": False,
        "issuer": "Unavailable",
        "expires": "Unavailable",
        "days_until_expiry": None,
        "error": None,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
        not_after = cert.get("notAfter")
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer = ", ".join("=".join(pair) for group in cert.get("issuer", []) for pair in group)
        result.update(
            {
                "valid": expiry > datetime.now(timezone.utc),
                "issuer": issuer or "Available",
                "expires": expiry.strftime("%Y-%m-%d"),
                "days_until_expiry": max(0, (expiry - datetime.now(timezone.utc)).days),
            }
        )
    except Exception as exc:
        result["error"] = str(exc)
    return result


def check_domain_reputation(domain: str) -> Dict:
    return {
        "domain": domain,
        "is_known_malicious": domain.lower() in KNOWN_MALICIOUS_DOMAINS,
        "is_ip_address": bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain)),
        "has_high_risk_tld": any(domain.lower().endswith(tld) for tld in HIGH_RISK_TLDS),
        "blacklist_status": "Listed" if domain.lower() in KNOWN_MALICIOUS_DOMAINS else "Not listed in local demo feed",
        "domain_age": "Unavailable without WHOIS API",
    }


def _extract_links(html: str, base_url: str) -> List[str]:
    hrefs = re.findall(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", html, flags=re.IGNORECASE)
    return [urljoin(base_url, href) for href in hrefs[:100]]


def interact_with_url(url: str) -> Dict:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    started = time.perf_counter()
    result = {
        "status_code": None,
        "final_url": url,
        "elapsed_seconds": 0.0,
        "headers": {},
        "redirect_chain": [],
        "cookies": [],
        "content_length": 0,
        "html_sample": "",
        "links": [],
        "error": None,
    }
    try:
        response = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        elapsed = round(time.perf_counter() - started, 3)
        headers = {k: v for k, v in response.headers.items()}
        html = response.text[:200000] if "text" in headers.get("Content-Type", "").lower() or response.text else ""
        result.update(
            {
                "status_code": response.status_code,
                "final_url": response.url,
                "elapsed_seconds": elapsed,
                "headers": headers,
                "redirect_chain": [r.url for r in response.history],
                "cookies": [cookie.name for cookie in session.cookies],
                "content_length": int(headers.get("Content-Length") or len(response.content or b"")),
                "html_sample": html[:5000],
                "links": _extract_links(html, response.url),
            }
        )
    except requests.RequestException as exc:
        result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
        result["error"] = str(exc)
    return result


def analyze_browser_behavior(interaction: Dict) -> Dict:
    html = interaction.get("html_sample", "") or ""
    links = interaction.get("links", [])
    hidden_iframes = len(re.findall(r"<iframe[^>]+(display\s*:\s*none|visibility\s*:\s*hidden|width=['\"]?0)", html, re.I))
    script_count = len(re.findall(r"<script\b", html, re.I))
    form_count = len(re.findall(r"<form\b", html, re.I))
    suspicious_js = [keyword for keyword in SCRIPT_RISK_KEYWORDS if keyword.lower() in html.lower()]
    suspicious_downloads = [link for link in links if urlparse(link).path.lower().endswith(DOWNLOAD_EXTENSIONS)]
    api_calls = [link for link in links if any(hint in link.lower() for hint in API_HINTS)]

    return {
        "script_count": script_count,
        "form_count": form_count,
        "hidden_iframes": hidden_iframes,
        "suspicious_js": suspicious_js,
        "suspicious_downloads": suspicious_downloads[:10],
        "api_calls": api_calls[:10],
        "request_frequency": max(1, len(links) + len(interaction.get("redirect_chain", []))),
    }


def build_ml_features(url_features: Dict, interaction: Dict, behavior: Dict) -> Dict:
    duration = max(float(interaction.get("elapsed_seconds") or 1.0), 0.1)
    packet_count = max(20, behavior["request_frequency"] * 12 + behavior["script_count"] * 3)
    byte_count = max(1000, interaction.get("content_length") or url_features["url_length"] * 120)
    flags = (
        len(interaction.get("redirect_chain", []))
        + len(interaction.get("cookies", []))
        + len(behavior.get("suspicious_js", []))
        + behavior.get("hidden_iframes", 0)
    )
    dest_port = 443 if url_features["uses_https"] else 80
    source_port = 1024 + min(50000, url_features["url_length"] * 7 + url_features["numbers_count"])

    feature_values = {
        "packet_count": float(packet_count),
        "byte_count": float(byte_count),
        "duration": float(duration),
        "protocol": 6.0,
        "flags": float(flags),
        "source_port": float(source_port),
        "dest_port": float(dest_port),
        "packet_rate": round(packet_count / duration, 3),
        "data_rate": round(byte_count / duration, 3),
    }
    return feature_values


def calculate_url_signal_score(
    url_features: Dict,
    reputation: Dict,
    ssl_info: Dict,
    suspicious: Dict[str, List[str]],
    behavior: Dict,
    interaction: Dict,
) -> Tuple[float, List[str]]:
    score = 0.0
    signals: List[str] = []

    if url_features["url_length"] > 75:
        score += 0.4
        signals.append("Unusually long URL")
    if not url_features["uses_https"]:
        score += 0.9
        signals.append("Not using HTTPS encryption")
    if url_features["has_ip"]:
        score += 1.7
        signals.append("Using IP address instead of domain")
    if url_features["special_chars"] > 5:
        score += 0.5
        signals.append("Excessive special characters in URL")
    if reputation["is_known_malicious"]:
        score += 4.0
        signals.append("Known malicious domain detected")
    if reputation["has_high_risk_tld"]:
        score += 1.2
        signals.append("High-risk domain extension detected")
    if url_features["uses_https"] and not ssl_info["valid"]:
        score += 1.0
        signals.append("SSL certificate is invalid or unavailable")
    if len(interaction.get("redirect_chain", [])) >= 3:
        score += 0.8
        signals.append("Multiple redirect hops detected")
    if behavior["hidden_iframes"] > 0:
        score += 1.5
        signals.append("Hidden iframe behavior detected")
    if behavior["suspicious_downloads"]:
        score += 2.2
        signals.append("Suspicious executable download link detected")
    if behavior["suspicious_js"]:
        score += 1.2
        signals.append("Obfuscated or risky JavaScript behavior detected")

    for threat_type in suspicious:
        weight = {"phishing": 1.5, "malware": 2.0, "ransomware": 2.5, "injection": 1.2}.get(threat_type, 1.0)
        score += weight
        signals.append(f"{threat_type.title()} pattern detected")

    return round(min(5.0, score), 2), sorted(set(signals))


def choose_website_threat_type(signals: List[str], ml_threat: Dict, suspicious: Dict[str, List[str]]) -> str:
    if "ransomware" in suspicious:
        return "Ransomware Site"
    if "malware" in suspicious or any("download" in signal.lower() for signal in signals):
        return "Malware Distribution"
    if "phishing" in suspicious:
        return "Phishing Website"
    if "injection" in suspicious:
        return "Injection Attempt"
    if ml_threat["label"] != "Normal" and ml_threat["confidence"] >= 0.45:
        return ml_threat["type"]
    if signals:
        return "Suspicious Website"
    return "Safe Website"


def map_website_intel(threat_type: str, ml_threat: Dict) -> Dict:
    if threat_type in ("Safe Website", "Suspicious Website", "Injection Attempt", "Phishing Website"):
        website_map = {
            "Safe Website": {
                "mitre": {"tactic": "N/A", "technique_id": "N/A", "technique": "No malicious technique detected"},
                "cves": [],
            },
            "Suspicious Website": {
                "mitre": {"tactic": "Initial Access", "technique_id": "T1189", "technique": "Drive-by Compromise"},
                "cves": ["CVE-2021-44228", "CVE-2023-34362"],
            },
            "Injection Attempt": {
                "mitre": {"tactic": "Initial Access", "technique_id": "T1190", "technique": "Exploit Public-Facing Application"},
                "cves": ["CVE-2021-41773", "CVE-2023-3519"],
            },
            "Phishing Website": {
                "mitre": {"tactic": "Initial Access", "technique_id": "T1566", "technique": "Phishing"},
                "cves": ["CVE-2021-40444", "CVE-2017-11882"],
            },
        }
        return website_map[threat_type]

    if threat_type == "Ransomware Site":
        return {
            "mitre": {"tactic": "Impact", "technique_id": "T1486", "technique": "Data Encrypted for Impact"},
            "cves": ["CVE-2023-0669", "CVE-2021-34527"],
        }
    if threat_type == "Malware Distribution":
        return {
            "mitre": {"tactic": "Initial Access", "technique_id": "T1204", "technique": "User Execution"},
            "cves": ["CVE-2023-38831", "CVE-2021-40444"],
        }
    return {"mitre": ml_threat.get("mitre", {}), "cves": ml_threat.get("cves", [])}


def summarize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    interesting = [
        "Server",
        "Content-Type",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
    ]
    return {name: headers.get(name, "Missing") for name in interesting}


def analyze_website(url: str) -> Dict:
    try:
        normalized_url = normalize_url(url)
        url_features = extract_url_features(normalized_url)
        domain = url_features["domain"]

        dns_info = dns_lookup(domain)
        ssl_info = check_ssl_certificate(domain) if url_features["uses_https"] and not url_features["has_ip"] else {
            "valid": False,
            "issuer": "Not checked",
            "expires": "Not checked",
            "days_until_expiry": None,
            "error": None if not url_features["uses_https"] else "Skipped for IP address",
        }
        reputation = check_domain_reputation(domain)
        suspicious = check_suspicious_patterns(normalized_url)
        interaction = interact_with_url(normalized_url)
        behavior = analyze_browser_behavior(interaction)
        ml_feature_map = build_ml_features(url_features, interaction, behavior)
        ml_values = list(ml_feature_map.values())
        prediction, confidence = predict(ml_values)
        ml_threat = get_threat(prediction, confidence)
        signal_bonus, signals = calculate_url_signal_score(
            url_features,
            reputation,
            ssl_info,
            suspicious,
            behavior,
            interaction,
        )
        threat_type = choose_website_threat_type(signals, ml_threat, suspicious)
        intel = map_website_intel(threat_type, ml_threat)

        severity = 1.0 if threat_type == "Safe Website" else ml_threat.get("severity_weight", 5.0)
        exploitability = 1.0 if threat_type == "Safe Website" else ml_threat.get("exploitability_score", 5.0)
        probability = max(ml_threat["confidence"], min(1.0, signal_bonus / 5.0))
        risk_score = calculate_risk_score(probability, severity, exploitability, signal_bonus=signal_bonus)
        if threat_type == "Safe Website":
            risk_score = min(risk_score, 1.0)
        risk_level = classify_risk(risk_score)

        timeline = [
            "URL submitted",
            "Passive URL intelligence completed",
            "DNS and SSL checks completed",
            "Controlled HTTP interaction completed",
            "Feature extraction completed",
            f"ML detection completed: {ml_threat['type']} ({ml_threat['confidence'] * 100:.1f}%)",
            "Threat intelligence mapping completed",
            f"Risk score calculated: {risk_score}/10",
        ]

        return {
            "url": normalized_url,
            "domain": domain,
            "ip_address": ", ".join(dns_info["ip_addresses"]) if dns_info["ip_addresses"] else "Unavailable",
            "ip_addresses": dns_info["ip_addresses"],
            "hosting_provider": dns_info["hosting_provider"],
            "domain_age": reputation["domain_age"],
            "ssl_valid": ssl_info["valid"],
            "blacklist_status": reputation["blacklist_status"],
            "status_code": interaction["status_code"],
            "final_url": interaction["final_url"],
            "threat_type": threat_type,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "threat_score": round(risk_score * 10, 2),
            "confidence_score": round(ml_threat["confidence"] * 100, 2),
            "detected_threats": signals,
            "is_safe": risk_level == "Low" and not signals,
            "features": url_features,
            "extracted_features": ml_feature_map,
            "domain_reputation": reputation,
            "dns_info": dns_info,
            "ssl_info": ssl_info,
            "suspicious_patterns": suspicious,
            "network_interaction": {
                "http_headers": summarize_headers(interaction["headers"]),
                "redirect_chain": interaction["redirect_chain"],
                "cookies": interaction["cookies"],
                "elapsed_seconds": interaction["elapsed_seconds"],
                "content_length": interaction["content_length"],
                "error": interaction["error"],
            },
            "browser_behavior": behavior,
            "ml_detection": {
                "attack_type": ml_threat["type"],
                "label": ml_threat["label"],
                "confidence": ml_threat["confidence"],
                "features": ml_values,
            },
            "threat_intelligence": intel,
            "mitre": intel["mitre"],
            "cves": intel["cves"],
            "recommendations": get_recommendations(ml_threat["type"], signals),
            "timeline": timeline,
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception as exc:
        fallback_url = url.strip()
        return {
            "url": fallback_url,
            "domain": "Unavailable",
            "ip_address": "Unavailable",
            "threat_type": "Analysis Error",
            "risk_level": "Unknown",
            "risk_score": 0,
            "threat_score": 0,
            "confidence_score": 0,
            "detected_threats": ["Failed to analyze URL"],
            "recommendations": ["Validate the URL and retry the scan."],
            "error": str(exc),
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }


def analyze_multiple_urls(urls: List[str]) -> Dict:
    analysis_results = [analyze_website(url) for url in urls if url.strip()]
    risk_counts = Counter(result.get("risk_level", "Unknown") for result in analysis_results)
    threats_found = sum(1 for result in analysis_results if result.get("risk_level") in ("Medium", "High", "Critical"))

    if threats_found == 0:
        summary = f"All {len(analysis_results)} website(s) analyzed - no high-risk threats detected."
    else:
        summary = f"{threats_found} out of {len(analysis_results)} website(s) require security review."

    return {
        "urls_analyzed": len(analysis_results),
        "threats_found": threats_found,
        "critical_count": risk_counts.get("Critical", 0),
        "high_count": risk_counts.get("High", 0),
        "medium_count": risk_counts.get("Medium", 0),
        "low_count": risk_counts.get("Low", 0),
        "unknown_count": risk_counts.get("Unknown", 0),
        "analysis_results": analysis_results,
        "summary": summary,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
