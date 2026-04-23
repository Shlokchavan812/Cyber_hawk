import os
from typing import Dict, Iterable, List, Optional

import joblib


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

le = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))


THREAT_KNOWLEDGE: Dict[str, Dict] = {
    "Normal": {
        "type": "Normal Traffic",
        "risk": "Low",
        "description": "The observed traffic matches normal network behavior.",
        "severity_weight": 1.0,
        "exploitability_score": 1.0,
        "mitre": {
            "tactic": "N/A",
            "technique_id": "N/A",
            "technique": "No malicious technique detected",
        },
        "cves": [],
        "recommendations": [
            "Continue routine monitoring.",
            "Keep endpoint and network telemetry collection enabled.",
            "Maintain current patching and access-control practices.",
        ],
    },
    "DoS": {
        "type": "Denial of Service",
        "risk": "High",
        "description": "Traffic volume and rate indicate a possible denial-of-service attempt.",
        "severity_weight": 8.5,
        "exploitability_score": 7.0,
        "mitre": {
            "tactic": "Impact",
            "technique_id": "T1498",
            "technique": "Network Denial of Service",
        },
        "cves": ["CVE-2022-1388", "CVE-2023-28771"],
        "recommendations": [
            "Rate-limit or block the attacking source at the firewall or WAF.",
            "Enable upstream DDoS protection if traffic volume is high.",
            "Review exposed services and close unnecessary public ports.",
            "Preserve packet captures and firewall logs for incident review.",
        ],
    },
    "Brute_Force": {
        "type": "Brute Force Attack",
        "risk": "Medium",
        "description": "Repeated authentication-like traffic suggests credential guessing.",
        "severity_weight": 6.0,
        "exploitability_score": 6.5,
        "mitre": {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique": "Brute Force",
        },
        "cves": ["CVE-2020-0796", "CVE-2019-19781"],
        "recommendations": [
            "Enforce MFA for exposed accounts.",
            "Lock accounts after a small number of failed attempts.",
            "Restrict management services such as SSH and RDP by source IP.",
            "Monitor authentication logs for repeated failures.",
        ],
    },
    "Port_Scan": {
        "type": "Port Scan",
        "risk": "Medium",
        "description": "Connection patterns suggest network reconnaissance or service discovery.",
        "severity_weight": 5.5,
        "exploitability_score": 5.0,
        "mitre": {
            "tactic": "Discovery",
            "technique_id": "T1046",
            "technique": "Network Service Scanning",
        },
        "cves": ["CVE-2021-44228", "CVE-2022-1388"],
        "recommendations": [
            "Block or rate-limit the scanning source.",
            "Disable unused ports and services.",
            "Enable IDS rules for reconnaissance behavior.",
            "Use network segmentation to limit lateral discovery.",
        ],
    },
    "Botnet": {
        "type": "Botnet",
        "risk": "High",
        "description": "Traffic resembles command-and-control or coordinated automated activity.",
        "severity_weight": 8.0,
        "exploitability_score": 8.0,
        "mitre": {
            "tactic": "Command and Control",
            "technique_id": "T1071",
            "technique": "Application Layer Protocol",
        },
        "cves": ["CVE-2023-34362", "CVE-2021-22986"],
        "recommendations": [
            "Isolate suspected infected hosts from the network.",
            "Block command-and-control indicators at DNS, proxy, and firewall layers.",
            "Run endpoint malware scans and collect forensic artifacts.",
            "Rotate credentials used on affected systems.",
        ],
    },
    "Malware": {
        "type": "Malware Communication",
        "risk": "Critical",
        "description": "Network behavior indicates possible malware delivery or callback traffic.",
        "severity_weight": 9.5,
        "exploitability_score": 8.5,
        "mitre": {
            "tactic": "Execution",
            "technique_id": "T1204",
            "technique": "User Execution",
        },
        "cves": ["CVE-2017-11882", "CVE-2021-40444", "CVE-2023-38831"],
        "recommendations": [
            "Immediately isolate affected systems.",
            "Block related domains, IPs, and file hashes.",
            "Run endpoint detection and response scans.",
            "Start incident response and preserve evidence.",
            "Patch exploited applications and restore from clean backups if needed.",
        ],
    },
}

RISK_BANDS = [
    (8.5, "Critical"),
    (6.5, "High"),
    (3.5, "Medium"),
    (0.0, "Low"),
]


def _prediction_to_label(prediction) -> str:
    if isinstance(prediction, tuple):
        prediction = prediction[0]
    return le.inverse_transform([int(prediction)])[0]


def classify_risk(score: float) -> str:
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "Low"


def calculate_risk_score(
    probability: float,
    severity_weight: float,
    exploitability_score: float,
    signal_bonus: float = 0.0,
) -> float:
    """Risk Score = probability x weighted(severity, exploitability), normalized to 10."""
    raw_score = probability * ((severity_weight * 0.6) + (exploitability_score * 0.4))
    return round(min(10.0, raw_score + signal_bonus), 2)


def get_threat(prediction, confidence: Optional[float] = None) -> Dict:
    """
    Convert a model prediction into threat-intelligence details.

    The function accepts either the numeric prediction or the legacy
    ``(prediction, probability)`` tuple returned by ``predict``.
    """
    if isinstance(prediction, tuple):
        prediction, tuple_confidence = prediction
        confidence = tuple_confidence if confidence is None else confidence

    threat_name = _prediction_to_label(prediction)
    info = dict(THREAT_KNOWLEDGE.get(threat_name, {}))
    if not info:
        info = {
            "type": "Unknown",
            "risk": "Unknown",
            "description": "Unable to classify threat.",
            "severity_weight": 1.0,
            "exploitability_score": 1.0,
            "mitre": {"tactic": "Unknown", "technique_id": "Unknown", "technique": "Unknown"},
            "cves": [],
            "recommendations": ["Review the source data and model output manually."],
        }

    confidence = float(confidence if confidence is not None else 0.0)
    risk_score = calculate_risk_score(
        confidence,
        info["severity_weight"],
        info["exploitability_score"],
    )
    if threat_name == "Normal":
        risk_score = min(risk_score, 1.0)

    info.update(
        {
            "label": threat_name,
            "confidence": round(confidence, 4),
            "risk_score": risk_score,
            "risk": classify_risk(risk_score),
        }
    )
    return info


def get_recommendations(threat_type: str, extra_signals: Optional[Iterable[str]] = None) -> List[str]:
    normalized = threat_type.lower().replace(" ", "_")
    for label, info in THREAT_KNOWLEDGE.items():
        if label.lower() == normalized or info["type"].lower() == threat_type.lower():
            recommendations = list(info["recommendations"])
            break
    else:
        recommendations = [
            "Review the indicator in a sandbox before user access is allowed.",
            "Monitor related DNS, proxy, and endpoint logs.",
            "Escalate to the security team if the indicator appears in production telemetry.",
        ]

    if extra_signals:
        if any("not using https" in signal.lower() for signal in extra_signals):
            recommendations.append("Prefer HTTPS and block clear-text credential submission.")
        if any("ip address" in signal.lower() for signal in extra_signals):
            recommendations.append("Investigate IP-based URLs because they often bypass domain controls.")

    return recommendations
