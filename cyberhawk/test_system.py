#!/usr/bin/env python3
"""
Smoke tests for the CyberHawk threat intelligence system.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


def print_header(title: str):
    print("=" * 72)
    print(title)
    print("=" * 72)


def test_imports() -> bool:
    print_header("TEST 1: Module imports")
    modules = [
        ("src.predict", "predict"),
        ("src.threat_intel", "get_threat"),
        ("src.report_generator", "generate_report"),
        ("src.website_threat_analyzer", "analyze_multiple_urls"),
        ("src.preprocessing", "load_and_preprocess"),
    ]
    ok = True
    for module, symbol in modules:
        try:
            imported = __import__(module, fromlist=[symbol])
            getattr(imported, symbol)
            print(f"PASS {module}.{symbol}")
        except Exception as exc:
            ok = False
            print(f"FAIL {module}.{symbol}: {exc}")
    print()
    return ok


def test_model_files() -> bool:
    print_header("TEST 2: Model files")
    models_dir = PROJECT_ROOT / "models"
    ok = True
    for filename in ["model.pkl", "scaler.pkl", "label_encoder.pkl"]:
        path = models_dir / filename
        if path.exists():
            print(f"PASS {filename} exists ({path.stat().st_size:,} bytes)")
        else:
            ok = False
            print(f"FAIL {filename} is missing")
    print()
    return ok


def test_predictions() -> bool:
    print_header("TEST 3: ML predictions and threat intelligence")
    from src.predict import predict
    from src.threat_intel import get_threat

    test_cases = [
        ("Normal Traffic", [100, 5000, 10, 6, 0, 1023, 80, 10, 500], "Low"),
        ("DoS Attack", [500, 25000, 2, 6, 0, 1027, 9200, 250, 12500], "High"),
        ("Malware", [600, 30000, 8, 6, 0, 1043, 80, 75, 3750], "Critical"),
        ("Brute Force", [300, 15000, 15, 6, 0, 1031, 22, 20, 1000], "Medium"),
        ("Port Scan", [200, 10000, 20, 6, 0, 1035, 80, 10, 500], "Medium"),
        ("Botnet", [450, 22500, 25, 6, 0, 1039, 80, 18, 900], "High"),
    ]

    ok = True
    for name, features, expected_risk in test_cases:
        try:
            prediction, confidence = predict(features)
            threat = get_threat(prediction, confidence)
            matched = threat["risk"] == expected_risk
            ok = ok and matched
            status = "PASS" if matched else "FAIL"
            print(
                f"{status} {name:<16} -> {threat['type']:<24} "
                f"risk={threat['risk']:<8} confidence={confidence * 100:.2f}%"
            )
        except Exception as exc:
            ok = False
            print(f"FAIL {name}: {exc}")
    print()
    return ok


def test_report_generation() -> bool:
    print_header("TEST 4: PDF report generation")
    from src.report_generator import generate_report, generate_website_report

    try:
        network_path = PROJECT_ROOT / "test_network_report.pdf"
        website_path = PROJECT_ROOT / "test_website_report.pdf"
        network_data = {
            "Attack Type": "Port Scan",
            "Confidence Score": "92.00%",
            "Risk Score": "5.1/10",
            "Risk Level": "Medium",
            "MITRE Technique": "T1046 - Network Service Scanning",
            "CVE References": "CVE-2021-44228",
            "Description": "Test report",
            "Input Features": "200, 10000, 20, 6, 0, 1035, 80, 10, 500",
            "Recommendations": ["Block source IP", "Disable unused ports"],
        }
        website_data = {
            "urls_analyzed": 1,
            "threats_found": 1,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 1,
            "low_count": 0,
            "summary": "Test website report",
            "analysis_results": [
                {
                    "url": "https://example.test",
                    "domain": "example.test",
                    "ip_address": "127.0.0.1",
                    "hosting_provider": "local",
                    "ssl_valid": True,
                    "blacklist_status": "Not listed",
                    "threat_type": "Suspicious Website",
                    "risk_level": "Medium",
                    "risk_score": 4.2,
                    "confidence_score": 50,
                    "mitre": {"technique_id": "T1189", "technique": "Drive-by Compromise"},
                    "cves": ["CVE-2021-44228"],
                    "detected_threats": ["Test signal"],
                    "browser_behavior": {"script_count": 1, "form_count": 0, "hidden_iframes": 0},
                    "recommendations": ["Review in a sandbox"],
                }
            ],
        }

        generated_network = generate_report(network_data, str(network_path))
        generated_website = generate_website_report(website_data, str(website_path))
        ok = Path(generated_network).exists() and Path(generated_website).exists()
        print(f"PASS network report: {generated_network}")
        print(f"PASS website report: {generated_website}")
        for path in [network_path, website_path]:
            if path.exists():
                path.unlink()
        print()
        return ok
    except Exception as exc:
        print(f"FAIL report generation: {exc}")
        print()
        return False


def test_data_loading() -> bool:
    print_header("TEST 5: Data loading and preprocessing")
    from src.preprocessing import load_and_preprocess

    try:
        X, y, scaler, encoder = load_and_preprocess(str(PROJECT_ROOT / "data" / "dataset.csv"))
        print(f"PASS feature matrix shape: {X.shape}")
        print(f"PASS target shape: {y.shape}")
        print(f"PASS classes: {', '.join(encoder.classes_)}")
        print()
        return X.shape[1] == 9 and len(encoder.classes_) >= 6
    except Exception as exc:
        print(f"FAIL data loading: {exc}")
        print()
        return False


def test_website_pipeline() -> bool:
    print_header("TEST 6: URL intelligence pipeline")
    from src.website_threat_analyzer import analyze_multiple_urls

    try:
        result = analyze_multiple_urls(["https://example.com", "http://192.168.1.1"])
        required_keys = {"urls_analyzed", "analysis_results", "summary"}
        ok = required_keys.issubset(result.keys()) and result["urls_analyzed"] == 2
        first = result["analysis_results"][0]
        detail_ok = {"ml_detection", "risk_score", "recommendations", "mitre"}.issubset(first.keys())
        print(f"PASS analyzed URLs: {result['urls_analyzed']}")
        print(f"PASS summary: {result['summary']}")
        print()
        return ok and detail_ok
    except Exception as exc:
        print(f"FAIL website pipeline: {exc}")
        print()
        return False


def test_end_to_end() -> bool:
    print_header("TEST 7: Network end-to-end workflow")
    from src.predict import predict
    from src.report_generator import generate_report
    from src.threat_intel import get_threat

    try:
        sample_data = [300, 15000, 15, 6, 0, 1031, 22, 20, 1000]
        prediction, confidence = predict(sample_data)
        threat = get_threat(prediction, confidence)
        report_path = PROJECT_ROOT / "test_e2e_report.pdf"
        generated = generate_report(
            {
                "Attack Type": threat["type"],
                "Confidence Score": f"{confidence * 100:.2f}%",
                "Risk Score": f"{threat['risk_score']}/10",
                "Risk Level": threat["risk"],
                "MITRE Technique": f"{threat['mitre']['technique_id']} - {threat['mitre']['technique']}",
                "CVE References": ", ".join(threat["cves"]),
                "Description": threat["description"],
                "Input Features": ", ".join(str(x) for x in sample_data),
                "Recommendations": threat["recommendations"],
            },
            str(report_path),
        )
        ok = Path(generated).exists()
        print(f"PASS predicted {threat['type']} with {confidence * 100:.2f}% confidence")
        print(f"PASS report path: {generated}")
        if report_path.exists():
            report_path.unlink()
        print()
        return ok
    except Exception as exc:
        print(f"FAIL end-to-end workflow: {exc}")
        print()
        return False


def main() -> int:
    print()
    print_header("CyberHawk System Test Suite")
    results = {
        "Module Imports": test_imports(),
        "Model Files": test_model_files(),
        "Threat Predictions": test_predictions(),
        "Report Generation": test_report_generation(),
        "Data Loading": test_data_loading(),
        "Website Pipeline": test_website_pipeline(),
        "End-to-End": test_end_to_end(),
    }

    print_header("TEST SUMMARY")
    passed = sum(1 for result in results.values() if result)
    for name, result in results.items():
        print(f"{'PASS' if result else 'FAIL'} {name}")
    print(f"Total: {passed}/{len(results)} tests passed")

    if passed == len(results):
        print("System is ready. Start the dashboard with:")
        print("  streamlit run dashboard/app.py")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
