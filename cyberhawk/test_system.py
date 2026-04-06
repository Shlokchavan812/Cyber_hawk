#!/usr/bin/env python3
"""
Test script for the Cyber Threat Intelligence System.
Tests all components to ensure they work correctly.
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test that all required modules can be imported."""
    print("=" * 60)
    print("TEST 1: Module Imports")
    print("=" * 60)
    
    try:
        from src.predict import predict
        print("✓ predict module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import predict: {e}")
        return False
    
    try:
        from src.threat_intel import get_threat
        print("✓ threat_intel module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import threat_intel: {e}")
        return False
    
    try:
        from src.report_generator import generate_report
        print("✓ report_generator module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import report_generator: {e}")
        return False
    
    try:
        from src.preprocessing import load_and_preprocess
        print("✓ preprocessing module imported successfully")
    except Exception as e:
        print(f"✗ Failed to import preprocessing: {e}")
        return False
    
    print()
    return True


def test_model_files():
    """Test that model files exist."""
    print("=" * 60)
    print("TEST 2: Model Files Validation")
    print("=" * 60)
    
    models_dir = project_root / "models"
    required_files = ["model.pkl", "scaler.pkl", "label_encoder.pkl"]
    
    all_exist = True
    for file in required_files:
        path = models_dir / file
        if path.exists():
            size = path.stat().st_size
            print(f"✓ {file} exists ({size:,} bytes)")
        else:
            print(f"✗ {file} NOT FOUND")
            all_exist = False
    
    print()
    return all_exist


def test_predictions():
    """Test prediction functionality."""
    print("=" * 60)
    print("TEST 3: Threat Predictions")
    print("=" * 60)
    
    from src.predict import predict
    from src.threat_intel import get_threat
    
    # Test cases with sample data
    test_cases = [
        {
            "name": "Normal Traffic",
            "features": [100, 5000, 10, 6, 0, 1023, 80, 10, 500],
            "expected_risk": "Low"
        },
        {
            "name": "DoS Attack",
            "features": [500, 25000, 2, 6, 0, 1027, 9200, 250, 12500],
            "expected_risk": "High"
        },
        {
            "name": "Malware",
            "features": [600, 30000, 8, 6, 0, 1043, 80, 75, 3750],
            "expected_risk": "Critical"
        },
        {
            "name": "Brute Force",
            "features": [300, 15000, 15, 6, 0, 1031, 22, 20, 1000],
            "expected_risk": "Medium"
        },
        {
            "name": "Port Scan",
            "features": [200, 10000, 20, 6, 0, 1035, 80, 10, 500],
            "expected_risk": "Medium"
        },
        {
            "name": "Botnet",
            "features": [450, 22500, 25, 6, 0, 1039, 80, 18, 900],
            "expected_risk": "High"
        }
    ]
    
    all_passed = True
    for test in test_cases:
        try:
            pred = predict(test["features"])
            threat = get_threat(pred)
            
            risk = threat["risk"]
            threat_type = threat["type"]
            
            # Check if risk level matches expected
            if risk == test["expected_risk"]:
                status = "✓"
            else:
                status = "⚠"
                all_passed = False
            
            print(f"{status} {test['name']:20} → {threat_type:20} (Risk: {risk})")
            
        except Exception as e:
            print(f"✗ {test['name']:20} → ERROR: {e}")
            all_passed = False
    
    print()
    return all_passed


def test_report_generation():
    """Test PDF report generation."""
    print("=" * 60)
    print("TEST 4: Report Generation")
    print("=" * 60)
    
    from src.report_generator import generate_report
    
    try:
        test_report_path = project_root / "test_report.pdf"
        
        report_data = {
            "Test Report": "System Test",
            "Status": "Passed",
            "Threat Type": "Normal Traffic",
            "Risk Level": "Low"
        }
        
        generated_path = generate_report(report_data, str(test_report_path))
        
        if os.path.exists(generated_path):
            size = os.path.getsize(generated_path)
            print(f"✓ PDF report generated successfully ({size:,} bytes)")
            print(f"  Path: {generated_path}")
            
            # Clean up test report
            os.remove(generated_path)
            print("✓ Test report cleaned up")
            print()
            return True
        else:
            print("✗ Report file was not created")
            print()
            return False
            
    except Exception as e:
        print(f"✗ Failed to generate report: {e}")
        print()
        return False


def test_data_loading():
    """Test data loading and preprocessing."""
    print("=" * 60)
    print("TEST 5: Data Loading & Preprocessing")
    print("=" * 60)
    
    from src.preprocessing import load_and_preprocess
    
    try:
        data_path = project_root / "data" / "dataset.csv"
        
        if not data_path.exists():
            print(f"✗ Dataset not found at {data_path}")
            print()
            return False
        
        X, y, scaler, le = load_and_preprocess(str(data_path))
        
        print(f"✓ Data loaded successfully")
        print(f"  - Feature matrix shape: {X.shape}")
        print(f"  - Target variable shape: {y.shape}")
        print(f"  - Number of classes: {len(le.classes_)}")
        print(f"  - Classes: {', '.join(le.classes_)}")
        print()
        return True
        
    except Exception as e:
        print(f"✗ Failed to load/preprocess data: {e}")
        print()
        return False


def test_end_to_end():
    """Test complete end-to-end workflow."""
    print("=" * 60)
    print("TEST 6: End-to-End Workflow")
    print("=" * 60)
    
    from src.predict import predict
    from src.threat_intel import get_threat
    from src.report_generator import generate_report
    
    try:
        # Sample network traffic data (Brute Force Attack)
        sample_data = [300, 15000, 15, 6, 0, 1031, 22, 20, 1000]
        
        # Step 1: Predict
        print("Step 1: Making prediction...")
        pred = predict(sample_data)
        print(f"  ✓ Prediction made: {int(pred)}")
        
        # Step 2: Get threat info
        print("Step 2: Getting threat intelligence...")
        threat = get_threat(pred)
        print(f"  ✓ Threat type: {threat['type']}")
        print(f"  ✓ Risk level: {threat['risk']}")
        
        # Step 3: Generate report
        print("Step 3: Generating report...")
        test_report_path = project_root / "test_e2e_report.pdf"
        report_data = {
            "Threat Analysis": "End-to-End Test",
            "Type": threat['type'],
            "Risk": threat['risk'],
            "Features": ", ".join(str(f) for f in sample_data)
        }
        
        generated_path = generate_report(report_data, str(test_report_path))
        
        if os.path.exists(generated_path):
            print(f"  ✓ Report generated")
            os.remove(generated_path)
        
        print("✓ End-to-end workflow completed successfully")
        print()
        return True
        
    except Exception as e:
        print(f"✗ End-to-end workflow failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def main():
    """Run all tests."""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "Cyber Threat Intelligence System" + " " * 16 + "║")
    print("║" + " " * 20 + "System Test Suite" + " " * 22 + "║")
    print("╚" + "=" * 58 + "╝")
    print()
    
    results = {
        "Module Imports": test_imports(),
        "Model Files": test_model_files(),
        "Threat Predictions": test_predictions(),
        "Report Generation": test_report_generation(),
        "Data Loading": test_data_loading(),
        "End-to-End": test_end_to_end(),
    }
    
    # Print summary
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:<8} {test_name}")
    
    print("=" * 60)
    print(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! System is ready to use.")
        print("\nTo start the dashboard, run:")
        print("  streamlit run dashboard/app.py")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the errors above.")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
