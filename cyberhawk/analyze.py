#!/usr/bin/env python3
"""
Advanced analysis script for batch processing and detailed threat analysis.
Can process multiple network flows and generate comprehensive reports.
"""

import sys
import os
from pathlib import Path
import json
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.predict import predict
from src.threat_intel import get_threat


class ThreatAnalyzer:
    """Advanced threat analysis engine."""
    
    def __init__(self):
        self.results = []
        self.stats = {
            "total_flows": 0,
            "threats_detected": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "threat_breakdown": {}
        }
    
    def analyze_flow(self, flow_data, flow_id=None):
        """
        Analyze a single network flow.
        
        Args:
            flow_data: List of 9 features
            flow_id: Optional identifier for the flow
            
        Returns:
            Dictionary with analysis results
        """
        if flow_id is None:
            flow_id = f"flow_{self.stats['total_flows'] + 1}"
        
        try:
            # Validate input
            if len(flow_data) != 9:
                raise ValueError(f"Expected 9 features, got {len(flow_data)}")
            
            # Make prediction
            pred = predict(flow_data)
            threat = get_threat(pred)
            
            # Build result
            result = {
                "flow_id": flow_id,
                "timestamp": datetime.now().isoformat(),
                "prediction": int(pred),
                "threat_type": threat["type"],
                "risk_level": threat["risk"],
                "description": threat.get("description", ""),
                "features": {
                    "packet_count": flow_data[0],
                    "byte_count": flow_data[1],
                    "duration": flow_data[2],
                    "protocol": flow_data[3],
                    "flags": flow_data[4],
                    "source_port": flow_data[5],
                    "dest_port": flow_data[6],
                    "packet_rate": flow_data[7],
                    "data_rate": flow_data[8]
                },
                "severity_score": self._calculate_severity(threat["risk"])
            }
            
            # Update statistics
            self.stats["total_flows"] += 1
            self.stats["threats_detected"] += 1 if threat["risk"] != "Low" else 0
            self.stats[threat["risk"].lower()] = self.stats.get(threat["risk"].lower(), 0) + 1
            
            # Track threat types
            threat_key = threat["type"]
            if threat_key not in self.stats["threat_breakdown"]:
                self.stats["threat_breakdown"][threat_key] = 0
            self.stats["threat_breakdown"][threat_key] += 1
            
            self.results.append(result)
            return result
            
        except Exception as e:
            error_result = {
                "flow_id": flow_id,
                "error": str(e),
                "status": "failed"
            }
            self.results.append(error_result)
            return error_result
    
    def analyze_batch(self, flows_data):
        """
        Analyze multiple flows.
        
        Args:
            flows_data: List of flow data (each flow is a list of 9 features)
            
        Returns:
            List of analysis results
        """
        batch_results = []
        for idx, flow in enumerate(flows_data):
            result = self.analyze_flow(flow, f"flow_{idx + 1}")
            batch_results.append(result)
        
        return batch_results
    
    @staticmethod
    def _calculate_severity(risk_level):
        """Convert risk level to numeric severity score (0-100)."""
        severity_map = {
            "Low": 10,
            "Medium": 50,
            "High": 75,
            "Critical": 100
        }
        return severity_map.get(risk_level, 0)
    
    def get_statistics(self):
        """Get analysis statistics."""
        return self.stats
    
    def get_critical_flows(self):
        """Get all flows with critical risk level."""
        return [r for r in self.results if r.get("risk_level") == "Critical"]
    
    def get_high_risk_flows(self):
        """Get all flows with high risk level."""
        return [r for r in self.results 
                if r.get("risk_level") in ["High", "Critical"]]
    
    def export_json(self, filepath):
        """Export results to JSON file."""
        data = {
            "timestamp": datetime.now().isoformat(),
            "statistics": self.stats,
            "results": self.results
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return filepath
    
    def export_csv(self, filepath):
        """Export results to CSV file."""
        import csv
        
        if not self.results:
            print("No results to export")
            return
        
        with open(filepath, 'w', newline='') as f:
            fieldnames = [
                "flow_id", "timestamp", "prediction", "threat_type", 
                "risk_level", "severity_score", "packet_count", "byte_count",
                "duration", "protocol", "source_port", "dest_port"
            ]
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in self.results:
                if "error" not in result:
                    row = {
                        "flow_id": result["flow_id"],
                        "timestamp": result["timestamp"],
                        "prediction": result["prediction"],
                        "threat_type": result["threat_type"],
                        "risk_level": result["risk_level"],
                        "severity_score": result["severity_score"],
                        "packet_count": result["features"]["packet_count"],
                        "byte_count": result["features"]["byte_count"],
                        "duration": result["features"]["duration"],
                        "protocol": result["features"]["protocol"],
                        "source_port": result["features"]["source_port"],
                        "dest_port": result["features"]["dest_port"]
                    }
                    writer.writerow(row)
        
        return filepath
    
    def print_summary(self):
        """Print analysis summary."""
        stats = self.stats
        
        print("\n" + "=" * 70)
        print("THREAT ANALYSIS SUMMARY")
        print("=" * 70)
        print(f"Total Flows Analyzed: {stats['total_flows']}")
        print(f"Threats Detected: {stats['threats_detected']}")
        print(f"  - Critical: {stats.get('critical', 0)}")
        print(f"  - High: {stats.get('high', 0)}")
        print(f"  - Medium: {stats.get('medium', 0)}")
        print(f"  - Low: {stats.get('low', 0)}")
        
        if stats["threat_breakdown"]:
            print("\nThreat Type Breakdown:")
            for threat_type, count in sorted(stats["threat_breakdown"].items(), 
                                            key=lambda x: x[1], reverse=True):
                print(f"  - {threat_type}: {count}")
        print("=" * 70 + "\n")


def main():
    """Run advanced analysis."""
    
    print("\n" + "╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "Advanced Threat Analysis Tool" + " " * 24 + "║")
    print("╚" + "=" * 68 + "╝\n")
    
    analyzer = ThreatAnalyzer()
    
    # Sample network flows for batch analysis
    sample_flows = [
        # Normal traffic
        [100, 5000, 10, 6, 0, 1023, 80, 10, 500],
        [105, 5250, 11, 6, 0, 1047, 80, 9.5, 477],
        
        # DoS attacks
        [500, 25000, 2, 6, 0, 1027, 9200, 250, 12500],
        [510, 25500, 2.5, 6, 0, 1051, 9200, 204, 10200],
        
        # Malware
        [600, 30000, 8, 6, 0, 1043, 80, 75, 3750],
        [610, 30500, 7.5, 6, 0, 1067, 80, 81.3, 4066],
        
        # Brute Force
        [300, 15000, 15, 6, 0, 1031, 22, 20, 1000],
        [305, 15250, 14.5, 6, 0, 1055, 22, 21, 1051],
        
        # Port Scans
        [200, 10000, 20, 6, 0, 1035, 80, 10, 500],
        [195, 9750, 19, 6, 0, 1059, 80, 10.2, 512],
        
        # Botnet
        [450, 22500, 25, 6, 0, 1039, 80, 18, 900],
        [460, 23000, 24.5, 6, 0, 1063, 80, 18.7, 938],
    ]
    
    print("Processing sample network flows...")
    print("-" * 70)
    
    # Analyze all flows
    results = analyzer.analyze_batch(sample_flows)
    
    # Print results
    for result in results:
        if "error" not in result:
            threat = result["threat_type"]
            risk = result["risk_level"]
            severity = result["severity_score"]
            flow_id = result["flow_id"]
            
            # Color-code risk levels in output
            risk_symbol = {
                "Low": "🟢",
                "Medium": "🟡",
                "High": "🔴",
                "Critical": "⛔"
            }.get(risk, "❓")
            
            print(f"{flow_id:10} → {threat:25} {risk_symbol} {risk:10} (Severity: {severity})")
    
    print("-" * 70)
    
    # Print summary
    analyzer.print_summary()
    
    # Export results
    output_dir = project_root / "analysis_results"
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Export as JSON
    json_path = output_dir / f"analysis_{timestamp}.json"
    analyzer.export_json(str(json_path))
    print(f"✓ Results exported to JSON: {json_path.name}")
    
    # Export as CSV
    csv_path = output_dir / f"analysis_{timestamp}.csv"
    analyzer.export_csv(str(csv_path))
    print(f"✓ Results exported to CSV: {csv_path.name}")
    
    # Get critical flows if any
    critical_flows = analyzer.get_critical_flows()
    if critical_flows:
        print(f"\n⚠️  ALERT: {len(critical_flows)} critical threat(s) detected!")
        for flow in critical_flows:
            print(f"   - {flow['flow_id']}: {flow['threat_type']}")
    
    print("\nAnalysis complete!")


if __name__ == "__main__":
    main()
