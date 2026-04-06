import joblib
import os

# Get the models directory path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
models_dir = os.path.join(base_dir, "models")

# Load label encoder to map predictions back to threat names
le = joblib.load(os.path.join(models_dir, "label_encoder.pkl"))

threat_map = {
    "Botnet": {"type": "Botnet", "risk": "High", "description": "Botnet activity detected"},
    "Brute_Force": {"type": "Brute Force Attack", "risk": "Medium", "description": "Brute force attack pattern"},
    "DoS": {"type": "Denial of Service", "risk": "High", "description": "DoS/DDoS attack detected"},
    "Malware": {"type": "Malware", "risk": "Critical", "description": "Malicious software activity"},
    "Normal": {"type": "Normal Traffic", "risk": "Low", "description": "No threats detected"},
    "Port_Scan": {"type": "Port Scan", "risk": "Medium", "description": "Network reconnaissance activity"}
}


def get_threat(pred):
    """
    Convert prediction to threat information.
    
    Args:
        pred: Numeric prediction from the model
        
    Returns:
        Dictionary with threat type, risk level, and description
    """
    # Convert numeric prediction to threat name
    threat_name = le.inverse_transform([int(pred)])[0]
    return threat_map.get(threat_name, {"type": "Unknown", "risk": "Unknown", "description": "Unable to classify threat"})
