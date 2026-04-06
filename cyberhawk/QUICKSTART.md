# Quick Start Guide

## 🚀 Getting Started (5 minutes)

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Step 1: Initial Setup

```bash
# Navigate to the project directory
cd cyberhawk

# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Train the Model (Optional)

The model has been pre-trained. To retrain with sample data:

```bash
python train.py
```

Expected output:
```
Starting model training...
Loading data from C:\Users\ADITYA\cyberhawk\data\dataset.csv...
Data shape: (52, 9)
...
Model saved to C:\Users\ADITYA\cyberhawk\models\model.pkl
Training complete!
```

### Step 3: Verify Installation

Run the test suite to ensure everything is working:

```bash
python test_system.py
```

Expected output:
```
🎉 All tests passed! System is ready to use.
```

### Step 4: Run the Dashboard

Start the web interface:

```bash
streamlit run dashboard/app.py
```

The dashboard will open in your browser at `http://localhost:8501`

---

## 📊 Using the System

### Option 1: Web Dashboard (Recommended)

The Streamlit dashboard provides the easiest way to use the system:

1. **Enter feature values** - Copy one of the sample inputs
2. **Click "Detect Threat"** button
3. **View results** - See threat type and risk level
4. **Generate Report** - Create a PDF report if needed

**Sample Inputs:**
- **Normal**: `100, 5000, 10, 6, 0, 1023, 80, 10, 500`
- **DoS**: `500, 25000, 2, 6, 0, 1027, 9200, 250, 12500`
- **Malware**: `600, 30000, 8, 6, 0, 1043, 80, 75, 3750`

### Option 2: Batch Analysis

For analyzing multiple network flows:

```bash
python analyze.py
```

This will:
- Analyze 12 sample network flows
- Generate statistics and threat breakdown
- Export results to JSON and CSV files in `analysis_results/` directory

### Option 3: Python API

Use the system programmatically:

```python
from src.predict import predict
from src.threat_intel import get_threat

# Prepare network features
features = [100, 5000, 10, 6, 0, 1023, 80, 10, 500]

# Make prediction
prediction = predict(features)

# Get threat information
threat = get_threat(prediction)

print(f"Threat Type: {threat['type']}")
print(f"Risk Level: {threat['risk']}")
```

---

## 📁 Project Files

```
Key Files:
├── train.py                # Model training
├── test_system.py          # System tests
├── analyze.py              # Batch analysis tool
├── dashboard/app.py        # Web interface
└── src/
    ├── predict.py          # Prediction engine
    ├── threat_intel.py     # Threat mapping
    ├── report_generator.py # PDF reports
    └── preprocessing.py    # Data preprocessing

Data & Models:
├── data/dataset.csv        # Training dataset
└── models/
    ├── model.pkl           # Trained model
    ├── scaler.pkl          # Feature scaler
    └── label_encoder.pkl   # Label encoder

Output:
└── analysis_results/       # Batch analysis results
```

---

## 🎯 Feature Reference

The system uses 9 network traffic features:

| # | Feature Name | Description | Example |
|---|---|---|---|
| 1 | packet_count | Number of packets in flow | 100-600 |
| 2 | byte_count | Total bytes transferred | 5000-35000 |
| 3 | duration | Flow duration (seconds) | 1-26 |
| 4 | protocol | Network protocol | 6 (TCP) |
| 5 | flags | TCP flags value | 0 |
| 6 | source_port | Source port | 1023-1070 |
| 7 | dest_port | Destination port | 22, 80, 443, 5060, 8080, 9200, 3306, 3389 |
| 8 | packet_rate | Packets per second | 8-311 |
| 9 | data_rate | Bytes per second | 400-15555 |

---

## 🎓 Threat Classifications

The system detects 6 types of threats:

| Threat Type | Risk Level | Characteristics |
|---|---|---|
| **Normal Traffic** | Low 🟢 | Regular network communication |
| **Port Scan** | Medium 🟡 | Network reconnaissance (low packet rate) |
| **Brute Force** | Medium 🟡 | Multiple connection attempts to port 22 |
| **DoS Attack** | High 🔴 | High packet/data rate, short duration |
| **Botnet** | High 🔴 | Suspicious patterns, various ports |
| **Malware** | Critical ⛔ | Very high data rates, command patterns |

---

## 🔧 Troubleshooting

### Issue: "Module not found" error

**Solution:**
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

### Issue: "Model files not found"

**Solution:**
```bash
# Retrain the model
python train.py
```

### Issue: Streamlit port already in use

**Solution:**
```bash
# Use a different port
streamlit run dashboard/app.py -- --server.port 8502
```

### Issue: Slow performance

**Solution:**
```bash
# Ensure you're using the virtual environment
.venv\Scripts\python.exe test_system.py
```

---

## 📈 Next Steps

1. **Test with real data:** Replace sample dataset with your network data
2. **Integrate with SIEM:** Connect to security tools
3. **Add more features:** Enhance detection with additional metrics
4. **Deploy to cloud:** Use Docker/Kubernetes for production

---

## 📞 Support

- Check the main **README.md** for detailed documentation
- Review code comments in each module
- Run `test_system.py` to verify installation
- Check browser console for debug messages

---

## ✅ Quick Verification Checklist

- [ ] Python installed (3.10+)
- [ ] Virtual environment activated
- [ ] Dependencies installed
- [ ] Test suite passes
- [ ] Dashboard loads in browser
- [ ] Sample prediction works

**Ready to detect threats!** 🛡️
