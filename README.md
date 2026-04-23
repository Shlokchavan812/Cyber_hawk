# 🦅 Cyber Hawk

A comprehensive cybersecurity toolkit featuring web vulnerability scanning and machine learning-based threat intelligence for network traffic analysis.

## 🚀 Features

### Web Vulnerability Scanner
- Automated web application security scanning
- Crawl depth configuration
- Real-time vulnerability detection
- User-friendly Streamlit dashboard

### Cyber Threat Intelligence System
- Machine learning-powered threat detection
- 6 threat classifications (Normal, DoS/DDoS, Brute Force, Port Scanning, Botnet, Malware)
- Risk assessment (Low, Medium, High, Critical)
- PDF report generation
- Network traffic pattern analysis

## 📁 Project Structure

```
Cyber_hawk/
├── app.py                          # Main web scanner dashboard
├── requirements.txt                # Root dependencies
├── README.md                       # This file
├── scanner/                        # Web vulnerability scanner
│   ├── __init__.py
│   ├── crawler.py
│   ├── engine.py
│   ├── reporter.py
│   └── vuln_scanner.py
├── utils/                          # Utility functions
│   └── __init__.py
└── cyberhawk/                      # ML threat intelligence system
    ├── analyze.py
    ├── config.json
    ├── train.py
    ├── test_system.py
    ├── requirements.txt
    ├── README.md
    ├── QUICKSTART.md
    ├── PROJECT_SUMMARY.md
    ├── COMPLETION_REPORT.txt
    ├── FILE_INDEX.md
    ├── dashboard/
    │   └── app.py                  # Threat intel dashboard
    ├── data/
    │   └── dataset.csv
    ├── models/
    │   ├── model.pkl
    │   ├── scaler.pkl
    │   └── label_encoder.pkl
    ├── src/
    │   ├── __init__.py
    │   ├── predict.py
    │   ├── preprocessing.py
    │   ├── report_generator.py
    │   ├── threat_intel.py
    │   └── train_model.py
    └── analysis_results/
        └── ...                     # Analysis output files
```

## 🛠️ Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Setup
1. **Clone or navigate to the project directory**

2. **Create and activate virtual environment**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/Mac:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   cd cyberhawk
   pip install -r requirements.txt
   cd ..
   ```

## 🎯 Usage

### Web Vulnerability Scanner
```bash
streamlit run app.py
```
- Access the dashboard at `http://localhost:8501`
- Enter target URL and crawl depth
- Launch scan and view results

### Cyber Threat Intelligence System
```bash
cd cyberhawk
streamlit run dashboard/app.py
```
- Access at `http://localhost:8501`
- Input network traffic features for analysis
- Generate PDF reports

### Training the ML Model (Optional)
```bash
cd cyberhawk
python train.py
```

## 📊 Threat Detection Features

The system analyzes 9 network features:
1. Packet count
2. Byte count
3. Flow duration
4. Protocol number
5. TCP flags
6. Source port
7. Destination port
8. Packet rate
9. Data rate

## 📈 Sample Inputs

- **Normal Traffic**: `100,5000,10,6,0,1023,80,10,500`
- **DoS Attack**: `500,25000,2,6,0,1027,9200,250,12500`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is for educational and research purposes. Use responsibly and in compliance with applicable laws.

## ⚠️ Disclaimer

This tool is designed for authorized security testing only. Users are responsible for obtaining proper authorization before scanning any systems or networks.
