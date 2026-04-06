# 🛡️ Cyber Threat Intelligence System

A machine learning-based system for detecting and classifying cyber threats from network traffic patterns.

## Project Structure

```
cyberhawk/
├── data/
│   └── dataset.csv              # Sample training dataset
├── models/
│   ├── model.pkl               # Trained Random Forest model
│   ├── scaler.pkl              # Feature scaler
│   └── label_encoder.pkl       # Label encoder for threat types
├── src/
│   ├── __init__.py
│   ├── predict.py              # Prediction module
│   ├── preprocessing.py         # Data preprocessing utilities
│   ├── report_generator.py     # PDF report generation
│   ├── threat_intel.py         # Threat mapping and analysis
│   └── train_model.py          # Model training script
├── dashboard/
│   └── app.py                  # Streamlit web interface
├── train.py                    # Standalone training script
└── requirements.txt            # Project dependencies
```

## Features

- **Network Traffic Analysis**: Analyzes 9 network features to detect threats
- **6 Threat Classifications**:
  - Normal Traffic
  - DoS/DDoS Attacks
  - Brute Force Attacks
  - Port Scanning
  - Botnet Activity
  - Malware

- **Risk Levels**: Low, Medium, High, Critical
- **PDF Report Generation**: Automatic threat analysis reports
- **Web Dashboard**: User-friendly Streamlit interface

## Installation

1. **Create and activate virtual environment**:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # On Windows
   source .venv/bin/activate  # On Linux/Mac
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Training the Model

The model has been pre-trained with sample data. To retrain:

```bash
python train.py
```

This will:
- Load the dataset from `data/dataset.csv`
- Train a Random Forest classifier
- Save the model, scaler, and label encoder to `models/`

### Running the Dashboard

Start the Streamlit web interface:

```bash
streamlit run dashboard/app.py
```

The dashboard will open at `http://localhost:8501`

### Sample Input Features

The system expects 9 comma-separated network features:

**Features (in order):**
1. `packet_count` - Number of packets in the flow
2. `byte_count` - Total bytes transferred
3. `duration` - Flow duration in seconds
4. `protocol` - Protocol number (e.g., 6 for TCP)
5. `flags` - TCP flags value
6. `source_port` - Source port number
7. `dest_port` - Destination port number
8. `packet_rate` - Packets per second
9. `data_rate` - Bytes per second

**Example Inputs:**

- **Normal Traffic**: `100, 5000, 10, 6, 0, 1023, 80, 10, 500`
- **DoS Attack**: `500, 25000, 2, 6, 0, 1027, 9200, 250, 12500`
- **Malware**: `600, 30000, 8, 6, 0, 1043, 80, 75, 3750`
- **Brute Force**: `300, 15000, 15, 6, 0, 1031, 22, 20, 1000`

## Model Performance

The trained model achieves excellent performance on the sample dataset:

```
Accuracy: 100%

Classification Report:
              precision    recall  f1-score   support
      Botnet       1.00      1.00      1.00         4
 Brute_Force       1.00      1.00      1.00         1
         DoS       1.00      1.00      1.00         1
     Malware       1.00      1.00      1.00         1
      Normal       1.00      1.00      1.00         2
   Port_Scan       1.00      1.00      1.00         2
```

## Key Components

### 1. Data Preprocessing (`src/preprocessing.py`)
- Handles missing values
- Encodes categorical features
- Scales features using StandardScaler

### 2. Model Training (`src/train_model.py`)
- Trains a Random Forest classifier
- Splits data into train/test sets
- Evaluates model performance

### 3. Threat Intelligence (`src/threat_intel.py`)
- Maps predictions to threat types
- Provides risk levels and descriptions
- Uses label encoding for classification

### 4. Report Generation (`src/report_generator.py`)
- Generates PDF reports with threat analysis
- Includes timestamps and detailed information
- Provides downloadable reports from dashboard

### 5. Web Dashboard (`dashboard/app.py`)
- Streamlit-based user interface
- Real-time threat detection
- Sample input suggestions
- PDF report download capability

## Requirements

- Python 3.10+
- pandas - Data manipulation
- numpy - Numerical computations
- scikit-learn - Machine learning
- matplotlib - Plotting (optional)
- seaborn - Statistical visualization (optional)
- streamlit - Web framework
- joblib - Model serialization
- fpdf - PDF generation

## Testing

A test script is available to verify the system:

```bash
python test_system.py
```

This will:
- Test the prediction module with sample data
- Verify threat intelligence mapping
- Check report generation functionality

## Future Enhancements

- Real-time network traffic integration
- Support for more threat types
- Advanced anomaly detection algorithms
- Historical threat tracking and analytics
- API endpoint for external integrations
- Performance monitoring and metrics

## License

This project is provided as-is for educational and security purposes.

## Support

For issues or questions, refer to the inline code documentation and comments in each module.
