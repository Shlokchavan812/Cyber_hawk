import joblib
import numpy as np
import os
import pandas as pd

# Get the models directory path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
models_dir = os.path.join(base_dir, "models")

model = joblib.load(os.path.join(models_dir, "model.pkl"))
scaler = joblib.load(os.path.join(models_dir, "scaler.pkl"))

FEATURE_NAMES = [
    "packet_count",
    "byte_count",
    "duration",
    "protocol",
    "flags",
    "source_port",
    "dest_port",
    "packet_rate",
    "data_rate",
]


def predict(input_data):
    data = pd.DataFrame(np.array(input_data).reshape(1, -1), columns=FEATURE_NAMES)
    data = scaler.transform(data)
    pred = model.predict(data)[0]
    prob = model.predict_proba(data).max()
    return pred, prob
