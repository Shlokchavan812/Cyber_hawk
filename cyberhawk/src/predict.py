import joblib
import numpy as np
import os

# Get the models directory path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
models_dir = os.path.join(base_dir, "models")

model = joblib.load(os.path.join(models_dir, "model.pkl"))
scaler = joblib.load(os.path.join(models_dir, "scaler.pkl"))


def predict(input_data):
    data = np.array(input_data).reshape(1, -1)
    data = scaler.transform(data)
    pred = model.predict(data)[0]
    prob = model.predict_proba(data).max()
    return pred, prob
