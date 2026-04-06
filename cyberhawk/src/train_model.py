import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from .preprocessing import load_and_preprocess

# Get the directory paths
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data_path = os.path.join(base_dir, "data", "dataset.csv")
models_dir = os.path.join(base_dir, "models")
os.makedirs(models_dir, exist_ok=True)

X, y, scaler, le = load_and_preprocess(data_path)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = RandomForestClassifier()
model.fit(X_train, y_train)

preds = model.predict(X_test)
print(classification_report(y_test, preds))

model_path = os.path.join(models_dir, "model.pkl")
scaler_path = os.path.join(models_dir, "scaler.pkl")
le_path = os.path.join(models_dir, "label_encoder.pkl")

joblib.dump(model, model_path)
joblib.dump(scaler, scaler_path)
joblib.dump(le, le_path)

print(f"Model saved to {model_path}")
print(f"Scaler saved to {scaler_path}")
print(f"Label encoder saved to {le_path}")
