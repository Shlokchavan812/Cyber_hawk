#!/usr/bin/env python3
"""Training script for the cyber threat detection model."""
import sys
import os

# Add the project root to the path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

def load_and_preprocess(path):
    df = pd.read_csv(path)
    df = df.dropna()

    le = LabelEncoder()
    df['label'] = le.fit_transform(df['label'])

    X = df.drop('label', axis=1)
    y = df['label']

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y, scaler, le

def main():
    print("Starting model training...")
    
    # Paths
    data_path = os.path.join(project_root, "data", "dataset.csv")
    models_dir = os.path.join(project_root, "models")
    os.makedirs(models_dir, exist_ok=True)
    
    # Load and preprocess data
    print(f"Loading data from {data_path}...")
    X, y, scaler, le = load_and_preprocess(data_path)
    print(f"Data shape: {X.shape}")
    print(f"Classes: {le.classes_}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"Training set size: {X_train.shape[0]}, Test set size: {X_test.shape[0]}")
    
    # Train model
    print("Training RandomForestClassifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    preds = model.predict(X_test)
    accuracy = accuracy_score(y_test, preds)
    print(f"\nAccuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, preds, target_names=le.classes_))
    
    # Save models
    model_path = os.path.join(models_dir, "model.pkl")
    scaler_path = os.path.join(models_dir, "scaler.pkl")
    le_path = os.path.join(models_dir, "label_encoder.pkl")
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(le, le_path)
    
    print(f"\nModel saved to {model_path}")
    print(f"Scaler saved to {scaler_path}")
    print(f"Label encoder saved to {le_path}")
    print("Training complete!")

if __name__ == "__main__":
    main()
