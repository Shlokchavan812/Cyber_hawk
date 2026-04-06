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
