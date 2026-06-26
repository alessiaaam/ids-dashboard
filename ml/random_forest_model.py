import pandas as pd
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

MODEL_PATH = "ml/random_forest.pkl"

FEATURES_USED = [
    "total_packets",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "unique_destination_ports",
    "syn_count",
    "syn_ack_ratio",
]

LABEL_MAP = {
    "BENIGN": 0,
    "PORT_SCAN": 1,
    "SYN_FLOOD": 2,
    "BRUTE_FORCE": 3,
}

LABEL_NAMES = {v: k for k, v in LABEL_MAP.items()}

def map_cicids_to_features(df):
    result = pd.DataFrame()
    result["total_packets"] = df["Total Fwd Packets"] + df["Total Backward Packets"]
    result["total_bytes"] = df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"]
    result["packets_per_second"] = df["Flow Packets/s"].replace([np.inf, -np.inf], 0)
    result["bytes_per_second"] = df["Flow Bytes/s"].replace([np.inf, -np.inf], 0)
    result["unique_destination_ports"] = df["Destination Port"]
    result["syn_count"] = df["SYN Flag Count"]
    ack = df["ACK Flag Count"].replace(0, 1)
    result["syn_ack_ratio"] = (df["SYN Flag Count"] / ack).replace([np.inf, -np.inf], 0)
    return result.fillna(0)

def map_label(label):
    label = str(label).strip()
    if label == "BENIGN":
        return 0
    elif label == "PortScan":
        return 1
    elif label in ["DoS slowloris", "DoS Slowhttptest", "DoS Hulk", "DoS GoldenEye", "DDoS"]:
        return 2
    elif label in ["Brute Force", "FTP-Patator", "SSH-Patator"]:
        return 3
    elif label == "Heartbleed":
        return 2
    else:
        return 0

def load_and_prepare(filepath, sample_benign=5000, sample_attack=5000):
    print(f"Incarc {filepath}...")
    df = pd.read_csv(filepath)
    df.columns = df.columns.str.strip()
    df["label_num"] = df["Label"].apply(map_label)
    benign = df[df["label_num"] == 0].sample(min(sample_benign, len(df[df["label_num"] == 0])), random_state=42)
    attack = df[df["label_num"] != 0].sample(min(sample_attack, len(df[df["label_num"] != 0])), random_state=42)
    sampled = pd.concat([benign, attack])
    X = map_cicids_to_features(sampled)
    y = sampled["label_num"]
    return X, y

def load_lab_data(filepath="ml/lab_data.csv"):
    df = pd.read_csv(filepath)
    X = df[FEATURES_USED].fillna(0)
    y = df["label"]
    return X, y

def train():
    dfs_X, dfs_y = [], []

    X1, y1 = load_and_prepare("ml/Wednesday-workingHours.pcap_ISCX.csv")
    dfs_X.append(X1)
    dfs_y.append(y1)

    X2, y2 = load_and_prepare("ml/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    dfs_X.append(X2)
    dfs_y.append(y2)

    X3, y3 = load_and_prepare("ml/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    dfs_X.append(X3)
    dfs_y.append(y3)

    print("Incarc ml/lab_data.csv...")
    X4, y4 = load_lab_data()
    dfs_X.append(X4)
    dfs_y.append(y4)

    X = pd.concat(dfs_X).reset_index(drop=True)
    y = pd.concat(dfs_y).reset_index(drop=True)

    print(f"Total exemple: {len(X)}")
    print(f"Distributie clase: {y.value_counts().to_dict()}")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Antrenez Random Forest...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, oob_score=True)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy (test set): {acc:.4f} ({acc*100:.2f}%)")
    print(f"OOB Score: {model.oob_score_:.4f} ({model.oob_score_*100:.2f}%)")
    print()
    labels_present = sorted(y_test.unique())
    names_present = [["BENIGN", "PORT_SCAN", "SYN_FLOOD", "BRUTE_FORCE"][l] for l in labels_present]
    print(classification_report(y_test, y_pred, labels=labels_present, target_names=names_present))

    joblib.dump(model, MODEL_PATH)
    print(f"Model salvat la {MODEL_PATH}")
    return model

def load_model():
    if not os.path.exists(MODEL_PATH):
        return train()
    return joblib.load(MODEL_PATH)

def predict_rf(features_df):
    if features_df.empty:
        return []

    model = load_model()
    X = features_df[FEATURES_USED].fillna(0)
    predictions = model.predict(X)
    probabilities = model.predict_proba(X)

    alerts = []
    for i, (pred, proba) in enumerate(zip(predictions, probabilities)):
        if pred == 0:
            continue
        row = features_df.iloc[i]
        confidence = round(float(max(proba)) * 100, 1)
        label = LABEL_NAMES.get(int(pred), "UNKNOWN")
        severity_map = {
            "PORT_SCAN": "HIGH",
            "SYN_FLOOD": "CRITICAL",
            "BRUTE_FORCE": "CRITICAL",
        }
        severity = severity_map.get(label, "MEDIUM")
        features_dict = {
            "total_packets": int(row.get("total_packets", 0)),
            "total_bytes": int(row.get("total_bytes", 0)),
            "packets_per_second": round(float(row.get("packets_per_second", 0)), 2),
            "bytes_per_second": round(float(row.get("bytes_per_second", 0)), 2),
            "unique_destination_ports": int(row.get("unique_destination_ports", 0)),
            "syn_count": int(row.get("syn_count", 0)),
            "syn_ack_ratio": round(float(row.get("syn_ack_ratio", 0)), 4),
        }
        alerts.append({
            "window_id": row["window_id"],
            "type": label,
            "severity": severity,
            "detail": f"Detectat de Random Forest cu confidenta {confidence}%",
            "timestamp": row["window_start"],
            "rf_confidence": confidence,
            "src_ip": row["src_ip"] if "src_ip" in row.index else "unknown",
            "features_json": json.dumps(features_dict),
        })
    return alerts

if __name__ == "__main__":
    train()
