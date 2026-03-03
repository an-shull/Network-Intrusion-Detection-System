# train_and_save_all.py
# Run this once to produce all model .pkl / .h5 / scaler files
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier
import tensorflow as tf
from tensorflow.keras import layers, models as km
from preprocessing import engineer_features

DATA_PATH = r"C:\Users\tanis\Desktop\MAJOR\pcaps\merged_final.csv"
MODELS_DIR = "models/"
RANDOM_STATE = 42

import os; os.makedirs(MODELS_DIR, exist_ok=True)

# ── Load & engineer features ──────────────────────────────────────────────────
print("Loading dataset...")
df = pd.read_csv(DATA_PATH)
X, ja3_encoders = engineer_features(df, fit_encoders=True)
y_raw = df['label'].astype(str)
label_enc = LabelEncoder()
y = label_enc.fit_transform(y_raw)

# Save shared artefacts
joblib.dump(ja3_encoders,  MODELS_DIR + "ja3_encoders.pkl")
joblib.dump(label_enc,     MODELS_DIR + "label_encoder.pkl")
print("Labels:", list(label_enc.classes_))

# ── Splits ────────────────────────────────────────────────────────────────────
X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30,
                                                     random_state=RANDOM_STATE, stratify=y)
X_test, X_val, y_test, y_val   = train_test_split(X_temp, y_temp, test_size=0.3333333,
                                                   random_state=RANDOM_STATE, stratify=y_temp)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)
joblib.dump(scaler, MODELS_DIR + "scaler.pkl")

# ── 1. Random Forest ──────────────────────────────────────────────────────────
print("Training Random Forest...")
rf = RandomForestClassifier(n_estimators=200, random_state=RANDOM_STATE, n_jobs=-1)
rf.fit(X_train, y_train)
joblib.dump(rf, MODELS_DIR + "random_forest.pkl")
print("  RF saved.")

# ── 2. XGBoost ────────────────────────────────────────────────────────────────
print("Training XGBoost...")
xgb = XGBClassifier(n_estimators=200, eval_metric='mlogloss',
                    random_state=RANDOM_STATE, n_jobs=4)
xgb.fit(X_train, y_train)
joblib.dump(xgb, MODELS_DIR + "xgboost.pkl")
print("  XGB saved.")

# ── 3. Logistic Regression ────────────────────────────────────────────────────
print("Training Logistic Regression...")
lr = LogisticRegression(max_iter=1000, multi_class='multinomial',
                        solver='saga', n_jobs=-1)
lr.fit(X_train_s, y_train)
joblib.dump(lr, MODELS_DIR + "logistic_regression.pkl")
print("  LR saved.")

# ── 4. KNN ────────────────────────────────────────────────────────────────────
print("Training KNN...")
knn = KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
knn.fit(X_train_s, y_train)
joblib.dump(knn, MODELS_DIR + "knn.pkl")
print("  KNN saved.")

# ── 5. SVM ────────────────────────────────────────────────────────────────────
print("Training SVM (CalibratedLinearSVC)...")
svm = CalibratedClassifierCV(LinearSVC(random_state=RANDOM_STATE, max_iter=5000))
svm.fit(X_train_s, y_train)
joblib.dump(svm, MODELS_DIR + "svm.pkl")
print("  SVM saved.")

# ── 6. Isolation Forest (unsupervised — train on 'classical' only) ────────────
print("Training Isolation Forest...")
normal_mask = y_raw == 'classical'
X_normal = X[normal_mask]
iso = IsolationForest(n_estimators=200, contamination='auto',
                      random_state=RANDOM_STATE)
iso.fit(scaler.transform(X_normal))
joblib.dump(iso, MODELS_DIR + "isolation_forest.pkl")
print("  IsoForest saved.")

# ── 7. Autoencoder (train on 'classical' only) ────────────────────────────────
print("Training Autoencoder...")
X_normal_s = scaler.transform(X_normal)
Xn_tr, Xn_val_ae = train_test_split(X_normal_s, test_size=0.15, random_state=RANDOM_STATE)
input_dim = X_normal_s.shape[1]
ae = km.Sequential([
    layers.Input(shape=(input_dim,)),
    layers.Dense(max(8, input_dim // 2), activation='relu'),
    layers.Dense(max(4, input_dim // 4), activation='relu'),
    layers.Dense(max(8, input_dim // 2), activation='relu'),
    layers.Dense(input_dim, activation='linear')
])
ae.compile(optimizer='adam', loss='mse')
ae.fit(Xn_tr, Xn_tr, epochs=30, batch_size=128,
       validation_data=(Xn_val_ae, Xn_val_ae), verbose=1)
# Compute and save reconstruction-error threshold
recon_val = ae.predict(Xn_val_ae)
mse_val   = np.mean(np.square(recon_val - Xn_val_ae), axis=1)
ae_threshold = float(mse_val.mean() + 3 * mse_val.std())
ae.save(MODELS_DIR + "autoencoder.h5")
joblib.dump({'threshold': ae_threshold}, MODELS_DIR + "autoencoder_meta.pkl")
print(f"  Autoencoder saved. Threshold={ae_threshold:.6f}")

print("\nAll models saved to", MODELS_DIR)