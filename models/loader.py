# models/loader.py
import os
import joblib
import numpy as np
import tensorflow as tf

MODELS_DIR = os.path.join(os.path.dirname(__file__))

_cache = {}

def load_all():
    """Load all model artefacts once and cache them."""
    if _cache:
        return _cache
    print("[loader] Loading all models...")
    _cache['rf']          = joblib.load(f"{MODELS_DIR}/random_forest.pkl")
    _cache['xgb']         = joblib.load(f"{MODELS_DIR}/xgboost.pkl")
    _cache['lr']          = joblib.load(f"{MODELS_DIR}/logistic_regression.pkl")
    _cache['knn']         = joblib.load(f"{MODELS_DIR}/knn.pkl")
    _cache['svm']         = joblib.load(f"{MODELS_DIR}/svm.pkl")
    _cache['iso']         = joblib.load(f"{MODELS_DIR}/isolation_forest.pkl")
    _cache['ae']          = tf.keras.models.load_model(f"{MODELS_DIR}/autoencoder.h5")
    _cache['ae_meta']     = joblib.load(f"{MODELS_DIR}/autoencoder_meta.pkl")
    _cache['scaler']      = joblib.load(f"{MODELS_DIR}/scaler.pkl")
    _cache['label_enc']   = joblib.load(f"{MODELS_DIR}/label_encoder.pkl")
    _cache['ja3_encoders']= joblib.load(f"{MODELS_DIR}/ja3_encoders.pkl")
    print("[loader] All models loaded.")
    return _cache