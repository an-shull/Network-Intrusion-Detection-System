# ensemble.py
import numpy as np
from dataclasses import dataclass, field
from typing import Optional
from models.loader import load_all
from preprocessing import flow_to_vector

# Weights for Stage-2 soft-voting (must sum to 1.0)
ENSEMBLE_WEIGHTS = {
    'rf':  0.30,
    'xgb': 0.30,
    'ae':  0.20,
    'knn': 0.10,
    'svm': 0.10,
}

@dataclass
class ThreatVerdict:
    label: str              # e.g. 'classical', 'pqc', 'attack'
    confidence: float       # 0.0 – 1.0
    is_anomaly: bool        # True if either Stage-1 model flagged it
    stage1_iso: bool        # Isolation Forest flag
    stage1_lr:  bool        # Logistic Regression flag
    all_probs: dict = field(default_factory=dict)  # per-model probabilities

class TwoStageEnsemble:
    def __init__(self):
        self._models = load_all()

    def predict(self, flow: dict) -> ThreatVerdict:
        """Score a single TLS flow dict and return a ThreatVerdict."""
        m        = self._models
        scaler   = m['scaler']
        label_enc= m['label_enc']
        ja3_enc  = m['ja3_encoders']

        vec     = flow_to_vector(flow, ja3_encoders=ja3_enc)
        vec_s   = scaler.transform([vec])    # scaled for LR/KNN/SVM/ISO/AE
        vec_u   = [vec]                       # unscaled for RF/XGB

        # ── Stage 1: fast pre-filters ─────────────────────────────────────────
        iso_pred  = m['iso'].predict(vec_s)[0]      # -1 = anomaly
        lr_probs  = m['lr'].predict_proba(vec_s)[0]
        lr_pred   = int(np.argmax(lr_probs))
        lr_label  = label_enc.inverse_transform([lr_pred])[0]

        stage1_iso = (iso_pred == -1)
        stage1_lr  = (lr_label != 'classical')

        # If both Stage-1 models say normal → fast exit
        if not stage1_iso and not stage1_lr:
            return ThreatVerdict(
                label='classical', confidence=float(lr_probs.max()),
                is_anomaly=False, stage1_iso=False, stage1_lr=False,
                all_probs={'lr': lr_probs.tolist()}
            )

        # ── Stage 2: full ensemble ─────────────────────────────────────────────
        rf_probs  = m['rf'].predict_proba(vec_u)[0]
        xgb_probs = m['xgb'].predict_proba(vec_u)[0]
        knn_probs = m['knn'].predict_proba(vec_s)[0]
        svm_probs = m['svm'].predict_proba(vec_s)[0]

        # Autoencoder: reconstruction error → binary anomaly probability
        recon = m['ae'].predict(vec_s, verbose=0)
        mse   = float(np.mean(np.square(recon - vec_s)))
        thresh= m['ae_meta']['threshold']
        # Map MSE to a 2-class probability vector [p_normal, p_anomaly]
        ae_anomaly_prob = min(1.0, mse / (thresh * 2))
        n_classes = len(label_enc.classes_)
        classical_idx = list(label_enc.classes_).index('classical') if 'classical' in label_enc.classes_ else 0
        ae_probs = np.full(n_classes, ae_anomaly_prob / max(n_classes - 1, 1))
        ae_probs[classical_idx] = 1.0 - ae_anomaly_prob

        # Weighted soft vote
        combined = (
            ENSEMBLE_WEIGHTS['rf']  * rf_probs  +
            ENSEMBLE_WEIGHTS['xgb'] * xgb_probs +
            ENSEMBLE_WEIGHTS['ae']  * ae_probs  +
            ENSEMBLE_WEIGHTS['knn'] * knn_probs +
            ENSEMBLE_WEIGHTS['svm'] * svm_probs
        )
        pred_idx   = int(np.argmax(combined))
        pred_label = label_enc.inverse_transform([pred_idx])[0]
        confidence = float(combined[pred_idx])

        return ThreatVerdict(
            label=pred_label,
            confidence=confidence,
            is_anomaly=(pred_label != 'classical'),
            stage1_iso=stage1_iso,
            stage1_lr=stage1_lr,
            all_probs={
                'rf': rf_probs.tolist(), 'xgb': xgb_probs.tolist(),
                'knn': knn_probs.tolist(), 'svm': svm_probs.tolist(),
                'ae_mse': mse, 'ae_threshold': thresh
            }
        )