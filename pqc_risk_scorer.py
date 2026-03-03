# pqc_risk_scorer.py
from pqc_extractor import CryptoFingerprint

def compute_qrs(fp: CryptoFingerprint) -> dict:
    """
    Compute a Quantum Risk Score (QRS) 0-100 for a TLS session.
    Returns dict with 'qrs' (int), 'label' (str), 'recommended_action' (str).
    """
    score = 50  # baseline

    # TLS version
    if fp.tls_version == '1.3':
        score -= 15
    elif fp.tls_version == '1.2':
        score += 10
    else:
        score += 20  # unknown / old

    # Cipher category
    if fp.cipher_category == 'PQC_SAFE':
        score -= 30
    elif fp.cipher_category == 'HYBRID':
        score -= 15
    elif fp.cipher_category == 'CLASSICAL_STRONG':
        score += 5
    elif fp.cipher_category == 'CLASSICAL_WEAK':
        score += 30

    # Key exchange
    if fp.key_exchange == 'ML-KEM':
        score -= 20
    elif fp.key_exchange == 'RSA':
        score += 20
    elif fp.key_exchange == 'DHE':
        score += 15

    # PQC extension present
    if fp.has_pqc_extension:
        score -= 10

    # Certificate key size
    if fp.cert_key_bits > 0:
        if fp.cert_key_bits < 1024:
            score += 25   # critically weak
        elif fp.cert_key_bits < 2048:
            score += 15
        elif fp.cert_key_bits >= 4096:
            score -= 5

    qrs = max(0, min(100, score))

    if qrs <= 20:
        label  = 'PQC-Safe'
        action = 'No action required. Session uses post-quantum cryptography.'
    elif qrs <= 40:
        label  = 'Hybrid'
        action = 'Monitor. Session uses hybrid PQC+classical. Plan full PQC migration.'
    elif qrs <= 70:
        label  = 'Legacy-Risk'
        action = ('Alert: Session uses classical-only crypto. '
                  'Upgrade to TLS 1.3 with ML-KEM key exchange.')
    else:
        label  = 'Critical-Legacy'
        action = ('CRITICAL: Weak or obsolete crypto detected. '
                  'Immediate remediation required. Disable RSA < 2048-bit. '
                  'Deploy FIPS 203 (ML-KEM) as key encapsulation mechanism.')

    return {'qrs': qrs, 'label': label, 'recommended_action': action}