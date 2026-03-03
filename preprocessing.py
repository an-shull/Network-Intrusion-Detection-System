# preprocessing.py
# Shared feature engineering used identically during training AND inference
import re
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

FEATURES = [
    'clienthello_len', 'serverhello_len', 'certificate_len',
    'ks_len_sum', 'record_len_mean', 'packet_interarrival_ms',
    'cipher_count', 'ext_count', 'client_ja3', 'server_ja3s'
]

def parse_int_sum(s):
    try:
        nums = re.findall(r"\d+", str(s))
        return sum(int(x) for x in nums) if nums else 0
    except:
        return 0

def parse_record_mean(s):
    try:
        nums = re.findall(r"\d+", str(s))
        nums = [int(x) for x in nums]
        return float(np.mean(nums)) if nums else 0.0
    except:
        return 0.0

def engineer_features(df, ja3_encoders=None, fit_encoders=False):
    df = df.copy()
    df['ks_len_sum']      = df['key_share_lengths'].apply(parse_int_sum)
    df['record_len_mean'] = df['record_lengths'].apply(parse_record_mean)
    df['cipher_count']    = df['cipher_suites'].fillna('').apply(
                                lambda x: 0 if x == '' else len(str(x).split(',')))
    df['ext_count']       = df['extensions_order'].fillna('').apply(
                                lambda x: 0 if x == '' else len(str(x).split(',')))
    encoders = {}
    for col in ['client_ja3', 'server_ja3s']:
        df[col] = df[col].astype(str)
        if fit_encoders:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            encoders[col] = le
        elif ja3_encoders and col in ja3_encoders:
            le = ja3_encoders[col]
            known = set(le.classes_)
            df[col] = df[col].apply(lambda v: v if v in known else le.classes_[0])
            df[col] = le.transform(df[col])
        else:
            df[col] = df[col].apply(lambda v: abs(hash(v)) % 100000)
    for c in FEATURES:
        df[c] = pd.to_numeric(df[c], errors='coerce')
        median_val = df[c].median()
        df[c] = df[c].fillna(median_val if not np.isnan(median_val) else 0.0)
    return df[FEATURES], encoders

def flow_to_vector(flow: dict, ja3_encoders=None):
    row = {
        'clienthello_len':        flow.get('clienthello_len', 0),
        'serverhello_len':        flow.get('serverhello_len', 0),
        'certificate_len':        flow.get('certificate_len', 0),
        'key_share_lengths':      flow.get('key_share_lengths', ''),
        'record_lengths':         flow.get('record_lengths', ''),
        'packet_interarrival_ms': flow.get('packet_interarrival_ms', 0),
        'cipher_suites':          flow.get('cipher_suites', ''),
        'extensions_order':       flow.get('extensions_order', ''),
        'client_ja3':             flow.get('client_ja3', ''),
        'server_ja3s':            flow.get('server_ja3s', ''),
    }
    df = pd.DataFrame([row])
    X, _ = engineer_features(df, ja3_encoders=ja3_encoders, fit_encoders=False)
    return X.values[0]