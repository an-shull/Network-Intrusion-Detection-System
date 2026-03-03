# pqc_extractor.py
# Extracts crypto fingerprint from a live TLS flow assembled by nids1.py
from dataclasses import dataclass, field
from typing import List, Optional

# IANA TLS cipher suite IDs mapped to PQC safety category
# Values: 'PQC_SAFE', 'HYBRID', 'CLASSICAL_STRONG', 'CLASSICAL_WEAK'
CIPHER_MAP = {
    # PQC / Hybrid (IETF draft values)
    0xFE30: 'PQC_SAFE',    # TLS_KYBER_512
    0xFE31: 'PQC_SAFE',    # TLS_KYBER_768
    0xFE32: 'PQC_SAFE',    # TLS_KYBER_1024
    # TLS 1.3 strong (ECDHE-based — classical strong)
    0x1301: 'CLASSICAL_STRONG',  # TLS_AES_128_GCM_SHA256
    0x1302: 'CLASSICAL_STRONG',  # TLS_AES_256_GCM_SHA384
    0x1303: 'CLASSICAL_STRONG',  # TLS_CHACHA20_POLY1305_SHA256
    # TLS 1.2 ECDHE strong
    0xC02B: 'CLASSICAL_STRONG',  # ECDHE-ECDSA-AES128-GCM-SHA256
    0xC02C: 'CLASSICAL_STRONG',  # ECDHE-ECDSA-AES256-GCM-SHA384
    0xC02F: 'CLASSICAL_STRONG',  # ECDHE-RSA-AES128-GCM-SHA256
    0xC030: 'CLASSICAL_STRONG',  # ECDHE-RSA-AES256-GCM-SHA384
    # RSA key exchange (quantum-vulnerable)
    0x002F: 'CLASSICAL_WEAK',    # RSA-AES128-SHA
    0x0035: 'CLASSICAL_WEAK',    # RSA-AES256-SHA
    0x003C: 'CLASSICAL_WEAK',    # RSA-AES128-SHA256
    0x003D: 'CLASSICAL_WEAK',    # RSA-AES256-SHA256
    # Export / legacy (critically weak)
    0x0003: 'CLASSICAL_WEAK',    # RSA_EXPORT_RC4_40_MD5
    0x0004: 'CLASSICAL_WEAK',    # RSA_RC4_128_MD5
    0x0005: 'CLASSICAL_WEAK',    # RSA_RC4_128_SHA
}

# TLS extension type numbers
EXT_KEY_SHARE        = 51
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGS   = 13

# Named groups — PQC ones
PQC_GROUPS = {0x6399, 0x639A, 0x639B}  # Kyber512, Kyber768, Kyber1024 (draft values)

@dataclass
class CryptoFingerprint:
    src_ip: str = ''
    dst_ip: str = ''
    tls_version: str = 'unknown'         # '1.2', '1.3', 'unknown'
    cipher_suite_hex: str = ''           # e.g. '0x1302'
    cipher_category: str = 'UNKNOWN'     # PQC_SAFE / HYBRID / CLASSICAL_STRONG / CLASSICAL_WEAK
    key_exchange: str = 'unknown'        # 'RSA', 'ECDH', 'DHE', 'ML-KEM', 'unknown'
    cert_key_bits: int = 0               # certificate public key size in bits
    has_pqc_extension: bool = False      # True if key_share includes a PQC group
    ja3: str = ''
    ja3s: str = ''
    raw_cipher_suites: List[int] = field(default_factory=list)
    raw_extensions: List[int] = field(default_factory=list)

def fingerprint_from_flow(flow: dict) -> CryptoFingerprint:
    """
    Build a CryptoFingerprint from a TLS flow dict assembled by the packet capture layer.
    
    Expected flow keys (all optional):
        src_ip, dst_ip, tls_version, cipher_suite (int or hex str),
        cipher_suites (comma-sep list), extensions_order (comma-sep list),
        key_share_groups (list of ints), cert_key_bits (int),
        client_ja3, server_ja3s
    """
    fp = CryptoFingerprint()
    fp.src_ip = flow.get('src_ip', '')
    fp.dst_ip = flow.get('dst_ip', '')
    fp.ja3    = flow.get('client_ja3', '')
    fp.ja3s   = flow.get('server_ja3s', '')

    # TLS version
    ver = flow.get('tls_version', '')
    if '1.3' in str(ver):
        fp.tls_version = '1.3'
    elif '1.2' in str(ver):
        fp.tls_version = '1.2'
    else:
        fp.tls_version = str(ver) or 'unknown'

    # Cipher suite
    raw_cs = flow.get('cipher_suite', None)
    if raw_cs is not None:
        try:
            cs_int = int(str(raw_cs), 16) if isinstance(raw_cs, str) and raw_cs.startswith('0x') \
                     else int(raw_cs)
            fp.cipher_suite_hex = hex(cs_int)
            fp.cipher_category  = CIPHER_MAP.get(cs_int, 'CLASSICAL_WEAK')
        except:
            fp.cipher_category = 'UNKNOWN'

    # All cipher suites offered
    cs_raw = flow.get('cipher_suites', '')
    if cs_raw:
        try:
            fp.raw_cipher_suites = [int(x.strip()) for x in str(cs_raw).split(',') if x.strip()]
        except:
            pass

    # Extensions
    ext_raw = flow.get('extensions_order', '')
    if ext_raw:
        try:
            fp.raw_extensions = [int(x.strip()) for x in str(ext_raw).split(',') if x.strip()]
        except:
            pass

    # PQC key share detection
    ks_groups = flow.get('key_share_groups', [])
    if any(g in PQC_GROUPS for g in ks_groups):
        fp.has_pqc_extension = True
        fp.key_exchange = 'ML-KEM'
    elif EXT_KEY_SHARE in fp.raw_extensions:
        # Key share present but no PQC group → classical ECDH
        fp.key_exchange = 'ECDH'
    elif 'RSA' in fp.cipher_suite_hex.upper() or fp.cipher_category == 'CLASSICAL_WEAK':
        fp.key_exchange = 'RSA'
    else:
        fp.key_exchange = 'ECDH'  # default for TLS 1.3

    # Certificate key size
    fp.cert_key_bits = int(flow.get('cert_key_bits', 0))

    return fp