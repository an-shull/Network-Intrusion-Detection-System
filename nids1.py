# nids1.py  — PQC-Aware NIDS (modified from original)
import sqlite3, time, smtplib, threading, os, json
import numpy as np
from email.mime.text import MIMEText
from flask import Flask, jsonify, request
from flask_cors import CORS
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from collections import deque
import psutil

from pqc_extractor import fingerprint_from_flow, CryptoFingerprint
from pqc_risk_scorer import compute_qrs
from ensemble import TwoStageEnsemble

app = Flask(__name__)
CORS(app)

# ── Globals ───────────────────────────────────────────────────────────────────
ensemble = None          # loaded once in main()
tls_flow_buffer = {}     # partial TLS flow assembly keyed by (src_ip, dst_ip, sport, dport)

# ── Database ──────────────────────────────────────────────────────────────────
def connect_db():
    try:
        return sqlite3.connect('nids_signatures.db', check_same_thread=False)
    except sqlite3.Error as e:
        print(f"[DB] Connection error: {e}")
        return None

def preload_signatures(conn):
    if not conn:
        return {}
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT source_ip, destination_ip, protocol, port, "
                       "packet_length, payload_pattern, attack_name FROM AttackSignatures")
        sig_map = {}
        for row in cursor.fetchall():
            src, dst, proto, port, pkt_len, payload, name = row
            sig_map[(src, dst, proto, port, pkt_len, payload)] = name
        return sig_map
    except sqlite3.Error as e:
        print(f"[DB] Signature load error: {e}")
        return {}

def get_active_ips():
    ips = []
    for _, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:
                ips.append(addr.address)
    return ips

def load_user_config(conn):
    default = {'email_alert_enabled': False, 'alert_email': '',
                'packet_size_threshold': 1500, 'monitored_ips': []}
    if not conn:
        return default
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT email_alert_enabled, alert_email, "
                       "packet_size_threshold FROM Configurations LIMIT 1")
        row = cursor.fetchone()
        if row:
            return {'email_alert_enabled': row[0], 'alert_email': row[1],
                    'packet_size_threshold': row[2], 'monitored_ips': get_active_ips()}
        return default
    except:
        return default

def refresh_monitored_ips(user_config, interval=60):
    while True:
        user_config['monitored_ips'] = get_active_ips()
        time.sleep(interval)

# ── Logging ───────────────────────────────────────────────────────────────────
def log_anomaly(conn, anomaly_type, description, packet, packet_size,
                qrs=None, pqc_label=None, verdict_label=None, confidence=None):
    if not conn:
        return
    try:
        cursor = conn.cursor()
        src = packet[IP].src if packet.haslayer(IP) else None
        dst = packet[IP].dst if packet.haslayer(IP) else None
        proto = ('TCP' if packet.haslayer(TCP) else
                 'UDP' if packet.haslayer(UDP) else
                 'DNS' if packet.haslayer(DNS) else 'Unknown')
        cursor.execute(
            "INSERT INTO Anomalies "
            "(timestamp, anomaly_type, description, packet_size, source_ip, "
            "destination_ip, protocol, qrs, pqc_label, verdict_label, confidence) "
            "VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (anomaly_type, description, packet_size, src, dst, proto,
             qrs, pqc_label, verdict_label, confidence)
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"[DB] Log error: {e}")

def log_pqc_session(conn, fp: CryptoFingerprint, qrs_result: dict):
    if not conn:
        return
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO pqc_sessions "
            "(src_ip, dst_ip, tls_version, cipher_suite, kex_algo, "
            "cert_key_bits, qrs, label, has_pqc_extension) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (fp.src_ip, fp.dst_ip, fp.tls_version, fp.cipher_suite_hex,
             fp.key_exchange, fp.cert_key_bits,
             qrs_result['qrs'], qrs_result['label'],
             int(fp.has_pqc_extension))
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"[DB] PQC session log error: {e}")

# ── Signature check ───────────────────────────────────────────────────────────
def check_signature(packet, signature_map):
    if not signature_map:
        return None
    src = packet[IP].src if packet.haslayer(IP) else None
    dst = packet[IP].dst if packet.haslayer(IP) else None
    payload = str(packet[Raw].load) if packet.haslayer(Raw) else ""
    pkt_len = len(packet)
    proto, port = None, None
    if packet.haslayer(TCP):
        proto, port = "TCP", packet[TCP].dport
    elif packet.haslayer(UDP):
        proto, port = "UDP", packet[UDP].dport
    elif packet.haslayer(DNS):
        proto, port = "DNS", 53
    key = (src, dst, proto, port, pkt_len, payload)
    return signature_map.get(key)

# ── TLS flow assembler ────────────────────────────────────────────────────────
def try_extract_tls_flow(packet) -> dict:
    """
    Very lightweight TLS flow metadata extractor from Scapy packets.
    Returns a partial flow dict; PQC extractor will fill the rest.
    For a production system, use pyshark for full handshake parsing.
    """
    if not packet.haslayer(TCP):
        return {}
    src = packet[IP].src if packet.haslayer(IP) else ''
    dst = packet[IP].dst if packet.haslayer(IP) else ''
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    pkt_len = len(packet)

    flow = {
        'src_ip': src,
        'dst_ip': dst,
        'clienthello_len':    pkt_len if dport == 443 else 0,
        'serverhello_len':    pkt_len if sport == 443 else 0,
        'certificate_len':    0,
        'key_share_lengths':  '',
        'record_lengths':     str(pkt_len),
        'packet_interarrival_ms': 0,
        'cipher_suites':      '',
        'extensions_order':   '',
        'client_ja3':         '',
        'server_ja3s':        '',
        'tls_version':        '1.3' if dport == 443 else 'unknown',
        'cipher_suite':       0x1302,   # default: assume TLS_AES_256_GCM
        'cert_key_bits':      0,
        'key_share_groups':   [],
    }
    return flow

# ── Core packet processor ─────────────────────────────────────────────────────
def process_packet(packet, signature_map, packet_sizes, user_config, ensemble):
    conn = connect_db()
    if not packet.haslayer(IP):
        return
    src = packet[IP].src
    dst = packet[IP].dst
    if src not in user_config['monitored_ips'] and dst not in user_config['monitored_ips']:
        return

    pkt_size = len(packet)
    packet_sizes.append(pkt_size)

    # ── Signature check ───────────────────────────────────────────────────────
    sig_hit = check_signature(packet, signature_map)
    if sig_hit:
        print(f"[SIG] {sig_hit}")
        if user_config['email_alert_enabled']:
            send_email_alert("NIDS Signature Alert", sig_hit, user_config['alert_email'])
        log_anomaly(conn, "Signature", sig_hit, packet, pkt_size)

    # ── PQC + ML pipeline (TLS packets only) ─────────────────────────────────
    if packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
        flow = try_extract_tls_flow(packet)

        # PQC fingerprint + risk score
        fp         = fingerprint_from_flow(flow)
        qrs_result = compute_qrs(fp)
        log_pqc_session(conn, fp, qrs_result)

        if qrs_result['qrs'] >= 41:
            print(f"[PQC] {qrs_result['label']} (QRS={qrs_result['qrs']}) "
                  f"{src} → {dst}")

        # ML ensemble
        if ensemble:
            try:
                verdict = ensemble.predict(flow)
                if verdict.is_anomaly:
                    desc = (f"ML Verdict: {verdict.label} "
                            f"(conf={verdict.confidence:.2f}, "
                            f"QRS={qrs_result['qrs']}, {qrs_result['label']})")
                    print(f"[ML] {desc}")
                    log_anomaly(conn, "ML+PQC", desc, packet, pkt_size,
                                qrs=qrs_result['qrs'],
                                pqc_label=qrs_result['label'],
                                verdict_label=verdict.label,
                                confidence=verdict.confidence)
            except Exception as e:
                print(f"[ML] Ensemble error: {e}")

    # ── Size-based anomaly (existing logic preserved) ─────────────────────────
    elif pkt_size > user_config['packet_size_threshold']:
        log_anomaly(conn, "Packet Size",
                    f"Large packet: {pkt_size} bytes", packet, pkt_size)

# ── Email alert ───────────────────────────────────────────────────────────────
def send_email_alert(subject, message, recipient_email):
    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From']    = 'nids@example.com'
        msg['To']      = recipient_email
        with smtplib.SMTP('smtp.example.com', 587) as server:
            server.starttls()
            server.login('your_email@example.com', 'password')
            server.sendmail('nids@example.com', [recipient_email], msg.as_string())
    except Exception as e:
        print(f"[SMTP] {e}")

# ── Packet capture loop ───────────────────────────────────────────────────────
def capture_packets(signature_map, user_config, ensemble):
    packet_sizes = deque(maxlen=100)
    print("[NIDS] Packet capture started.")
    while True:
        pkt = sniff(count=1)[0]
        threading.Thread(
            target=process_packet,
            args=(pkt, signature_map, packet_sizes, user_config, ensemble),
            daemon=True
        ).start()

# ── Flask API (existing routes preserved + new PQC routes) ───────────────────
@app.route('/logs', methods=['GET'])
def get_logs():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, anomaly_type, description, packet_size, "
                   "source_ip, destination_ip, protocol, qrs, pqc_label, "
                   "verdict_label, confidence FROM Anomalies ORDER BY timestamp DESC LIMIT 500")
    cols = ['timestamp','anomaly_type','description','packet_size',
            'source_ip','destination_ip','protocol','qrs','pqc_label',
            'verdict_label','confidence']
    return jsonify([dict(zip(cols, row)) for row in cursor.fetchall()])

@app.route('/update-config', methods=['POST'])
def update_config():
    data = request.json
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE Configurations SET email_alert_enabled=?, "
                   "alert_email=?, packet_size_threshold=?",
                   (data['email_alert_enabled'], data['alert_email'],
                    data['packet_size_threshold']))
    conn.commit()
    return jsonify({"message": "Configuration updated"})

@app.route('/api/pqc/summary', methods=['GET'])
def pqc_summary():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT label, COUNT(*) FROM pqc_sessions GROUP BY label")
    distribution = {row[0]: row[1] for row in cursor.fetchall()}
    cursor.execute("SELECT AVG(qrs) FROM pqc_sessions")
    avg_qrs = cursor.fetchone()[0] or 0
    total = sum(distribution.values())
    pqc_safe_pct = round(100 * distribution.get('PQC-Safe', 0) / max(total, 1), 1)
    return jsonify({
        'distribution': distribution,
        'avg_qrs': round(avg_qrs, 1),
        'total_sessions': total,
        'pqc_safe_pct': pqc_safe_pct,
        'readiness_score': round(100 - avg_qrs, 1)
    })

@app.route('/api/pqc/sessions', methods=['GET'])
def pqc_sessions():
    conn = connect_db()
    cursor = conn.cursor()
    limit  = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    cursor.execute(
        "SELECT id, src_ip, dst_ip, tls_version, cipher_suite, kex_algo, "
        "cert_key_bits, qrs, label, has_pqc_extension, ts "
        "FROM pqc_sessions ORDER BY ts DESC LIMIT ? OFFSET ?",
        (limit, offset)
    )
    cols = ['id','src_ip','dst_ip','tls_version','cipher_suite','kex_algo',
            'cert_key_bits','qrs','label','has_pqc_extension','ts']
    return jsonify([dict(zip(cols, row)) for row in cursor.fetchall()])

@app.route('/api/pqc/alerts', methods=['GET'])
def pqc_alerts():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT s.id, s.src_ip, s.dst_ip, s.qrs, s.label, s.ts, s.kex_algo "
        "FROM pqc_sessions s "
        "WHERE s.qrs >= 41 ORDER BY s.qrs DESC, s.ts DESC LIMIT 50"
    )
    cols = ['id','src_ip','dst_ip','qrs','label','ts','kex_algo']
    return jsonify([dict(zip(cols, row)) for row in cursor.fetchall()])

@app.route('/api/pqc/readiness', methods=['GET'])
def pqc_readiness():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT AVG(qrs) FROM pqc_sessions")
    avg_qrs = cursor.fetchone()[0] or 50
    return jsonify({'readiness_score': round(100 - avg_qrs, 1), 'avg_qrs': round(avg_qrs, 1)})

@app.route('/api/pqc/cipher-breakdown', methods=['GET'])
def cipher_breakdown():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT label, COUNT(*) FROM pqc_sessions GROUP BY label")
    return jsonify({row[0]: row[1] for row in cursor.fetchall()})

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    global ensemble
    conn           = connect_db()
    signature_map  = preload_signatures(conn)
    user_config    = load_user_config(conn)

    threading.Thread(target=refresh_monitored_ips,
                     args=(user_config,), daemon=True).start()

    print("[NIDS] Loading ML ensemble...")
    try:
        ensemble = TwoStageEnsemble()
        print("[NIDS] Ensemble ready.")
    except Exception as e:
        print(f"[NIDS] Ensemble load failed (running without ML): {e}")
        ensemble = None

    threading.Thread(target=capture_packets,
                     args=(signature_map, user_config, ensemble),
                     daemon=True).start()

if __name__ == '__main__':
    threading.Thread(target=main, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)