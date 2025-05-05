import os
import json
import logging
import datetime
import random
import base64
import joblib
import hashlib
import numpy as np
import pandas as pd
import jwt
import bcrypt
from scapy.all import sniff, IP, TCP, UDP
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from pymongo import MongoClient
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from functools import wraps
import time
from threading import Thread
from flask_cors import CORS
from datetime import timezone
import pytz
import psutil
from collections import defaultdict

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_default_secret_key'

# Enable CORS for frontend-backend communication
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="http://localhost:5173")

# Load secret key for JWT
SECRET_KEY = os.getenv('SECRET_KEY', 'your_default_secret_key')

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")
db = client['ids_database']
users_collection = db['users']

# Paths to required files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BINARY_MODEL_PATH = os.path.join(BASE_DIR, 'binary_model.pkl')
MULTI_MODEL_PATH = os.path.join(BASE_DIR, 'multi_model.pkl')
LABEL_ENCODER_PATH = os.path.join(BASE_DIR, 'label_encoder.pkl')
LABEL_ENCODER_NON_NORMAL_PATH = os.path.join(BASE_DIR, 'label_encoder_non_normal.pkl')
SCALER_PATH = os.path.join(BASE_DIR, 'datasets', 'scaler.pkl')
FEATURE_NAMES_PATH = os.path.join(BASE_DIR, 'feature_names.pkl')
OPTIMAL_THRESHOLD_PATH = os.path.join(BASE_DIR, 'optimal_threshold.pkl')
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, 'private.key')
CAT_ENCODERS_PATH = os.path.join(BASE_DIR, 'datasets', 'cat_encoders.pkl')

# Load model components
binary_model = joblib.load(BINARY_MODEL_PATH)
multi_model = joblib.load(MULTI_MODEL_PATH)
label_encoder = joblib.load(LABEL_ENCODER_PATH)
label_encoder_non_normal = joblib.load(LABEL_ENCODER_NON_NORMAL_PATH)
scaler = joblib.load(SCALER_PATH)
feature_names = joblib.load(FEATURE_NAMES_PATH)
optimal_threshold = joblib.load(OPTIMAL_THRESHOLD_PATH)
cat_encoders = joblib.load(CAT_ENCODERS_PATH)

# Debug: Print valid service labels and label encoder classes
print("Valid service labels:", cat_encoders['service'].classes_)
print("Label encoder classes:", label_encoder.classes_)

# Define the static label_to_name mapping
label_to_name = {
    0: 'apache2', 1: 'back', 2: 'buffer_overflow', 3: 'ftp_write', 4: 'guess_passwd',
    5: 'httptunnel', 6: 'imap', 7: 'ipsweep', 8: 'land', 9: 'loadmodule',
    10: 'mailbomb', 11: 'mscan', 12: 'multihop', 13: 'neptune', 14: 'nmap',
    15: 'normal', 16: 'perl', 17: 'phf', 18: 'pod', 19: 'portsweep',
    20: 'processtable', 21: 'rootkit', 22: 'saint', 23: 'satan', 24: 'smurf',
    25: 'snmpgetattack', 26: 'snmpguess', 27: 'spy', 28: 'teardrop',
    29: 'warezclient', 30: 'warezmaster', 31: 'worm', 32: 'rare'
}

# Log the label_to_name mapping for verification
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG to see detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(BASE_DIR, 'app.log'))
    ]
)
logging.info(f"label_to_name mapping initialized: {label_to_name}")

# Global flow tracking
flows = defaultdict(lambda: {
    'packets': [], 'start_time': None, 'src_bytes': 0, 'dst_bytes': 0, 'count': 0,
    'serror_count': 0, 'rerror_count': 0, 'last_time': None, 'service': 0,
    'dst_host_count': defaultdict(int), 'dst_host_srv_count': defaultdict(int),
    'same_srv_count': 0, 'diff_srv_count': 0, 'same_src_port_count': 0, 'srv_diff_host_count': 0
})
FLOW_TIMEOUT = 10  # Seconds to consider a flow active

# Flow update function
def update_flow(packet):
    """Update flow statistics with a new packet."""
    if IP not in packet:
        return None
    flow_key = (packet[IP].src, packet[IP].dst, packet[IP].proto)
    flow = flows[flow_key]
    
    current_time = time.time()
    if flow['start_time'] is None:
        flow['start_time'] = current_time
    
    flow['packets'].append(packet)
    flow['count'] += 1
    flow['src_bytes'] += len(packet[IP])
    flow['dst_bytes'] += len(packet) - len(packet[IP]) if len(packet) > len(packet[IP]) else 0
    flow['last_time'] = current_time
    
    if TCP in packet:
        if packet[TCP].flags & 0x02:  # SYN flag
            flow['serror_count'] += 1
        if packet[TCP].flags & 0x04:  # RST flag
            flow['rerror_count'] += 1
    
    if IP in packet:
        flow['dst_host_count'][packet[IP].dst] += 1
        flow['dst_host_srv_count'][flow['service']] += 1
        
        if TCP in packet or UDP in packet:
            port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            flow['service'] = port
            for p in flow['packets']:
                p_port = p[TCP].dport if TCP in p else p[UDP].dport if UDP in p else None
                if p_port == port:
                    flow['same_srv_count'] += 1
                else:
                    flow['diff_srv_count'] += 1
                if p[IP].src == packet[IP].src and (p[TCP].sport if TCP in p else p[UDP].sport if UDP in p else 0) == (packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0):
                    flow['same_src_port_count'] += 1
                if p[IP].dst != packet[IP].dst:
                    flow['srv_diff_host_count'] += 1
    
    if current_time - flow['start_time'] > FLOW_TIMEOUT:
        del flows[flow_key]
    
    return flow_key

# Feature extraction function
def extract_features(flow_key, flow_data):
    features = {
        'duration': 0, 'protocol_type': 0, 'service': 0, 'flag': 0, 'src_bytes': 0, 'dst_bytes': 0, 'land': 0,
        'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
        'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 0,
        'srv_count': 0, 'serror_rate': 0, 'srv_serror_rate': 0, 'rerror_rate': 0, 'srv_rerror_rate': 0,
        'same_srv_rate': 0, 'diff_srv_rate': 0, 'srv_diff_host_rate': 0, 'dst_host_count': 0, 'dst_host_srv_count': 0,
        'dst_host_same_srv_rate': 0, 'dst_host_diff_srv_rate': 0, 'dst_host_same_src_port_rate': 0,
        'dst_host_srv_diff_host_rate': 0, 'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 0,
        'dst_host_rerror_rate': 0, 'dst_host_srv_rerror_rate': 0
    }

    packets = flow_data['packets']
    if not packets or len(packets) == 0:
        return pd.DataFrame([features])

    latest_packet = packets[-1]
    if IP in latest_packet:
        proto_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
        proto_str = proto_map.get(latest_packet[IP].proto, 'tcp')
        features['protocol_type'] = cat_encoders['protocol_type'].transform([proto_str])[0]
        features['src_bytes'] = flow_data['src_bytes']
        features['dst_bytes'] = flow_data['dst_bytes']
        features['land'] = 1 if latest_packet[IP].src == latest_packet[IP].dst else 0

    features['duration'] = flow_data['last_time'] - flow_data['start_time'] if flow_data['last_time'] else 0
    features['count'] = flow_data['count']

    port = flow_data['service']
    service_map = {
        80: 'http', 443: 'http_443', 21: 'ftp', 22: 'ssh', 23: 'telnet',
        25: 'smtp', 53: 'domain', 110: 'pop_3', 143: 'imap4', 445: 'netbios_ssn'
    }
    service_str = service_map.get(port, 'other')
    features['service'] = cat_encoders['service'].transform([service_str])[0]

    if TCP in latest_packet:
        tcp_flags = latest_packet[TCP].flags
        if tcp_flags & 0x02 and not (tcp_flags & 0x10):
            flag_str = 'S0'
        elif tcp_flags & 0x04:
            flag_str = 'RSTOS0'
        elif tcp_flags & 0x01:
            flag_str = 'SF'
        elif tcp_flags & 0x10 and not (tcp_flags & 0x02):
            flag_str = 'SF'
        else:
            flag_str = 'SF'
    else:
        flag_str = 'SF'
    features['flag'] = cat_encoders['flag'].transform([flag_str])[0]

    total_packets = features['count']
    features['srv_count'] = flow_data['same_srv_count']
    features['serror_rate'] = flow_data['serror_count'] / total_packets if total_packets > 0 else 0
    features['srv_serror_rate'] = features['serror_rate']
    features['rerror_rate'] = flow_data['rerror_count'] / total_packets if total_packets > 0 else 0
    features['srv_rerror_rate'] = features['rerror_rate']
    features['same_srv_rate'] = flow_data['same_srv_count'] / total_packets if total_packets > 0 else 0
    features['diff_srv_rate'] = flow_data['diff_srv_count'] / total_packets if total_packets > 0 else 0

    dst_ip = latest_packet[IP].dst if IP in latest_packet else None
    if dst_ip:
        features['dst_host_count'] = len(flow_data['dst_host_count'])
        features['dst_host_srv_count'] = flow_data['dst_host_srv_count'].get(features['service'], 0)
        features['dst_host_same_srv_rate'] = (features['dst_host_srv_count'] / features['dst_host_count']) if features['dst_host_count'] > 0 else 0
        features['dst_host_diff_srv_rate'] = 1 - features['dst_host_same_srv_rate']
        features['dst_host_same_src_port_rate'] = flow_data['same_src_port_count'] / total_packets if total_packets > 0 else 0
        features['dst_host_srv_diff_host_rate'] = flow_data['srv_diff_host_count'] / features['dst_host_srv_count'] if features['dst_host_srv_count'] > 0 else 0
        features['dst_host_serror_rate'] = features['serror_rate']
        features['dst_host_srv_serror_rate'] = features['serror_rate']
        features['dst_host_rerror_rate'] = features['rerror_rate']
        features['dst_host_srv_rerror_rate'] = features['rerror_rate']

    return pd.DataFrame([features])

# Global dictionary to track last alert time
last_alert_time = {}

# Real-time alert sending
def send_real_time_alert(alert_type, message, details=None):
    global last_alert_time
    throttle_interval = 5
    current_time = datetime.datetime.now()
    if alert_type not in last_alert_time or (current_time - last_alert_time[alert_type]).total_seconds() > throttle_interval:
        last_alert_time[alert_type] = current_time
        alert = {
            "timestamp": current_time.astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M:%S %p'),
            "type": alert_type,
            "message": message,
            "details": details
        }
        socketio.emit('real-time-alert', alert)
        logging.info(f"Real-time alert sent: {alert}")

def combined_predict(X, threshold):
    if not isinstance(X, pd.DataFrame):
        X = pd.DataFrame(X, columns=feature_names)
    
    binary_pred_prob = binary_model.predict_proba(X)[:, 1]  # Probability of non-normal
    logging.debug(f"Binary model probabilities: {binary_pred_prob}, Threshold: {threshold}")
    binary_pred = (binary_pred_prob >= threshold).astype(int)
    logging.debug(f"Binary prediction (0=normal, 1=non-normal): {binary_pred}")
    final_pred = np.zeros(len(X), dtype=int)
    
    normal_mask = (binary_pred == 0)
    final_pred[normal_mask] = 15
    
    non_normal_mask = (binary_pred == 1)
    if np.any(non_normal_mask):
        non_normal_pred = multi_model.predict(X[non_normal_mask])
        non_normal_pred_original = label_encoder_non_normal.inverse_transform(non_normal_pred)
        final_pred[non_normal_mask] = non_normal_pred_original
    
    logging.debug(f"Final prediction: {final_pred}")
    return final_pred

# Update predict_packet to log raw prediction for debugging
def predict_packet(packet):
    try:
        flow_key = update_flow(packet)
        if not flow_key:
            return
        
        flow_data = flows[flow_key]
        features = extract_features(flow_key, flow_data)
        features_scaled = scaler.transform(features)
        prediction = combined_predict(features_scaled, threshold=optimal_threshold)
        label_idx = prediction[0]
        label_name = label_to_name.get(label_idx, 'unknown')
        logging.debug(f"predict_packet - label_idx: {label_idx}, label_name: {label_name}")
        label_display = f"{label_idx}-{label_name}"

        packet_info = {
            "src_ip": packet[IP].src if IP in packet else "Unknown",
            "dst_ip": packet[IP].dst if IP in packet else "Unknown",
            "protocol": packet[IP].proto if IP in packet else "Unknown",  # Still numeric here
            "length": len(packet),
            "summary": packet.summary()
        }

        logging.info(f"Prediction for flow {flow_key}: {label_display}")
        emit_real_time_data(packet_info, label_display)

        if label_idx != 15:
            send_real_time_alert(
                alert_type="Intrusion Detected",
                message=f"Potential intrusion detected: {label_display}",
                details=packet_info
            )
    except Exception as e:
        logging.error(f"Error during prediction: {e}")

# Add protocol mapping near the top with other mappings
protocol_mapping = {
    0: "HOPOPT",      # IPv6 Hop-by-Hop Option
    1: "ICMP",        # Internet Control Message Protocol
    2: "IGMP",        # Internet Group Management Protocol
    4: "IP-in-IP",    # IP in IP (encapsulation)
    6: "TCP",         # Transmission Control Protocol
    17: "UDP",        # User Datagram Protocol
    41: "IPv6",       # IPv6 encapsulation
    43: "IPv6-Route", # Routing Header for IPv6
    44: "IPv6-Frag",  # Fragment Header for IPv6
    46: "RSVP",       # Resource Reservation Protocol
    47: "GRE",        # Generic Routing Encapsulation
    50: "ESP",        # Encapsulating Security Payload
    51: "AH",         # Authentication Header
    58: "IPv6-ICMP",  # ICMP for IPv6
    89: "OSPF",       # Open Shortest Path First
    103: "PIM",       # Protocol Independent Multicast
    108: "IPComp",    # IP Payload Compression Protocol
    112: "VRRP",      # Virtual Router Redundancy Protocol
    115: "L2TP",      # Layer Two Tunneling Protocol
    132: "SCTP",      # Stream Control Transmission Protocol
    136: "UDPLite",   # Lightweight User Datagram Protocol
    137: "MPLS-in-IP",# MPLS in IP
    255: "Reserved"
}

# Update emit_real_time_data to use protocol names
def emit_real_time_data(packet_info, label_display):
    ist_tz = pytz.timezone('Asia/Kolkata')
    current_time_utc = datetime.datetime.now(pytz.utc)
    current_time_ist = current_time_utc.astimezone(ist_tz).strftime('%Y-%m-%d %I:%M:%S %p')

    protocol_num = packet_info["protocol"]
    protocol_name = protocol_mapping.get(protocol_num, str(protocol_num))  # Fallback to number if unknown

    data = {
        "timestamp": current_time_ist,
        "src_ip": packet_info["src_ip"],
        "dst_ip": packet_info["dst_ip"],
        "protocol": protocol_name,  # Use readable name
        "length": packet_info["length"],
        "summary": packet_info["summary"],
        "prediction": label_display,
    }
    socketio.emit('real-time-data', data)
    logging.info(f"Emitted real-time-data: {data}")

# Packet capture function
def capture_packets(interface):
    logging.info(f"Starting packet capture on interface: {interface}")
    sniff(iface=interface, prn=predict_packet, store=False)

# Flask endpoint to start packet capture
@app.route('/start-packet-capture', methods=['POST'])
def start_packet_capture():
    interface = request.json.get('interface', 'eth0')
    thread = Thread(target=capture_packets, args=(interface,))
    thread.daemon = True
    thread.start()
    return jsonify({"message": f"Packet capture started on interface {interface}"}), 200

# Function to extract features and predict attack type
# Update emit_real_time_packet for consistency (if used)
def emit_real_time_packet(packet):
    flow_key = update_flow(packet)
    if not flow_key:
        return
    
    flow_data = flows[flow_key]
    features = extract_features(flow_key, flow_data)
    features_scaled = scaler.transform(features)
    
    try:
        prediction = combined_predict(features_scaled, threshold=optimal_threshold)
        label_idx = prediction[0]
        label_name = label_to_name.get(label_idx, 'unknown')
        logging.debug(f"emit_real_time_packet - label_idx: {label_idx}, label_name: {label_name}")
        label_display = f"{label_idx}-{label_name}"
    except Exception as e:
        label_display = "Prediction Error"
        logging.error(f"Prediction error: {e}")

    protocol_name = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"  # Already correct here

    packet_data = {
        "timestamp": datetime.datetime.now(pytz.utc).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M:%S %p'),
        "src_ip": packet[IP].src if IP in packet else "Unknown",
        "dst_ip": packet[IP].dst if IP in packet else "Unknown",
        "protocol": protocol_name,
        "length": len(packet),
        "prediction": label_display
    }
    socketio.emit('real-time-packet', packet_data)
    logging.info(f"Real-time packet with prediction sent: {packet_data}")

# WebSocket event for real-time alerts
@socketio.on('connect')
def handle_connect():
    logging.info("Client connected to WebSocket.")
    emit('server_message', {'message': 'Connected to server'})

# Function to anonymize sensitive data
def anonymize_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

# JWT functions
def generate_jwt(user_id, role):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    token = jwt.encode({'user_id': user_id, 'role': role, 'exp': expiration_time}, SECRET_KEY, algorithm='HS256')
    logging.info(f"JWT generated for user {anonymize_data(user_id)} with role {role}.")
    return token

def log_activity(user_id, action, details=""):
    timestamp = datetime.datetime.now(pytz.utc).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M:%S %p')
    activity_log = {
        "user_id": user_id,
        "action": action,
        "timestamp": timestamp,
        "details": details
    }
    db.activity_logs.insert_one(activity_log)
    logging.info(f"Activity logged for user {user_id}: {action} at {timestamp}")

# Function to monitor system performance
def monitor_system_performance():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    if cpu_usage > 85:
        send_real_time_alert(
            alert_type="System Performance Issue",
            message=f"High CPU usage detected: {cpu_usage}%",
            details="Server is under heavy load"
        )
    if memory_usage > 85:
        send_real_time_alert(
            alert_type="System Performance Issue",
            message=f"High memory usage detected: {memory_usage}%",
            details="Server is running out of memory"
        )

def start_performance_monitoring():
    while True:
        monitor_system_performance()
        time.sleep(10)

# Start performance monitoring in a background thread
performance_thread = Thread(target=start_performance_monitoring)
performance_thread.daemon = True
performance_thread.start()

def verify_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        logging.warning("JWT expired.")
        return None
    except jwt.InvalidTokenError:
        logging.warning("Invalid JWT.")
        return None

# RSA key functions
def load_private_key():
    with open(PRIVATE_KEY_PATH, 'r') as f:
        return RSA.import_key(f.read())

def decrypt_aes_key(private_key, encrypted_aes_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))

def decrypt_features(aes_key, nonce, ciphertext, tag):
    nonce_bytes = base64.b64decode(nonce) if isinstance(nonce, str) else nonce
    ciphertext_bytes = base64.b64decode(ciphertext) if isinstance(ciphertext, str) else ciphertext
    tag_bytes = base64.b64decode(tag) if isinstance(tag, str) else tag
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce_bytes)
    decrypted_data = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
    features = json.loads(decrypted_data)
    return pd.DataFrame([features], columns=feature_names)

# Role-Based Access Control Decorator
def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization', '').split(" ")[1]
            decoded = verify_jwt(token)
            if not decoded or decoded.get('role') != role:
                return jsonify({"error": "Access denied"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Admin routes
@app.route('/admin', methods=['GET'])
@role_required('admin')
def admin_dashboard():
    logging.info("Admin dashboard accessed.")
    return jsonify({"message": "Welcome to the admin dashboard."})

@app.route('/admin/users', methods=['GET'])
@role_required('admin')
def get_all_users():
    try:
        users = list(users_collection.find({}, {"_id": 0}))
        for user in users:
            if 'password' in user:
                user['password'] = base64.b64encode(user['password']).decode('utf-8')
        return jsonify({"users": users})
    except Exception as e:
        app.logger.error(f"Error fetching users: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/admin/create_user', methods=['POST'])
@role_required('admin')
def create_user():
    user_data = request.json
    user_id = user_data.get('user_id')
    password = user_data.get('password')
    role = user_data.get('role', 'user')
    if users_collection.find_one({"user_id": user_id}):
        return jsonify({"error": "User already exists."}), 400
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users_collection.insert_one({"user_id": user_id, "role": role, "password": hashed_password})
    return jsonify({"message": f"User {user_id} created with role {role}."}), 201

@app.route('/admin/update_user_role', methods=['POST'])
@role_required('admin')
def update_user_role():
    user_data = request.json
    user_id = user_data.get('user_id')
    new_role = user_data.get('role')
    result = users_collection.update_one({"user_id": user_id}, {"$set": {"role": new_role}})
    if result.matched_count == 0:
        return jsonify({"error": f"User {user_id} not found."}), 404
    log_activity(user_id, "Role Update", f"Role updated to {new_role}")
    return jsonify({"message": f"User {user_id}'s role updated to {new_role}."})

@app.route('/admin/delete_user', methods=['POST'])
@role_required('admin')
def delete_user():
    user_data = request.json
    user_id = user_data.get('user_id')
    result = users_collection.delete_one({"user_id": user_id})
    if result.deleted_count == 0:
        return jsonify({"error": f"User {user_id} not found."}), 404
    log_activity(user_id, "User Deletion", f"User {user_id} deleted.")
    return jsonify({"message": f"User {user_id} has been deleted."})

@app.route('/admin/login_history', methods=['GET'])
@role_required('admin')
def get_login_history():
    try:
        login_history = list(db.user_login_history.find({}, {"_id": 0}).sort("timestamp", -1).limit(50))
        return jsonify({"login_history": login_history})
    except Exception as e:
        app.logger.error(f"Error fetching login history: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/admin/activity_logs', methods=['GET'])
@role_required('admin')
def get_activity_logs():
    try:
        activity_logs = list(db.activity_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(10))
        return jsonify({"activity_logs": activity_logs})
    except Exception as e:
        app.logger.error(f"Error fetching activity logs: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/admin/bulk_actions', methods=['POST'])
@role_required('admin')
def bulk_actions():
    try:
        actions = request.json.get('actions', [])
        results = []
        for action in actions:
            user_id = action.get('user_id')
            operation = action.get('operation')
            details = action.get('details', {})
            if operation == "delete":
                result = users_collection.delete_one({"user_id": user_id})
                if result.deleted_count > 0:
                    log_activity(user_id, "Bulk Deletion", "User deleted via bulk action.")
                    results.append({"user_id": user_id, "status": "deleted"})
                else:
                    results.append({"user_id": user_id, "status": "not found"})
            elif operation == "update_role":
                new_role = details.get('role')
                result = users_collection.update_one({"user_id": user_id}, {"$set": {"role": new_role}})
                if result.matched_count > 0:
                    log_activity(user_id, "Bulk Role Update", f"Role updated to {new_role} via bulk action.")
                    results.append({"user_id": user_id, "status": f"role updated to {new_role}"})
                else:
                    results.append({"user_id": user_id, "status": "not found"})
            elif operation == "suspend":
                result = users_collection.update_one({"user_id": user_id}, {"$set": {"suspended": True}})
                if result.matched_count > 0:
                    log_activity(user_id, "Suspension", "User suspended via bulk action.")
                    results.append({"user_id": user_id, "status": "suspended"})
                else:
                    results.append({"user_id": user_id, "status": "not found"})
            elif operation == "unsuspend":
                result = users_collection.update_one({"user_id": user_id}, {"$set": {"suspended": False}})
                if result.matched_count > 0:
                    log_activity(user_id, "Unsuspension", "User unsuspended via bulk action.")
                    results.append({"user_id": user_id, "status": "unsuspended"})
                else:
                    results.append({"user_id": user_id, "status": "not found"})
            elif operation == "add_user":
                new_user_data = details.get('user_data')
                if not new_user_data:
                    results.append({"user_id": user_id, "status": "missing user data"})
                    continue
                existing_user = users_collection.find_one({"user_id": user_id})
                if existing_user:
                    results.append({"user_id": user_id, "status": "already exists"})
                    continue
                new_user_data['user_id'] = user_id
                new_user_data['password'] = bcrypt.hashpw(new_user_data['password'].encode('utf-8'), bcrypt.gensalt())
                new_user_data['suspended'] = new_user_data.get('suspended', False)
                result = users_collection.insert_one(new_user_data)
                if result.inserted_id:
                    log_activity(user_id, "Bulk User Addition", "User added via bulk action.")
                    results.append({"user_id": user_id, "status": "added"})
                else:
                    results.append({"user_id": user_id, "status": "error adding user"})
        return jsonify({"results": results}), 200
    except Exception as e:
        app.logger.error(f"Error in bulk actions: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/admin/suspend_user', methods=['POST'])
@role_required('admin')
def suspend_user():
    user_data = request.json
    user_id = user_data.get('user_id')
    user = users_collection.find_one({"user_id": user_id})
    if not user:
        return jsonify({"error": f"User {user_id} not found."}), 404
    result = users_collection.update_one({"user_id": user_id}, {"$set": {"suspended": True}})
    if result.matched_count == 0:
        return jsonify({"error": f"Failed to suspend user {user_id}."}), 500
    log_activity(user_id, "Suspension", f"User {user_id} suspended.")
    return jsonify({"message": f"User {user_id} has been suspended."})

@app.route('/admin/unsuspend_user', methods=['POST'])
@role_required('admin')
def unsuspend_user():
    user_data = request.json
    user_id = user_data.get('user_id')
    user = users_collection.find_one({"user_id": user_id})
    if not user:
        return jsonify({"error": f"User {user_id} not found."}), 404
    result = users_collection.update_one({"user_id": user_id}, {"$set": {"suspended": False}})
    if result.matched_count == 0:
        return jsonify({"error": f"Failed to unsuspend user {user_id}."}), 500
    log_activity(user_id, "Unsuspension", f"User {user_id} unsuspended.")
    return jsonify({"message": f"User {user_id} has been unsuspended."})

# Performance check function
def check_system_performance():
    cpu_usage = psutil.cpu_percent(interval=1)
    if cpu_usage > 80:
        send_real_time_alert(
            alert_type="System Performance Alert",
            message=f"High CPU usage detected: {cpu_usage}%",
            details="Consider optimizing the system or scaling resources."
        )

def generate_real_time_data():
    ist_tz = pytz.timezone('Asia/Kolkata')
    while True:
        features = pd.DataFrame([np.random.rand(len(feature_names))], columns=feature_names)
        
        if int(time.time()) % 5 == 0:
            features['serror_rate'] = 1.0
            features['srv_serror_rate'] = 1.0
            features['count'] = 500
            logging.info("Simulating aggressive attack traffic (e.g., neptune)")
            logging.debug(f"Raw attack features: serror_rate={features['serror_rate'].values[0]}, srv_serror_rate={features['srv_serror_rate'].values[0]}, count={features['count'].values[0]}, duration={features['duration'].values[0]}")
        
        features_scaled = scaler.transform(features)
        prediction = combined_predict(features_scaled, threshold=optimal_threshold)
        label_idx = prediction[0]
        label_name = label_to_name.get(label_idx, 'unknown')
        label_display = f"{label_idx}-{label_name}"
        
        # Simulate realistic network data
        src_ip = f"192.168.1.{random.randint(100, 150)}"  # Simulating a range of source IPs
        dst_ip = f"10.0.0.{random.randint(1, 255)}"      # Simulating destination IPs
        protocol = random.choice(["TCP", "UDP", "ICMP"])  # Random protocol
        packet_length = random.randint(64, 1500)         # Realistic packet size
        
        current_time_utc = datetime.datetime.now(pytz.utc)
        current_time_ist = current_time_utc.astimezone(ist_tz).strftime('%Y-%m-%d %I:%M:%S %p')
        data = {
            "timestamp": current_time_ist,
            "prediction": label_display,
            "confidence": 0.99,
            "client_ip": src_ip,  # Alias for src_ip
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "length": packet_length,
            "summary": f"{protocol} packet from {src_ip} to {dst_ip}"
        }
        socketio.emit('real-time-data', data)
        
        if label_idx != 15:
            send_real_time_alert(
                alert_type="Intrusion Detected",
                message=f"Potential intrusion detected: {label_display}",
                details=f"Source IP: {src_ip}, Dest IP: {dst_ip}, Protocol: {protocol}, Length: {packet_length}"
            )
        if int(time.time()) % 10 == 0:
            check_system_performance()
        time.sleep(1)

def generate_real_time_data_neptune():
    ist_tz = pytz.timezone('Asia/Kolkata')
    while True:
        # Simulate neptune-like features
        features = pd.DataFrame([{
            'duration': 0, 'protocol_type': 1, 'service': 46, 'flag': 1,  # tcp, private, S0 (encoded values)
            'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
            'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0,
            'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0, 'count': 166, 'srv_count': 9,
            'serror_rate': 1.0, 'srv_serror_rate': 1.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 0.05, 'diff_srv_rate': 0.06,
            'srv_diff_host_rate': 0.0, 'dst_host_count': 255, 'dst_host_srv_count': 9,
            'dst_host_same_srv_rate': 0.04, 'dst_host_diff_srv_rate': 0.05,
            'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 1.0, 'dst_host_srv_serror_rate': 1.0,
            'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0
        }], columns=feature_names)

        if int(time.time()) % 5 == 0:
            logging.info("Simulating neptune attack traffic")
        
        features_scaled = scaler.transform(features)
        prediction = combined_predict(features_scaled, threshold=optimal_threshold)
        label_idx = prediction[0]
        label_name = label_to_name.get(label_idx, 'unknown')
        label_display = f"{label_idx}-{label_name}"
        client_ip = "192.168.1.100"
        current_time_ist = datetime.datetime.now(pytz.utc).astimezone(ist_tz).strftime('%Y-%m-%d %I:%M:%S %p')
        data = {
            "timestamp": current_time_ist,
            "prediction": label_display,
            "confidence": 0.99,
            "client_ip": client_ip
        }
        socketio.emit('real-time-data', data)
        if label_idx != 15:
            send_real_time_alert(
                alert_type="Intrusion Detected",
                message=f"Potential intrusion detected: {label_display}",
                details=f"Features: {features.to_dict()}"
            )
        time.sleep(1)

def generate_real_time_data_back():
    ist_tz = pytz.timezone('Asia/Kolkata')
    while True:
        # Simulate back-like features
        features = pd.DataFrame([{
            'duration': 0, 'protocol_type': 1, 'service': 22, 'flag': 9,  # tcp, http, SF
            'src_bytes': 54540, 'dst_bytes': 8314, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 2, 'num_failed_logins': 0, 'logged_in': 1, 'num_compromised': 1,
            'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0,
            'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0, 'count': 3, 'srv_count': 3,
            'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0, 'dst_host_count': 118, 'dst_host_srv_count': 118,
            'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.01, 'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.02, 'dst_host_srv_rerror_rate': 0.02
        }], columns=feature_names)

        if int(time.time()) % 5 == 0:
            logging.info("Simulating back attack traffic")
        
        features_scaled = scaler.transform(features)
        prediction = combined_predict(features_scaled, threshold=optimal_threshold)
        label_idx = prediction[0]
        label_name = label_to_name.get(label_idx, 'unknown')
        label_display = f"{label_idx}-{label_name}"
        client_ip = "192.168.1.100"
        current_time_ist = datetime.datetime.now(pytz.utc).astimezone(ist_tz).strftime('%Y-%m-%d %I:%M:%S %p')
        data = {
            "timestamp": current_time_ist,
            "prediction": label_display,
            "confidence": 0.99,
            "client_ip": client_ip
        }
        socketio.emit('real-time-data', data)
        if label_idx != 15:
            send_real_time_alert(
                alert_type="Intrusion Detected",
                message=f"Potential intrusion detected: {label_display}",
                details=f"Features: {features.to_dict()}"
            )
        time.sleep(1)        

@app.route('/login', methods=['POST'])
def login():
    user_id = request.json.get('user_id')
    password = request.json.get('password')
    logging.info(f"Login attempt for user: {user_id}")
    user = users_collection.find_one({"user_id": user_id})
    if not user:
        logging.error(f"User {user_id} not found.")
        return jsonify({"error": "User not found"}), 404
    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        logging.error(f"Invalid password for user {user_id}.")
        return jsonify({"error": "Invalid password"}), 401
    if user.get("suspended"):
        logging.warning(f"User {user_id} is suspended.")
        return jsonify({"error": "Your account has been suspended."}), 403
    role = user.get('role', 'user')
    token = generate_jwt(user_id, role)
    log_entry = {
        "user_id": user_id,
        "timestamp": datetime.datetime.now(pytz.utc).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M:%S %p'),
        "client_ip": request.remote_addr,
        "user_agent": request.headers.get('User-Agent')
    }
    db.user_login_history.insert_one(log_entry)
    log_activity(user_id, "Login", "User successfully logged in.")
    return jsonify({"token": token, "role": role}), 200

@app.route('/predict', methods=['POST'])
@role_required('user')
def predict():
    try:
        client_ip = request.remote_addr
        encrypted_data = request.json.get('encrypted_features')
        if not encrypted_data:
            logging.error("Encrypted features missing")
            return jsonify({"error": "Missing encrypted features."}), 400
        encrypted_features = json.loads(encrypted_data)
        encrypted_aes_key = encrypted_features.get('aes_key')
        nonce = encrypted_features.get('nonce')
        ciphertext = encrypted_features.get('ciphertext')
        tag = encrypted_features.get('tag')
        logging.debug(f"Encrypted AES key: {encrypted_aes_key}")
        logging.debug(f"Nonce: {nonce}")
        logging.debug(f"Ciphertext: {ciphertext}")
        logging.debug(f"Tag: {tag}")
        private_key = load_private_key()
        aes_key = decrypt_aes_key(private_key, encrypted_aes_key)
        decrypted_features = decrypt_features(aes_key, nonce, ciphertext, tag)
        features_scaled = scaler.transform(decrypted_features)
        prediction = combined_predict(features_scaled, threshold=optimal_threshold)
        label_idx = prediction[0]
        label_name = label_to_name.get(label_idx, 'unknown')
        label_display = f"{label_idx}-{label_name}"
        return jsonify({"prediction": label_display, "client_ip": client_ip})
    except Exception as e:
        logging.error(f"Prediction error: {e}")
        return jsonify({"error": "Prediction failed."}), 500

@app.route('/user-info', methods=['GET'])
@role_required('user')
def get_user_info():
    token = request.headers.get('Authorization', '').split(" ")[1]
    decoded = verify_jwt(token)
    if not decoded:
        return jsonify({"error": "Invalid token."}), 403
    user_id = decoded.get('user_id')
    user = users_collection.find_one({"user_id": user_id}, {"_id": 0, "password": 0})
    if not user:
        return jsonify({"error": "User not found."}), 404
    return jsonify({"user_info": user})

@app.route('/update-password', methods=['POST'])
@role_required('user')
def update_password():
    user_data = request.json
    old_password = user_data.get('old_password')
    new_password = user_data.get('new_password')
    token = request.headers.get('Authorization', '').split(" ")[1]
    decoded = verify_jwt(token)
    if not decoded:
        return jsonify({"error": "Invalid token."}), 403
    user_id = decoded.get('user_id')
    user = users_collection.find_one({"user_id": user_id})
    if not user:
        return jsonify({"error": "User not found."}), 404
    if not bcrypt.checkpw(old_password.encode('utf-8'), user['password']):
        return jsonify({"error": "Incorrect old password"}), 401
    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    result = users_collection.update_one({"user_id": user_id}, {"$set": {"password": hashed_new_password}})
    if result.modified_count == 0:
        return jsonify({"error": "Password update failed."}), 500
    return jsonify({"message": "Password updated successfully"}), 200

if __name__ == "__main__":
    Thread(target=generate_real_time_data, daemon=True).start()  # Uncomment for testing
    socketio.run(app, host="0.0.0.0", port=5000)