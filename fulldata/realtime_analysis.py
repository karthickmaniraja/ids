from scapy.all import sniff, IP, TCP, UDP
import joblib
import numpy as np
from datetime import datetime

# Load the trained model, label encoder, and feature names
model = joblib.load('trained_model.pkl')
label_encoder = joblib.load('label_encoder.pkl')
feature_names = joblib.load('feature_names.pkl')

# Define the feature extraction function
def extract_features(packet):
    """
    Extract relevant features from a network packet to match the model's input features.
    """
    features = {name: 0 for name in feature_names}  # Initialize all features to 0

    if IP in packet:
        # Example feature extraction logic:
        features['packet_length'] = len(packet)  # Total packet length
        features['src_ip'] = hash(packet[IP].src) % 1000  # Hash source IP for encoding
        features['dst_ip'] = hash(packet[IP].dst) % 1000  # Hash destination IP for encoding
        features['protocol'] = packet[IP].proto  # Protocol (6 = TCP, 17 = UDP)

        if TCP in packet:
            features['src_port'] = packet[TCP].sport  # Source port
            features['dst_port'] = packet[TCP].dport  # Destination port
        elif UDP in packet:
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport

    # Return features as a NumPy array in the correct order
    return np.array([features[name] for name in feature_names])

# Define the prediction function
def predict(packet):
    """
    Predict whether a network packet is normal or an anomaly.
    """
    try:
        features = extract_features(packet)
        features_reshaped = features.reshape(1, -1)  # Reshape for the model
        prediction = model.predict(features_reshaped)
        label = label_encoder.inverse_transform(prediction)[0]  # Decode the label

        # Log the prediction result
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] Prediction: {label}")
    except Exception as e:
        print(f"Error in prediction: {e}")

# Define the real-time packet capture function
def capture_packets(interface='eth0'):
    """
    Capture packets in real-time and analyze them.
    """
    print(f"Starting real-time packet capture on interface: {interface}")
    sniff(iface=interface, prn=predict, store=False)

# Main function
if __name__ == "__main__":
    network_interface = "Ethernet"  # Replace with your active network interface
    capture_packets(interface=network_interface)
