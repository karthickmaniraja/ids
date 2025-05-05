import numpy as np
import pandas as pd
import requests
import joblib
import time
from encryption_utils import load_public_key, hybrid_encrypt
from encryption_utils import load_public_key, hybrid_encrypt  # Correct import

# Load the model and label encoders for local decoding
model = joblib.load('trained_model.pkl')  # Path to the trained model
label_encoder = joblib.load('label_encoder.pkl')  # Path to the label encoder

# Load the public key for encryption
public_key = load_public_key('public.key')  # Path to the public key

# Prepare your sample data (you can modify this part based on how you're generating or collecting the data)
def prepare_data(sample_data):
    # Ensure the features are in the correct format for prediction
    features = sample_data.to_dict()  # Convert the sample data to a dictionary

    for key, value in features.items():
        # Convert any int64 or float64 to Python int or float for compatibility
        if isinstance(value, np.int64):  # Check for int64 type
            features[key] = int(value)  # Convert int64 to Python int
        elif isinstance(value, np.float64):  # Check for float64 type
            features[key] = float(value)  # Convert float64 to Python float
    return features

def simulate_realtime():
    # Simulate or fetch real-time data (adjust this based on your needs)
    sample_data = pd.Series({
        "duration": -0.110249,
        "protocol_type": 1,
        "service": 24,
        "flag": 9,
        "src_bytes": -0.007722,
        "dst_bytes": -0.004823,
        "land": -0.014088,
        "wrong_fragment": -0.089486,
        "urgent": -0.007736,
        "hot": -0.095076,
        "num_failed_logins": -0.027023,
        "logged_in": 1.235694,
        "num_compromised": -0.011664,
        "root_shell": -0.036653,
        "su_attempted": -0.024438,
        "num_root": -0.012385,
        "num_file_creations": -0.02618,
        "num_shells": -0.01861,
        "num_access_files": -0.041221,
        "num_outbound_cmds": 0,
        "is_host_login": -0.002817,
        "is_guest_login": -0.097531,
        "count": -0.603516,
        "srv_count": -0.175367,
        "serror_rate": -0.637209,
        "srv_serror_rate": -0.631929,
        "rerror_rate": -0.374362,
        "srv_rerror_rate": -0.374433,
        "same_srv_rate": 0.771283,
        "diff_srv_rate": -0.349683,
        "srv_diff_host_rate": -0.37456,
        "dst_host_count": -1.009507,
        "dst_host_srv_count": 1.258754,
        "dst_host_same_srv_rate": 1.066401,
        "dst_host_diff_srv_rate": -0.439078,
        "dst_host_same_src_port_rate": -0.447834,
        "dst_host_srv_diff_host_rate": -0.022587,
        "dst_host_serror_rate": -0.639532,
        "dst_host_srv_serror_rate": -0.624872,
        "dst_host_rerror_rate": -0.387635,
        "dst_host_srv_rerror_rate": -0.376387
    })

    # Prepare features for prediction
    features_for_prediction = prepare_data(sample_data)
    print("Features for prediction:", features_for_prediction)

    # Encrypt the features using hybrid encryption (you can implement this part separately if needed)
    encrypted_payload = hybrid_encrypt(public_key, str(list(features_for_prediction.values())))  # Encrypt using hybrid encryption
    payload = {'encrypted_features': encrypted_payload}
    print("Encrypted Payload for prediction:", payload)

    # Send the prediction request to the Flask API
    try:
        response = requests.post('http://127.0.0.1:5000/predict', json=payload, verify=False)
        prediction = response.json()
        print("Prediction received:", prediction)
    except requests.exceptions.RequestException as e:
        print(f"Error in prediction: {e}")

    # Simulate delay for real-time data
    time.sleep(1)  # Simulate real-time delay of 1 second

if __name__ == "__main__":
    try:
        simulate_realtime()
    except KeyboardInterrupt:
        print("Real-time simulation stopped.")
