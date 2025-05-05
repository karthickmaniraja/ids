import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding  # Correct import for padding

# Load the public key
def load_public_key(public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

# Encrypt features using public key and AES (Hybrid encryption)
def encrypt_features(public_key, features):
    # Generate AES key for symmetric encryption
    aes_key = os.urandom(32)

    # Encrypt the features using AES (for simplicity, base64 encoded string can be used)
    # You'll need to apply actual AES encryption for real use cases
    encrypted_features = base64.b64encode(json.dumps(features).encode())

    # Encrypt AES key using the RSA public key (asymmetric encryption)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Return the AES key and encrypted features in a JSON format (simulating the hybrid encryption approach)
    encrypted_data = {
        'aes_key': base64.b64encode(encrypted_aes_key).decode(),
        'ciphertext': encrypted_features.decode(),
        'nonce': base64.b64encode(os.urandom(16)).decode(),  # Random nonce for AES (if needed)
        'tag': base64.b64encode(os.urandom(16)).decode()    # Random tag for AES (if needed)
    }

    # Ensure the output is properly serialized as a JSON string with escape characters
    return json.dumps(encrypted_data)

# Main execution
if __name__ == "__main__":
    public_key_path = "C:\\Users\\Ashwi\\OneDrive\\Desktop\\IDS Project\\public.key"  # Correct path to the public key
    public_key = load_public_key(public_key_path)

    # Example features to encrypt
    features = {"feature1": 1.0, "feature2": 2.0, "feature3": 3.0}

    encrypted_features = encrypt_features(public_key, features)

    # Print the encrypted features with escape characters for JSON compatibility
    print("Encrypted Features (with escape characters):")
    print(encrypted_features)
