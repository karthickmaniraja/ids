import json
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# Example feature vector with 41 elements
features = [0.1] * 41  # Replace this with your actual features

# Serialize feature vector
serialized_features = json.dumps(features)

# Encrypt the features with AES
def encrypt_features(aes_key, features):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(features.encode())
    return {
        "aes_key": base64.b64encode(aes_key).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }

# Encrypt AES key with RSA
def encrypt_aes_key(public_key_path, aes_key):
    with open(public_key_path, 'r') as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_key).decode()

# Generate AES key (16 bytes for AES-128)
aes_key = b'0123456789abcdef'

# Encrypt the features
encrypted_features = encrypt_features(aes_key, serialized_features)

# Encrypt the AES key using the public key
encrypted_features['aes_key'] = encrypt_aes_key("public.key", aes_key)

# Prepare the payload
payload = json.dumps({
    "encrypted_features": json.dumps(encrypted_features)
})

print("Payload:", payload)
