from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import json

def load_public_key(public_key_path="C:\\Users\\Ashwi\\OneDrive\\Desktop\\IDS Project\\public.key"):
    """
    Load the RSA public key from the given file path.
    """
    try:
        with open(public_key_path, 'rb') as key_file:
            public_key = RSA.import_key(key_file.read())
        return public_key
    except Exception as e:
        print(f"Error loading public key: {e}")
        raise

def load_private_key(private_key_path="C:\\Users\\Ashwi\\OneDrive\\Desktop\\IDS Project\\private.key"):
    """
    Load the RSA private key from the given file path.
    """
    try:
        with open(private_key_path, 'rb') as key_file:
            private_key = RSA.import_key(key_file.read())
        return private_key
    except Exception as e:
        print(f"Error loading private key: {e}")
        raise

def hybrid_encrypt(public_key, data):
    """
    Encrypt the data using hybrid encryption (AES + RSA).
    Encrypt the data with a random AES key and encrypt the AES key with RSA.
    """
    try:
        # Generate a random AES session key
        aes_key = get_random_bytes(32)  # AES key for encryption (256-bit)

        # Encrypt the data using AES
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode('utf-8'))

        # Encrypt the AES key using the RSA public key
        cipher_rsa = PKCS1_OAEP.new(public_key)
        aes_key_encrypted = cipher_rsa.encrypt(aes_key)

        # Prepare the encrypted data to send
        encrypted_payload = {
            'aes_key': base64.b64encode(aes_key_encrypted).decode('utf-8'),
            'nonce': base64.b64encode(cipher_aes.nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }

        return json.dumps(encrypted_payload)  # Return the encrypted data as a JSON string
    except Exception as e:
        print(f"Error during encryption: {e}")
        raise

def hybrid_decrypt(private_key, encrypted_payload):
    """
    Decrypt the encrypted payload using hybrid encryption.
    """
    try:
        # Parse the payload
        encrypted_payload = json.loads(encrypted_payload)
        aes_key_encrypted = base64.b64decode(encrypted_payload['aes_key'])
        nonce = base64.b64decode(encrypted_payload['nonce'])
        ciphertext = base64.b64decode(encrypted_payload['ciphertext'])
        tag = base64.b64decode(encrypted_payload['tag'])

        # Decrypt the AES key using the RSA private key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(aes_key_encrypted)

        # Decrypt the data using the AES key
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # Return the decrypted data as a string (no unpad required for EAX mode)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"Error during decryption: {e}")
        raise
