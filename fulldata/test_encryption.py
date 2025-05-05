from encryption_utils import load_public_key, load_private_key, hybrid_encrypt, hybrid_decrypt

def test_encryption_decryption():
    # Load keys from file locations
    public_key_path = "C:\\Users\\Ashwi\\OneDrive\\Desktop\\IDS Project\\public.key"
    private_key_path = "C:\\Users\\Ashwi\\OneDrive\\Desktop\\IDS Project\\private.key"
    public_key = load_public_key(public_key_path)
    private_key = load_private_key(private_key_path)

    # Sample data for testing
    data = "Test data for encryption."

    # Encrypt the data
    encrypted_data = hybrid_encrypt(public_key, data)
    print(f"Encrypted data: {encrypted_data}")

    # Decrypt the data
    decrypted_data = hybrid_decrypt(private_key, encrypted_data)
    print(f"Decrypted data: {decrypted_data}")

if __name__ == "__main__":
    test_encryption_decryption()
