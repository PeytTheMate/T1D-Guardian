from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import json

def generate_key():
    """
    Generate a random AES encryption key
    
    Returns:
        bytes: A 256-bit (32-byte) random key
    """
    return get_random_bytes(32)

def encrypt_data(data, key):
    """
    Encrypt data using AES-GCM
    
    Args:
        data (str): JSON string or text to encrypt
        key (bytes): Encryption key
    
    Returns:
        bytes: Encrypted data (nonce + tag + ciphertext)
    """
    # Convert string data to bytes if needed
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Create cipher object
    cipher = AES.new(key, AES.MODE_GCM)
    
    # Encrypt data
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # Combine nonce, tag, and ciphertext into a single byte string
    encrypted_data = cipher.nonce + tag + ciphertext
    
    return encrypted_data

def decrypt_data(encrypted_data, key):
    """
    Decrypt data using AES-GCM
    
    Args:
        encrypted_data (bytes): Encrypted data (nonce + tag + ciphertext)
        key (bytes): Encryption key
    
    Returns:
        str: Decrypted data as string
    """
    # Extract nonce and tag
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    # Create cipher object
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Decrypt and verify
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    
    # Convert bytes to string
    return decrypted_data.decode('utf-8')

def encrypt_sensitive_data(data_dict, key):
    """
    Encrypt a dictionary of data with sensitive fields
    
    Args:
        data_dict (dict): Dictionary with data to encrypt
        key (bytes): Encryption key
    
    Returns:
        dict: Dictionary with sensitive fields encrypted
    """
    # Define sensitive fields to encrypt
    sensitive_fields = ['glucose_value', 'predictions', 'patient_info']
    
    result = data_dict.copy()
    
    # Encrypt sensitive fields
    for field in sensitive_fields:
        if field in result and result[field] is not None:
            field_data = json.dumps(result[field])
            result[field] = base64.b64encode(encrypt_data(field_data, key)).decode('utf-8')
    
    return result

def decrypt_sensitive_data(encrypted_dict, key):
    """
    Decrypt a dictionary with encrypted fields
    
    Args:
        encrypted_dict (dict): Dictionary with encrypted fields
        key (bytes): Encryption key
    
    Returns:
        dict: Dictionary with fields decrypted
    """
    # Define sensitive fields to decrypt
    sensitive_fields = ['glucose_value', 'predictions', 'patient_info']
    
    result = encrypted_dict.copy()
    
    # Decrypt sensitive fields
    for field in sensitive_fields:
        if field in result and result[field] is not None:
            try:
                encrypted_bytes = base64.b64decode(result[field])
                decrypted_str = decrypt_data(encrypted_bytes, key)
                result[field] = json.loads(decrypted_str)
            except:
                # Skip fields that cannot be decrypted
                pass
    
    return result
