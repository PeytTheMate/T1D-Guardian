import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def generate_key(password, salt=None, iterations=100000):
    """
    Generate an AES encryption key from a password using PBKDF2
    
    Parameters:
    password (str): Password used to derive the key
    salt (bytes, optional): Salt for key derivation. If None, a random salt is generated
    iterations (int): Number of iterations for PBKDF2
    
    Returns:
    dict: Dictionary containing the key and salt
    """
    if salt is None:
        salt = get_random_bytes(16)
    elif isinstance(salt, str):
        salt = salt.encode('utf-8')
    
    # Derive a 32-byte key (256 bits) from the password
    key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=iterations)
    
    return {
        'key': key,
        'salt': salt
    }

def encrypt_data(data, key_dict):
    """
    Encrypt data using AES-256 in CBC mode
    
    Parameters:
    data (str or bytes): Data to encrypt
    key_dict (dict): Dictionary containing the key and salt
    
    Returns:
    bytes: Encrypted data with format: iv + ciphertext
    """
    # Convert string data to bytes if needed
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Generate a random initialization vector
    iv = get_random_bytes(16)
    
    # Create cipher object and encrypt
    cipher = AES.new(key_dict['key'], AES.MODE_CBC, iv)
    
    # Pad data to be a multiple of 16 bytes (AES block size)
    padded_data = pad(data, AES.block_size)
    
    # Encrypt and combine IV + ciphertext
    ciphertext = cipher.encrypt(padded_data)
    encrypted_data = iv + ciphertext
    
    return encrypted_data

def decrypt_data(encrypted_data, key_dict):
    """
    Decrypt data that was encrypted with AES-256 CBC
    
    Parameters:
    encrypted_data (bytes): Encrypted data (iv + ciphertext)
    key_dict (dict): Dictionary containing the key and salt
    
    Returns:
    bytes: Decrypted data
    """
    # Extract IV (first 16 bytes) and ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Create cipher object for decryption
    cipher = AES.new(key_dict['key'], AES.MODE_CBC, iv)
    
    # Decrypt and unpad
    padded_data = cipher.decrypt(ciphertext)
    data = unpad(padded_data, AES.block_size)
    
    return data

def save_encrypted_data(data, filename, key_dict):
    """
    Encrypt and save data to a file
    
    Parameters:
    data (str or bytes): Data to encrypt and save
    filename (str): Name of the file to save the encrypted data
    key_dict (dict): Dictionary containing the key and salt
    
    Returns:
    bool: True if successful
    """
    encrypted_data = encrypt_data(data, key_dict)
    
    try:
        with open(filename, 'wb') as f:
            f.write(encrypted_data)
        return True
    except Exception as e:
        print(f"Error saving encrypted data: {str(e)}")
        return False

def load_encrypted_data(filename, key_dict):
    """
    Load and decrypt data from a file
    
    Parameters:
    filename (str): Name of the file containing encrypted data
    key_dict (dict): Dictionary containing the key and salt
    
    Returns:
    bytes: Decrypted data
    """
    try:
        with open(filename, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_data(encrypted_data, key_dict)
        return decrypted_data
    except Exception as e:
        print(f"Error loading encrypted data: {str(e)}")
        return None

def hash_data(data):
    """
    Generate a SHA-256 hash of data
    
    Parameters:
    data (str or bytes): Data to hash
    
    Returns:
    str: Hexadecimal string representation of the hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    hash_obj = hashlib.sha256(data)
    return hash_obj.hexdigest()
