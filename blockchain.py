import hashlib
import json
import time
from web3 import Web3
from eth_account.messages import encode_defunct

def generate_hash(data):
    """
    Generate a SHA-256 hash of the data
    
    Args:
        data (bytes or str): Data to hash
    
    Returns:
        str: Hexadecimal hash string
    """
    # Convert to bytes if string
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Generate SHA-256 hash
    hash_obj = hashlib.sha256(data)
    return hash_obj.hexdigest()

def store_hash_on_blockchain(data_hash, infura_api_key, private_key):
    """
    Store a data hash on Ethereum Sepolia testnet
    
    Args:
        data_hash (str): SHA-256 hash to store
        infura_api_key (str): Infura API key for Ethereum connection
        private_key (str): Ethereum private key for transaction signing
    
    Returns:
        str: Transaction hash
    """
    # Connect to Ethereum Sepolia testnet
    w3 = Web3(Web3.HTTPProvider(f"https://sepolia.infura.io/v3/{infura_api_key}"))
    
    # Verify connection
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to Ethereum network")
    
    # Get account address from private key
    account = w3.eth.account.from_key(private_key)
    address = account.address
    
    # Create message to sign (hash + timestamp)
    timestamp = int(time.time())
    message = f"T1D-Guardian Data Hash: {data_hash}, Timestamp: {timestamp}"
    
    # Sign message
    message_encoded = encode_defunct(text=message)
    signed_message = w3.eth.account.sign_message(message_encoded, private_key=private_key)
    
    # Get the latest transaction count for the address
    nonce = w3.eth.get_transaction_count(address)
    
    # Create a simple transaction that stores data in the transaction input field
    tx = {
        'from': address,
        'to': address,  # Send to self
        'value': 0,
        'gas': 100000,
        'gasPrice': w3.eth.gas_price,
        'nonce': nonce,
        'data': w3.to_hex(text=message),
    }
    
    # Sign and send transaction
    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    
    # Return the transaction hash
    return w3.to_hex(tx_hash)

def verify_hash(tx_hash, infura_api_key):
    """
    Verify a hash stored on the blockchain
    
    Args:
        tx_hash (str): Transaction hash to verify
        infura_api_key (str): Infura API key for Ethereum connection
    
    Returns:
        dict: Verification information
    """
    # Connect to Ethereum Sepolia testnet
    w3 = Web3(Web3.HTTPProvider(f"https://sepolia.infura.io/v3/{infura_api_key}"))
    
    # Verify connection
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to Ethereum network")
    
    # Get transaction details
    tx = w3.eth.get_transaction(tx_hash)
    
    # Extract data from transaction
    if tx and tx.input:
        # Convert from hex to text
        try:
            data_text = w3.to_text(tx.input)
            # Parse message format "T1D-Guardian Data Hash: {hash}, Timestamp: {timestamp}"
            if "T1D-Guardian Data Hash" in data_text:
                hash_part = data_text.split("Data Hash: ")[1].split(",")[0]
                timestamp_part = int(data_text.split("Timestamp: ")[1])
                
                # Create verification result
                result = {
                    "verified": True,
                    "hash": hash_part,
                    "timestamp": timestamp_part,
                    "human_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp_part)),
                    "transaction": tx_hash
                }
                return result
        except:
            pass
    
    return None
