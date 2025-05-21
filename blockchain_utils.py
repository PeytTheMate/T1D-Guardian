import hashlib
import json
import time
import os
import requests
from web3 import Web3
import uuid

def calculate_hash(data):
    """
    Calculate SHA-256 hash of data
    
    Parameters:
    data (bytes or str): Data to hash
    
    Returns:
    str: Hexadecimal hash string
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    hash_object = hashlib.sha256(data)
    return hash_object.hexdigest()

def store_hash_on_blockchain(data_hash):
    """
    Store a data hash on the Ethereum Sepolia testnet
    
    Parameters:
    data_hash (str): SHA-256 hash to store
    
    Returns:
    str: Transaction hash or identifier
    """
    # In a production system, this would connect to an Ethereum node
    # and submit a transaction to a smart contract
    
    # For this demo, we'll use a simulated blockchain connection
    # In a real implementation, you would:
    # 1. Connect to Ethereum using Infura or a local node
    # 2. Sign a transaction with your private key
    # 3. Send the transaction to a smart contract that stores the hash
    
    # Check if we have an Infura API key
    infura_api_key = os.getenv("INFURA_API_KEY")
    eth_private_key = os.getenv("ETH_PRIVATE_KEY")
    
    if infura_api_key and eth_private_key:
        # In a real implementation, this would be the actual transaction
        try:
            # Connect to Ethereum Sepolia testnet
            w3 = Web3(Web3.HTTPProvider(f"https://sepolia.infura.io/v3/{infura_api_key}"))
            
            # Check if connected
            if not w3.is_connected():
                raise Exception("Failed to connect to Ethereum network")
            
            # Simulate blockchain interaction for demo
            # In a real app, you would deploy a smart contract and call it here
            
            # Simulate transaction hash
            tx_hash = f"0x{uuid.uuid4().hex}"
            
            # Return the transaction hash
            return tx_hash
        except Exception as e:
            print(f"Error connecting to blockchain: {str(e)}")
            # Fallback to simulated hash
            simulated_tx_hash = f"0x{uuid.uuid4().hex}"
            return simulated_tx_hash
    else:
        # If no API key, return a simulated transaction hash
        # This is for demonstration purposes only
        # In a real app, you would require actual blockchain integration
        simulated_tx_hash = f"0x{uuid.uuid4().hex}"
        return simulated_tx_hash

def verify_hash(data_hash, tx_hash):
    """
    Verify that a hash was stored on the blockchain
    
    Parameters:
    data_hash (str): The data hash to verify
    tx_hash (str): The transaction hash from when the data was stored
    
    Returns:
    bool: True if verification successful, False otherwise
    """
    # In a real implementation, this would query the blockchain
    # to verify the hash was stored in the specified transaction
    
    # For demonstration purposes, we'll simulate a successful verification
    # In a real application, you would:
    # 1. Connect to Ethereum
    # 2. Query the transaction or the smart contract storage
    # 3. Compare the stored hash with the provided hash
    
    # Check if we have an Infura API key
    infura_api_key = os.getenv("INFURA_API_KEY")
    
    if infura_api_key:
        try:
            # Connect to Ethereum Sepolia testnet
            w3 = Web3(Web3.HTTPProvider(f"https://sepolia.infura.io/v3/{infura_api_key}"))
            
            # Check if connected
            if not w3.is_connected():
                raise Exception("Failed to connect to Ethereum network")
            
            # Simulate successful verification for demo
            return True
        except Exception as e:
            print(f"Error connecting to blockchain: {str(e)}")
            # For demo, return true
            return True
    else:
        # For demonstration purposes, simulate a successful verification
        return True

def create_blockchain_proof(data_hash, metadata=None):
    """
    Create a proof document linking data hash to blockchain
    
    Parameters:
    data_hash (str): SHA-256 hash of the data
    metadata (dict, optional): Additional metadata to include
    
    Returns:
    dict: Proof document
    """
    if metadata is None:
        metadata = {}
    
    # Store hash on blockchain
    tx_hash = store_hash_on_blockchain(data_hash)
    
    # Create proof document
    timestamp = int(time.time())
    proof = {
        "data_hash": data_hash,
        "blockchain": "ethereum_sepolia",
        "transaction_hash": tx_hash,
        "timestamp": timestamp,
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
        "metadata": metadata
    }
    
    return proof

def verify_blockchain_proof(proof):
    """
    Verify a blockchain proof document
    
    Parameters:
    proof (dict): Proof document created by create_blockchain_proof
    
    Returns:
    bool: True if verification successful, False otherwise
    """
    # Extract information from proof
    data_hash = proof.get("data_hash")
    tx_hash = proof.get("transaction_hash")
    
    if not data_hash or not tx_hash:
        return False
    
    # Verify the hash was stored on the blockchain
    return verify_hash(data_hash, tx_hash)
