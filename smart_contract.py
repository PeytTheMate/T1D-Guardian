from web3 import Web3
import json
import time
from eth_account import Account
from eth_account.messages import encode_defunct

# Simplified smart contract for T1D data consent management
CONSENT_CONTRACT_ABI = [
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "dataOwner",
                "type": "address"
            },
            {
                "internalType": "address",
                "name": "dataConsumer",
                "type": "address"
            },
            {
                "internalType": "string",
                "name": "dataHash",
                "type": "string"
            },
            {
                "internalType": "uint256",
                "name": "expiryTimestamp",
                "type": "uint256"
            }
        ],
        "name": "grantConsent",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "dataOwner",
                "type": "address"
            },
            {
                "internalType": "address",
                "name": "dataConsumer",
                "type": "address"
            }
        ],
        "name": "revokeConsent",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "dataOwner",
                "type": "address"
            },
            {
                "internalType": "address",
                "name": "dataConsumer",
                "type": "address"
            }
        ],
        "name": "verifyConsent",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            },
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            },
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

# This is a placeholder for demonstration - in production, would need actual deployed contract address
CONSENT_CONTRACT_ADDRESS = "0x0000000000000000000000000000000000000000"

def connect_to_ethereum(infura_api_key):
    """
    Connect to Ethereum network via Infura
    
    Args:
        infura_api_key (str): Infura API key
        
    Returns:
        Web3: Web3 connection object
    """
    w3 = Web3(Web3.HTTPProvider(f"https://sepolia.infura.io/v3/{infura_api_key}"))
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to Ethereum network")
    return w3

def create_consent_record(w3, private_key, recipient_address, data_hash, expiry_days, contract_address=CONSENT_CONTRACT_ADDRESS):
    """
    Record consent for data sharing on the Ethereum blockchain
    
    Args:
        w3 (Web3): Web3 connection object
        private_key (str): Private key of the data owner
        recipient_address (str): Ethereum address of the data recipient
        data_hash (str): SHA-256 hash of the data being shared
        expiry_days (int): Number of days until consent expires
        contract_address (str): Address of deployed consent smart contract
        
    Returns:
        str: Transaction hash
    """
    # Get account from private key
    account = Account.from_key(private_key)
    owner_address = account.address
    
    # Calculate expiry timestamp
    expiry_timestamp = int(time.time()) + (expiry_days * 86400)  # seconds in a day
    
    # Create contract instance
    contract = w3.eth.contract(address=contract_address, abi=CONSENT_CONTRACT_ABI)
    
    # Build transaction
    tx = contract.functions.grantConsent(
        owner_address,
        recipient_address,
        data_hash,
        expiry_timestamp
    ).build_transaction({
        'from': owner_address,
        'nonce': w3.eth.get_transaction_count(owner_address),
        'gas': 100000,
        'gasPrice': w3.eth.gas_price
    })
    
    # Sign and send transaction
    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    
    return w3.to_hex(tx_hash)

def verify_consent(w3, owner_address, consumer_address, contract_address=CONSENT_CONTRACT_ADDRESS):
    """
    Verify if consent exists and is valid
    
    Args:
        w3 (Web3): Web3 connection object
        owner_address (str): Ethereum address of the data owner
        consumer_address (str): Ethereum address of the data consumer
        contract_address (str): Address of deployed consent smart contract
        
    Returns:
        dict: Consent verification result
    """
    # Create contract instance
    contract = w3.eth.contract(address=contract_address, abi=CONSENT_CONTRACT_ABI)
    
    # Call verify consent function
    result = contract.functions.verifyConsent(owner_address, consumer_address).call()
    
    valid, data_hash, expiry = result
    current_time = int(time.time())
    
    return {
        "consent_exists": valid,
        "data_hash": data_hash,
        "expiry_timestamp": expiry,
        "is_valid": valid and expiry > current_time,
        "human_expiry": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expiry)) if valid else "N/A"
    }

def revoke_consent(w3, private_key, consumer_address, contract_address=CONSENT_CONTRACT_ADDRESS):
    """
    Revoke previously granted consent
    
    Args:
        w3 (Web3): Web3 connection object
        private_key (str): Private key of the data owner
        consumer_address (str): Ethereum address of the data consumer
        contract_address (str): Address of deployed consent smart contract
        
    Returns:
        str: Transaction hash
    """
    # Get account from private key
    account = Account.from_key(private_key)
    owner_address = account.address
    
    # Create contract instance
    contract = w3.eth.contract(address=contract_address, abi=CONSENT_CONTRACT_ABI)
    
    # Build transaction
    tx = contract.functions.revokeConsent(
        owner_address,
        consumer_address
    ).build_transaction({
        'from': owner_address,
        'nonce': w3.eth.get_transaction_count(owner_address),
        'gas': 100000,
        'gasPrice': w3.eth.gas_price
    })
    
    # Sign and send transaction
    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    
    return w3.to_hex(tx_hash)

def create_signed_consent_message(private_key, recipient_address, data_hash, expiry_days):
    """
    Create a signed message for off-chain consent when smart contract is not available
    
    Args:
        private_key (str): Private key of the data owner
        recipient_address (str): Ethereum address of the data recipient
        data_hash (str): SHA-256 hash of the data being shared
        expiry_days (int): Number of days until consent expires
        
    Returns:
        dict: Signed consent message and verification info
    """
    # Get account from private key
    account = Account.from_key(private_key)
    owner_address = account.address
    
    # Calculate expiry timestamp
    expiry_timestamp = int(time.time()) + (expiry_days * 86400)
    
    # Create consent message
    message = f"I, {owner_address}, consent to share data with hash {data_hash} with {recipient_address} until {expiry_timestamp}"
    
    # Sign message
    msg_hash = encode_defunct(text=message)
    signed_message = Account.sign_message(msg_hash, private_key)
    
    return {
        "message": message,
        "signature": signed_message.signature.hex(),
        "owner_address": owner_address,
        "recipient_address": recipient_address,
        "data_hash": data_hash,
        "expiry_timestamp": expiry_timestamp,
        "human_expiry": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expiry_timestamp))
    }

def verify_signed_consent(message, signature, owner_address, recipient_address):
    """
    Verify a signed consent message
    
    Args:
        message (str): The original consent message
        signature (str): The signature to verify
        owner_address (str): Expected owner's Ethereum address
        recipient_address (str): Expected recipient's Ethereum address
        
    Returns:
        dict: Verification result
    """
    try:
        # Recover the address that signed the message
        msg_hash = encode_defunct(text=message)
        recovered_address = Account.recover_message(msg_hash, signature=signature)
        
        # Check if recovered address matches owner address
        is_valid_signer = (recovered_address.lower() == owner_address.lower())
        
        # Extract expiry timestamp from message
        parts = message.split('until ')
        if len(parts) == 2:
            expiry_timestamp = int(parts[1])
            is_expired = int(time.time()) > expiry_timestamp
        else:
            expiry_timestamp = 0
            is_expired = True
        
        # Check if message mentions correct recipient
        contains_recipient = recipient_address.lower() in message.lower()
        
        return {
            "is_valid": is_valid_signer and contains_recipient and not is_expired,
            "signer_verified": is_valid_signer,
            "recipient_verified": contains_recipient,
            "is_expired": is_expired,
            "expiry_timestamp": expiry_timestamp,
            "recovered_address": recovered_address,
            "human_expiry": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expiry_timestamp)) if expiry_timestamp > 0 else "N/A"
        }
    except Exception as e:
        return {
            "is_valid": False,
            "error": str(e)
        }