import json
import time
from datetime import datetime
import hashlib
import os
import pandas as pd
from web3 import Web3
from eth_account.messages import encode_defunct
from eth_account import Account

class AuditLogEntry:
    """
    Represents a single entry in the audit log
    """
    def __init__(self, actor, action, data_reference, timestamp=None):
        """
        Create a new audit log entry
        
        Args:
            actor (str): The ID or address of the actor performing the action
            action (str): Description of the action performed
            data_reference (str): Reference to the data affected (e.g., data hash)
            timestamp (float, optional): Unix timestamp, defaults to current time
        """
        self.actor = actor
        self.action = action
        self.data_reference = data_reference
        self.timestamp = timestamp if timestamp is not None else time.time()
        
    def to_dict(self):
        """Convert entry to dictionary"""
        return {
            "actor": self.actor,
            "action": self.action,
            "data_reference": self.data_reference,
            "timestamp": self.timestamp,
            "human_time": datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create entry from dictionary"""
        return cls(
            actor=data.get("actor"),
            action=data.get("action"),
            data_reference=data.get("data_reference"),
            timestamp=data.get("timestamp")
        )


class AuditLog:
    """
    Manages an immutable, verifiable audit log for T1D data access and actions
    """
    def __init__(self, log_file=None):
        """
        Initialize a new audit log
        
        Args:
            log_file (str, optional): Path to the log file
        """
        self.entries = []
        self.log_file = log_file or "t1d_audit_log.json"
        self.load_log()
        
    def load_log(self):
        """Load the log from file if it exists"""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    data = json.load(f)
                    self.entries = [AuditLogEntry.from_dict(entry) for entry in data.get("entries", [])]
            except Exception as e:
                print(f"Error loading audit log: {e}")
    
    def add_entry(self, actor, action, data_reference):
        """
        Add a new entry to the audit log
        
        Args:
            actor (str): The ID or address of the actor performing the action
            action (str): Description of the action performed
            data_reference (str): Reference to the data affected (e.g., data hash)
            
        Returns:
            AuditLogEntry: The created entry
        """
        entry = AuditLogEntry(actor, action, data_reference)
        self.entries.append(entry)
        self.save_log()
        return entry
    
    def save_log(self):
        """Save the log to a file"""
        try:
            log_data = {
                "entries": [entry.to_dict() for entry in self.entries],
                "log_hash": self.calculate_log_hash(),
                "updated_at": datetime.now().isoformat()
            }
            
            with open(self.log_file, 'w') as f:
                json.dump(log_data, f, indent=2)
        except Exception as e:
            print(f"Error saving audit log: {e}")
    
    def calculate_log_hash(self):
        """
        Calculate a hash that represents the entire log state
        
        Returns:
            str: SHA-256 hash of the log
        """
        if not self.entries:
            return ""
            
        # Create a string representation of all entries
        entries_str = json.dumps([entry.to_dict() for entry in self.entries], sort_keys=True)
        
        # Calculate hash
        return hashlib.sha256(entries_str.encode()).hexdigest()
    
    def get_entries_for_actor(self, actor):
        """
        Get all entries for a specific actor
        
        Args:
            actor (str): Actor ID or address
            
        Returns:
            list: List of entries
        """
        return [entry for entry in self.entries if entry.actor == actor]
    
    def get_entries_for_data(self, data_reference):
        """
        Get all entries for a specific data reference
        
        Args:
            data_reference (str): Data reference (e.g., hash)
            
        Returns:
            list: List of entries
        """
        return [entry for entry in self.entries if entry.data_reference == data_reference]
    
    def get_entries_for_timeframe(self, start_time, end_time):
        """
        Get all entries within a specific timeframe
        
        Args:
            start_time (float): Start timestamp
            end_time (float): End timestamp
            
        Returns:
            list: List of entries
        """
        return [
            entry for entry in self.entries 
            if start_time <= entry.timestamp <= end_time
        ]
    
    def get_all_entries(self):
        """
        Get all entries in the log
        
        Returns:
            list: List of all entries as dictionaries
        """
        return [entry.to_dict() for entry in self.entries]
    
    def to_dataframe(self):
        """
        Convert the audit log to a pandas DataFrame
        
        Returns:
            pd.DataFrame: Audit log as a DataFrame
        """
        return pd.DataFrame([entry.to_dict() for entry in self.entries])


class BlockchainAuditLog(AuditLog):
    """
    Extends AuditLog with blockchain verification capabilities
    """
    def __init__(self, log_file=None, infura_api_key=None):
        """
        Initialize a blockchain-backed audit log
        
        Args:
            log_file (str, optional): Path to the log file
            infura_api_key (str, optional): Infura API key for Ethereum connection
        """
        super().__init__(log_file)
        self.infura_api_key = infura_api_key
        self.blockchain_records = []
        
    def connect_to_ethereum(self):
        """
        Connect to Ethereum network
        
        Returns:
            Web3: Web3 connection or None if failed
        """
        if not self.infura_api_key:
            print("No Infura API key provided")
            return None
            
        try:
            w3 = Web3(Web3.HTTPProvider(f"https://sepolia.infura.io/v3/{self.infura_api_key}"))
            if not w3.is_connected():
                print("Failed to connect to Ethereum network")
                return None
            return w3
        except Exception as e:
            print(f"Error connecting to Ethereum: {e}")
            return None
    
    def add_entry_with_blockchain(self, actor, action, data_reference, private_key):
        """
        Add an entry to the log and record it on blockchain
        
        Args:
            actor (str): The ID or address of the actor
            action (str): Description of the action
            data_reference (str): Reference to the data
            private_key (str): Ethereum private key for signing
            
        Returns:
            dict: Entry information with blockchain record
        """
        # Add entry to local log
        entry = self.add_entry(actor, action, data_reference)
        
        # Connect to Ethereum
        w3 = self.connect_to_ethereum()
        if not w3:
            return {"entry": entry.to_dict(), "blockchain": {"success": False, "error": "No Ethereum connection"}}
        
        try:
            # Get account from private key
            account = Account.from_key(private_key)
            address = account.address
            
            # Create log entry message
            log_data = entry.to_dict()
            message = (
                f"T1D-Guardian Audit Log Entry:\n"
                f"Actor: {log_data['actor']}\n"
                f"Action: {log_data['action']}\n"
                f"Data Reference: {log_data['data_reference']}\n"
                f"Timestamp: {log_data['timestamp']}\n"
                f"Log Hash: {self.calculate_log_hash()}"
            )
            
            # Sign message
            message_encoded = encode_defunct(text=message)
            signed_message = w3.eth.account.sign_message(message_encoded, private_key=private_key)
            
            # Get the latest transaction count
            nonce = w3.eth.get_transaction_count(address)
            
            # Create a simple transaction that stores data in the input field
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
            
            # Save blockchain record
            blockchain_record = {
                "tx_hash": w3.to_hex(tx_hash),
                "entry_hash": hashlib.sha256(json.dumps(log_data, sort_keys=True).encode()).hexdigest(),
                "timestamp": time.time(),
                "human_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            self.blockchain_records.append(blockchain_record)
            
            # Save the updated log
            self.save_log()
            
            return {
                "entry": entry.to_dict(),
                "blockchain": {
                    "success": True,
                    "tx_hash": blockchain_record["tx_hash"]
                }
            }
            
        except Exception as e:
            return {"entry": entry.to_dict(), "blockchain": {"success": False, "error": str(e)}}
    
    def verify_blockchain_records(self):
        """
        Verify all blockchain records in the log
        
        Returns:
            list: Verification results for each record
        """
        # Connect to Ethereum
        w3 = self.connect_to_ethereum()
        if not w3:
            return [{"verified": False, "error": "No Ethereum connection"} for _ in self.blockchain_records]
        
        results = []
        
        for record in self.blockchain_records:
            try:
                # Get transaction data
                tx_hash = record["tx_hash"]
                tx = w3.eth.get_transaction(tx_hash)
                
                # Extract data from transaction
                if tx and tx.input:
                    # Convert from hex to text
                    data_text = w3.to_text(tx.input)
                    
                    # Basic verification - check if it contains audit log entry text
                    if "T1D-Guardian Audit Log Entry:" in data_text:
                        results.append({
                            "tx_hash": tx_hash,
                            "verified": True,
                            "data": data_text,
                            "block_number": tx.blockNumber,
                            "block_time": w3.eth.get_block(tx.blockNumber).timestamp
                        })
                    else:
                        results.append({"tx_hash": tx_hash, "verified": False, "error": "Invalid data format"})
                else:
                    results.append({"tx_hash": tx_hash, "verified": False, "error": "No transaction data"})
                    
            except Exception as e:
                results.append({"tx_hash": record["tx_hash"], "verified": False, "error": str(e)})
        
        return results
    
    def verify_single_record(self, tx_hash):
        """
        Verify a single blockchain record
        
        Args:
            tx_hash (str): Transaction hash
            
        Returns:
            dict: Verification result
        """
        # Connect to Ethereum
        w3 = self.connect_to_ethereum()
        if not w3:
            return {"verified": False, "error": "No Ethereum connection"}
        
        try:
            # Get transaction data
            tx = w3.eth.get_transaction(tx_hash)
            
            # Extract data from transaction
            if tx and tx.input:
                # Convert from hex to text
                data_text = w3.to_text(tx.input)
                
                # Basic verification - check if it contains audit log entry text
                if "T1D-Guardian Audit Log Entry:" in data_text:
                    return {
                        "tx_hash": tx_hash,
                        "verified": True,
                        "data": data_text,
                        "block_number": tx.blockNumber,
                        "block_time": w3.eth.get_block(tx.blockNumber).timestamp
                    }
                else:
                    return {"tx_hash": tx_hash, "verified": False, "error": "Invalid data format"}
            else:
                return {"tx_hash": tx_hash, "verified": False, "error": "No transaction data"}
                
        except Exception as e:
            return {"tx_hash": tx_hash, "verified": False, "error": str(e)}
    
    def save_log(self):
        """Save the log with blockchain records to a file"""
        try:
            log_data = {
                "entries": [entry.to_dict() for entry in self.entries],
                "blockchain_records": self.blockchain_records,
                "log_hash": self.calculate_log_hash(),
                "updated_at": datetime.now().isoformat()
            }
            
            with open(self.log_file, 'w') as f:
                json.dump(log_data, f, indent=2)
        except Exception as e:
            print(f"Error saving audit log: {e}")
    
    def load_log(self):
        """Load the log with blockchain records from file"""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    data = json.load(f)
                    self.entries = [AuditLogEntry.from_dict(entry) for entry in data.get("entries", [])]
                    self.blockchain_records = data.get("blockchain_records", [])
            except Exception as e:
                print(f"Error loading audit log: {e}")