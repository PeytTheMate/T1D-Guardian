import json
import hashlib
import base64
import time
from datetime import datetime, timedelta
import secrets
from eth_account.messages import encode_defunct
from eth_account import Account
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

class DecentralizedIdentity:
    """
    Simplified implementation of a Decentralized Identity (DID) for T1D patients
    
    This class provides functionality for creating and managing decentralized
    identities that can be used for privacy-preserving verification of patient data.
    """
    
    def __init__(self):
        """Initialize a new DID instance"""
        self.did = None
        self.private_key = None
        self.public_key = None
        self.document = None
        self.ethereum_address = None
    
    def create_identity(self, metadata=None):
        """
        Create a new decentralized identity
        
        Args:
            metadata (dict, optional): Additional metadata for the DID document
            
        Returns:
            dict: The created DID document
        """
        # Generate RSA key pair for signing
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Convert to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Generate Ethereum key for blockchain operations
        eth_private_key = secrets.token_bytes(32)
        eth_account = Account.from_key(eth_private_key)
        eth_address = eth_account.address
        
        # Create a unique DID
        did_seed = base64.b64encode(public_pem).decode('utf-8')
        did_id = "did:t1d:" + hashlib.sha256(did_seed.encode()).hexdigest()[:16]
        
        # Create DID document
        timestamp = datetime.now().isoformat()
        
        document = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": did_id,
            "created": timestamp,
            "updated": timestamp,
            "verificationMethod": [
                {
                    "id": f"{did_id}#keys-1",
                    "type": "RsaVerificationKey2018",
                    "controller": did_id,
                    "publicKeyPem": public_pem.decode('utf-8')
                },
                {
                    "id": f"{did_id}#keys-2",
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "controller": did_id,
                    "ethereumAddress": eth_address
                }
            ],
            "authentication": [
                f"{did_id}#keys-1",
                f"{did_id}#keys-2"
            ],
            "service": [
                {
                    "id": f"{did_id}#t1d-guardian",
                    "type": "T1D-Guardian",
                    "serviceEndpoint": "https://t1d-guardian.app/api/v1"
                }
            ]
        }
        
        # Add optional metadata
        if metadata:
            document["metadata"] = metadata
        
        # Store DID information
        self.did = did_id
        self.private_key = private_pem
        self.public_key = public_pem
        self.document = document
        self.ethereum_address = eth_address
        self.ethereum_private_key = eth_private_key
        
        return document
    
    def sign_data(self, data):
        """
        Sign data using the DID's private key
        
        Args:
            data (dict or str): Data to sign
            
        Returns:
            dict: Signed data with signature
        """
        if not self.private_key:
            raise ValueError("No DID identity has been created or loaded")
        
        # Convert data to string if it's a dictionary
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        
        # Load the private key
        private_key = serialization.load_pem_private_key(
            self.private_key,
            password=None,
            backend=default_backend()
        )
        
        # Create signature
        signature = private_key.sign(
            data_str.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Create a signed data object
        signed_data = {
            "data": data,
            "signature": base64.b64encode(signature).decode('utf-8'),
            "signer": self.did,
            "created": datetime.now().isoformat(),
            "verification_method": f"{self.did}#keys-1"
        }
        
        return signed_data
    
    def verify_signed_data(self, signed_data):
        """
        Verify signed data using the DID's public key
        
        Args:
            signed_data (dict): Signed data to verify
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        # Verify required fields
        required_fields = ["data", "signature", "signer", "verification_method"]
        if not all(field in signed_data for field in required_fields):
            return False
        
        # Get public key from the DID document
        verification_method_id = signed_data["verification_method"]
        
        if self.document:
            # Find the verification method in the local document
            for method in self.document["verificationMethod"]:
                if method["id"] == verification_method_id:
                    public_key_pem = method["publicKeyPem"]
                    break
            else:
                return False
        else:
            # If we don't have the document locally, use the attached public key
            if "public_key_pem" in signed_data:
                public_key_pem = signed_data["public_key_pem"]
            else:
                return False
        
        # Convert data to string if it's a dictionary
        if isinstance(signed_data["data"], dict):
            data_str = json.dumps(signed_data["data"], sort_keys=True)
        else:
            data_str = str(signed_data["data"])
        
        # Decode signature
        signature = base64.b64decode(signed_data["signature"])
        
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8') if isinstance(public_key_pem, str) else public_key_pem,
            backend=default_backend()
        )
        
        # Verify signature
        try:
            public_key.verify(
                signature,
                data_str.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def create_verifiable_credential(self, subject, claims, expiration_days=365):
        """
        Create a verifiable credential for T1D data
        
        Args:
            subject (str): DID of the subject (patient)
            claims (dict): Claims about the subject
            expiration_days (int): Number of days until credential expires
            
        Returns:
            dict: The verifiable credential
        """
        if not self.private_key:
            raise ValueError("No DID identity has been created or loaded")
        
        # Generate credential ID
        credential_id = f"{self.did}#vc-{secrets.token_hex(8)}"
        
        # Set issuance and expiration dates
        issuance_date = datetime.now()
        expiration_date = issuance_date + timedelta(days=expiration_days)
        
        # Create credential
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://t1d-guardian.app/credentials/v1"
            ],
            "id": credential_id,
            "type": ["VerifiableCredential", "T1DGuardianCredential"],
            "issuer": self.did,
            "issuanceDate": issuance_date.isoformat(),
            "expirationDate": expiration_date.isoformat(),
            "credentialSubject": {
                "id": subject,
                "type": "T1DPatient",
                **claims
            }
        }
        
        # Sign the credential
        signed_credential = self.sign_data(credential)
        
        return signed_credential
    
    def create_verifiable_presentation(self, credentials, challenge=None):
        """
        Create a verifiable presentation containing multiple credentials
        
        Args:
            credentials (list): List of verifiable credentials
            challenge (str, optional): Challenge string for authentication
            
        Returns:
            dict: The verifiable presentation
        """
        if not self.private_key:
            raise ValueError("No DID identity has been created or loaded")
        
        # Generate presentation ID
        presentation_id = f"{self.did}#vp-{secrets.token_hex(8)}"
        
        # Create presentation
        presentation = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://t1d-guardian.app/presentations/v1"
            ],
            "id": presentation_id,
            "type": ["VerifiablePresentation", "T1DGuardianPresentation"],
            "holder": self.did,
            "verifiableCredential": credentials
        }
        
        # Add challenge if provided
        if challenge:
            presentation["challenge"] = challenge
        
        # Sign the presentation
        signed_presentation = self.sign_data(presentation)
        
        return signed_presentation
    
    def export_did_document(self):
        """
        Export the DID document as JSON
        
        Returns:
            str: JSON representation of the DID document
        """
        if not self.document:
            raise ValueError("No DID document available")
        
        return json.dumps(self.document, indent=2)
    
    def export_private_key(self, password=None):
        """
        Export the private key, optionally encrypted with a password
        
        Args:
            password (str, optional): Password for encryption
            
        Returns:
            bytes: The exported private key
        """
        if not self.private_key:
            raise ValueError("No private key available")
        
        if password:
            # Load the private key
            private_key = serialization.load_pem_private_key(
                self.private_key,
                password=None,
                backend=default_backend()
            )
            
            # Encrypt with password
            encrypted_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )
            return encrypted_pem
        else:
            return self.private_key
    
    def import_from_json(self, json_data, private_key_pem=None, password=None):
        """
        Import DID from JSON document and optionally private key
        
        Args:
            json_data (str): JSON DID document
            private_key_pem (bytes, optional): PEM-encoded private key
            password (str, optional): Password to decrypt private key
            
        Returns:
            bool: True if import successful
        """
        try:
            # Parse the DID document
            document = json.loads(json_data) if isinstance(json_data, str) else json_data
            
            # Verify it's a valid DID document
            if not ("id" in document and document["id"].startswith("did:")):
                return False
            
            # Set the document
            self.document = document
            self.did = document["id"]
            
            # If private key is provided, set it
            if private_key_pem:
                if password:
                    try:
                        # Try to load with password to verify it's correct
                        serialization.load_pem_private_key(
                            private_key_pem,
                            password=password.encode(),
                            backend=default_backend()
                        )
                    except Exception:
                        return False
                
                self.private_key = private_key_pem
                
                # Extract public key from private key
                private_key = serialization.load_pem_private_key(
                    private_key_pem,
                    password=password.encode() if password else None,
                    backend=default_backend()
                )
                
                public_key = private_key.public_key()
                self.public_key = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            
            # Extract Ethereum address if available
            for method in document.get("verificationMethod", []):
                if "ethereumAddress" in method:
                    self.ethereum_address = method["ethereumAddress"]
                    break
            
            return True
        except Exception as e:
            print(f"Error importing DID: {e}")
            return False


class VerifiableDataRegistry:
    """
    Simple in-memory registry for DIDs and verifiable credentials
    
    In a real implementation, this would interact with a blockchain or
    distributed ledger for storing and retrieving DID documents and
    credential status.
    """
    
    def __init__(self):
        """Initialize the registry"""
        self.did_documents = {}
        self.credential_status = {}
    
    def register_did(self, did_document):
        """
        Register a DID document in the registry
        
        Args:
            did_document (dict): DID document to register
            
        Returns:
            bool: True if registration successful
        """
        if "id" not in did_document:
            return False
        
        did_id = did_document["id"]
        self.did_documents[did_id] = did_document
        return True
    
    def resolve_did(self, did):
        """
        Resolve a DID to its document
        
        Args:
            did (str): DID to resolve
            
        Returns:
            dict: The DID document or None if not found
        """
        return self.did_documents.get(did)
    
    def register_credential_status(self, credential_id, status):
        """
        Register credential status (issued, revoked, etc.)
        
        Args:
            credential_id (str): ID of the credential
            status (dict): Status information
            
        Returns:
            bool: True if registration successful
        """
        self.credential_status[credential_id] = status
        return True
    
    def check_credential_status(self, credential_id):
        """
        Check the status of a credential
        
        Args:
            credential_id (str): ID of the credential
            
        Returns:
            dict: Status information or None if not found
        """
        return self.credential_status.get(credential_id)
    
    def revoke_credential(self, credential_id, reason=None):
        """
        Revoke a credential
        
        Args:
            credential_id (str): ID of the credential to revoke
            reason (str, optional): Reason for revocation
            
        Returns:
            bool: True if revocation successful
        """
        if credential_id not in self.credential_status:
            return False
        
        status = self.credential_status[credential_id]
        status["revoked"] = True
        status["revocationDate"] = datetime.now().isoformat()
        
        if reason:
            status["revocationReason"] = reason
        
        return True