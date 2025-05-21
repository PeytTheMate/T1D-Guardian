import hashlib
import json
import hmac
import base64
import time
from datetime import datetime, timedelta
import numpy as np

class ZKGlucoseProof:
    """
    Zero-Knowledge Proof system for T1D glucose data
    
    This is a simplified implementation for educational purposes that demonstrates
    the concept of zero-knowledge proofs. For production use, a formal ZK proof
    library or framework would be required.
    """
    
    def __init__(self, secret_key=None):
        """
        Initialize the ZK proof system with an optional secret key
        
        Args:
            secret_key (bytes, optional): Secret key for HMAC. If None, a random key is generated
        """
        # Generate a random secret key if not provided
        if secret_key is None:
            self.secret_key = hashlib.sha256(str(time.time()).encode()).digest()
        else:
            self.secret_key = secret_key
    
    def generate_proof_below_threshold(self, glucose_data, threshold, date=None):
        """
        Generate a proof that all glucose values for a day are below a threshold
        without revealing the actual values
        
        Args:
            glucose_data (pd.DataFrame): DataFrame with glucose values
            threshold (int): Threshold value (e.g., 150 mg/dL)
            date (str, optional): Specific date to check in YYYY-MM-DD format
        
        Returns:
            dict: The zero-knowledge proof
        """
        # Filter data for the specified date if provided
        if date:
            # Convert timestamp to datetime if it's a string
            if not pd.api.types.is_datetime64_dtype(glucose_data['timestamp']):
                glucose_data = glucose_data.copy()
                glucose_data['timestamp'] = pd.to_datetime(glucose_data['timestamp'])
            
            # Filter to the specific date
            date_obj = pd.to_datetime(date)
            mask = (glucose_data['timestamp'] >= date_obj) & (glucose_data['timestamp'] < date_obj + pd.Timedelta(days=1))
            day_data = glucose_data.loc[mask]
        else:
            day_data = glucose_data
        
        if len(day_data) == 0:
            return {
                "success": False,
                "error": "No data found for the specified date"
            }
        
        # Check if all glucose values are below the threshold
        all_below = all(day_data['glucose_value'] < threshold)
        
        # Count readings and calculate basics stats (revealing aggregate data is ok)
        reading_count = len(day_data)
        max_value = day_data['glucose_value'].max()
        
        # Create commitment using HMAC
        # We include the glucose values in the HMAC but don't reveal them
        glucose_str = ','.join([str(v) for v in day_data['glucose_value']])
        
        # Create HMAC of the glucose values using our secret key
        commitment = hmac.new(
            self.secret_key, 
            glucose_str.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        # For further verification, create a Merkle-tree like structure of the values
        hashed_values = []
        for value in day_data['glucose_value']:
            # Hash each glucose value with the threshold to prove it's below
            if value < threshold:
                h = hashlib.sha256(f"{value}<{threshold}".encode()).hexdigest()
            else:
                h = hashlib.sha256(f"{value}>={threshold}".encode()).hexdigest()
            hashed_values.append(h)
        
        # Combine hashed values in pairs until we get a single root hash
        while len(hashed_values) > 1:
            new_hashes = []
            for i in range(0, len(hashed_values), 2):
                if i + 1 < len(hashed_values):
                    combined = hashed_values[i] + hashed_values[i+1]
                else:
                    combined = hashed_values[i] + hashed_values[i]
                new_hash = hashlib.sha256(combined.encode()).hexdigest()
                new_hashes.append(new_hash)
            hashed_values = new_hashes
        
        merkle_root = hashed_values[0] if hashed_values else None
        
        # Create the proof
        proof = {
            "success": True,
            "all_below_threshold": all_below,
            "threshold": threshold,
            "reading_count": reading_count,
            "date": date,
            "commitment": commitment,
            "merkle_root": merkle_root,
            "max_value": max_value if all_below else "Above threshold",
            "timestamp": datetime.now().isoformat()
        }
        
        return proof
    
    def verify_below_threshold_proof(self, proof, verification_data=None):
        """
        Verify a proof that all glucose values are below threshold
        
        Args:
            proof (dict): The proof to verify
            verification_data (pd.DataFrame, optional): The actual data for verification
                                                       (only needed for full verification)
        
        Returns:
            dict: Verification result
        """
        # Basic verification without the original data
        if not proof.get("success", False):
            return {
                "verified": False,
                "reason": "Proof was not successful"
            }
        
        if "all_below_threshold" not in proof or "threshold" not in proof:
            return {
                "verified": False,
                "reason": "Proof is missing required fields"
            }
        
        # For full verification, we need the original data
        if verification_data is not None:
            # Filter data for the specified date if provided
            if proof.get("date"):
                date_obj = pd.to_datetime(proof["date"])
                mask = (verification_data['timestamp'] >= date_obj) & (verification_data['timestamp'] < date_obj + pd.Timedelta(days=1))
                day_data = verification_data.loc[mask]
            else:
                day_data = verification_data
            
            # Check if all values are below threshold
            all_below = all(day_data['glucose_value'] < proof["threshold"])
            
            # Recalculate commitment
            glucose_str = ','.join([str(v) for v in day_data['glucose_value']])
            
            recalculated_commitment = hmac.new(
                self.secret_key, 
                glucose_str.encode(), 
                hashlib.sha256
            ).hexdigest()
            
            commitment_verified = (recalculated_commitment == proof["commitment"])
            
            # Recalculate Merkle root
            hashed_values = []
            for value in day_data['glucose_value']:
                if value < proof["threshold"]:
                    h = hashlib.sha256(f"{value}<{proof['threshold']}".encode()).hexdigest()
                else:
                    h = hashlib.sha256(f"{value}>={proof['threshold']}".encode()).hexdigest()
                hashed_values.append(h)
            
            # Combine hashed values in pairs until we get a single root hash
            while len(hashed_values) > 1:
                new_hashes = []
                for i in range(0, len(hashed_values), 2):
                    if i + 1 < len(hashed_values):
                        combined = hashed_values[i] + hashed_values[i+1]
                    else:
                        combined = hashed_values[i] + hashed_values[i]
                    new_hash = hashlib.sha256(combined.encode()).hexdigest()
                    new_hashes.append(new_hash)
                hashed_values = new_hashes
            
            merkle_root = hashed_values[0] if hashed_values else None
            merkle_verified = (merkle_root == proof["merkle_root"])
            
            return {
                "verified": all_below == proof["all_below_threshold"] and commitment_verified and merkle_verified,
                "all_below_verified": all_below == proof["all_below_threshold"],
                "commitment_verified": commitment_verified,
                "merkle_verified": merkle_verified,
                "reason": "Full verification completed with original data"
            }
        
        # Limited verification without the original data
        return {
            "verified": True,
            "reason": "Limited verification without original data. Proof format is valid."
        }
    
    def generate_proof_time_in_range(self, glucose_data, lower_bound, upper_bound, date=None, min_percentage=None):
        """
        Generate a proof that time in range is above a certain percentage
        without revealing the actual values
        
        Args:
            glucose_data (pd.DataFrame): DataFrame with glucose values
            lower_bound (int): Lower threshold (e.g., 70 mg/dL)
            upper_bound (int): Upper threshold (e.g., 180 mg/dL)
            date (str, optional): Specific date to check in YYYY-MM-DD format
            min_percentage (float, optional): Minimum percentage of time in range to prove
        
        Returns:
            dict: The zero-knowledge proof
        """
        # Filter data for the specified date if provided
        if date:
            # Convert timestamp to datetime if it's a string
            if not pd.api.types.is_datetime64_dtype(glucose_data['timestamp']):
                glucose_data = glucose_data.copy()
                glucose_data['timestamp'] = pd.to_datetime(glucose_data['timestamp'])
            
            # Filter to the specific date
            date_obj = pd.to_datetime(date)
            mask = (glucose_data['timestamp'] >= date_obj) & (glucose_data['timestamp'] < date_obj + pd.Timedelta(days=1))
            day_data = glucose_data.loc[mask]
        else:
            day_data = glucose_data
        
        if len(day_data) == 0:
            return {
                "success": False,
                "error": "No data found for the specified date"
            }
        
        # Calculate time in range
        in_range = ((day_data['glucose_value'] >= lower_bound) & 
                   (day_data['glucose_value'] <= upper_bound)).sum()
        total = len(day_data)
        tir_percentage = (in_range / total) * 100
        
        # Check if TIR meets the minimum requirement
        meets_minimum = True
        if min_percentage is not None:
            meets_minimum = tir_percentage >= min_percentage
        
        # Create commitment using HMAC
        glucose_str = ','.join([str(v) for v in day_data['glucose_value']])
        
        # Create HMAC of the glucose values
        commitment = hmac.new(
            self.secret_key, 
            glucose_str.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        # Create the proof
        proof = {
            "success": True,
            "time_in_range_percentage": round(tir_percentage, 1),
            "meets_minimum": meets_minimum,
            "minimum_percentage": min_percentage,
            "lower_bound": lower_bound,
            "upper_bound": upper_bound,
            "reading_count": total,
            "date": date,
            "commitment": commitment,
            "timestamp": datetime.now().isoformat()
        }
        
        return proof

    def generate_proof_average_below(self, glucose_data, threshold, date=None):
        """
        Generate a proof that the average glucose is below a threshold
        without revealing individual values
        
        Args:
            glucose_data (pd.DataFrame): DataFrame with glucose values
            threshold (int): Threshold value (e.g., 140 mg/dL)
            date (str, optional): Specific date to check in YYYY-MM-DD format
        
        Returns:
            dict: The zero-knowledge proof
        """
        # Filter data for the specified date if provided
        if date:
            # Convert timestamp to datetime if it's a string
            if not pd.api.types.is_datetime64_dtype(glucose_data['timestamp']):
                glucose_data = glucose_data.copy()
                glucose_data['timestamp'] = pd.to_datetime(glucose_data['timestamp'])
            
            # Filter to the specific date
            date_obj = pd.to_datetime(date)
            mask = (glucose_data['timestamp'] >= date_obj) & (glucose_data['timestamp'] < date_obj + pd.Timedelta(days=1))
            day_data = glucose_data.loc[mask]
        else:
            day_data = glucose_data
        
        if len(day_data) == 0:
            return {
                "success": False,
                "error": "No data found for the specified date"
            }
        
        # Calculate average glucose
        avg_glucose = day_data['glucose_value'].mean()
        avg_below_threshold = avg_glucose < threshold
        
        # Create commitment using HMAC
        glucose_str = ','.join([str(v) for v in day_data['glucose_value']])
        
        # Create HMAC of the glucose values
        commitment = hmac.new(
            self.secret_key, 
            glucose_str.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        # Create the proof
        proof = {
            "success": True,
            "average_below_threshold": avg_below_threshold,
            "threshold": threshold,
            "average": round(avg_glucose, 1) if avg_below_threshold else "Above threshold",
            "reading_count": len(day_data),
            "date": date,
            "commitment": commitment,
            "timestamp": datetime.now().isoformat()
        }
        
        return proof

# Import pandas here to avoid issues with circular imports
import pandas as pd