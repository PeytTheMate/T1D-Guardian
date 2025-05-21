import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import os
from datetime import datetime, timedelta
import tempfile
import time
import json
import base64

from data_processor import preprocess_dexcom_data, engineer_features
from ai_model import train_model, predict_hypoglycemia_risk, predict_glucose_future
from encryption import encrypt_data, decrypt_data, generate_key
from blockchain import generate_hash, store_hash_on_blockchain, verify_hash
from utils import display_glucose_stats, time_in_range
from pdf_generator import generate_diabetes_report
from smart_contract import create_consent_record, verify_consent, create_signed_consent_message
from zk_proof import ZKGlucoseProof
from did_identity import DecentralizedIdentity, VerifiableDataRegistry
from audit_log import AuditLog, BlockchainAuditLog, AuditLogEntry


# The page settings
st.set_page_config(
    page_title="T1D-Guardian",
    page_icon="🩸",
    layout="wide",
)

# Title and description
st.title("T1D-Guardian")
st.markdown("### A Privacy-Preserving Type 1 Diabetes Analytics System")
st.markdown("""
This application helps Type 1 diabetes patients analyze their glucose data,
providing insights and predictions while ensuring data privacy through encryption and blockchain verification.
""")

# Initialize the session-state variables 
# I feel like I'm in my first CS class again writing so many unnecessary if statement

if 'data' not in st.session_state:
    st.session_state.data = None
if 'processed_data' not in st.session_state:
    st.session_state.processed_data = None
if 'encryption_key' not in st.session_state:
    st.session_state.encryption_key = None
if 'model' not in st.session_state:
    st.session_state.model = None
if 'predictions' not in st.session_state:
    st.session_state.predictions = None
if 'data_hash' not in st.session_state:
    st.session_state.data_hash = None
if 'blockchain_tx' not in st.session_state:
    st.session_state.blockchain_tx = None
if 'audit_log' not in st.session_state:
    st.session_state.audit_log = AuditLog(log_file="t1d_guardian_audit_log.json")
if 'user_role' not in st.session_state:
    st.session_state.user_role = "patient"  # Default role is patient, can be "healthcare_provider"
if 'user_id' not in st.session_state:
    st.session_state.user_id = "patient_1"  # Default user ID, would be set during login in a real app

# Sidebar to upload data and see controls
with st.sidebar:
    st.header("Data Controls")
    
    # Data upload section
    st.subheader("Upload Data")
    uploaded_file = st.file_uploader("Upload Dexcom CSV data", type=["csv"])
    
    if uploaded_file is not None:
        try:
            # Save the data to session state
            df = pd.read_csv(uploaded_file)
            st.session_state.data = df
            st.success("Data uploaded successfully!")
        except Exception as e:
            st.error(f"Error loading data: {e}")
    
    # Encrypted key generation
    st.subheader("Data Encryption")
    if st.button("Generate New Encryption Key"):
        st.session_state.encryption_key = generate_key()
        st.success("New encryption key generated!")
    
    # Saving the current encryption key
    if st.session_state.encryption_key is not None:
        if st.download_button(
            label="Download Encryption Key",
            data=st.session_state.encryption_key,
            file_name="t1d_guardian_key.bin",
            mime="application/octet-stream"
        ):
            st.info("Keep this key safe. You'll need it to decrypt your data.")
    
    # To import an existing key
    uploaded_key = st.file_uploader("Upload existing encryption key", type=["bin"])
    if uploaded_key is not None:
        st.session_state.encryption_key = uploaded_key.read()
        st.success("Encryption key loaded!")

# Main
if st.session_state.data is not None:
    # Tabs navigation
    tabs = st.tabs(["Data Overview", "Analytics", "AI Insights", "Security & Verification"])
    
    with tabs[0]:
        st.header("Data Overview")
        st.write("Preview of your uploaded Dexcom data:")
        st.dataframe(st.session_state.data.head())
        
        # Process data button
        if st.button("Preprocess Data"):
            with st.spinner("Processing data..."):
                try:
                    # Preprocess the data
                    st.session_state.processed_data = preprocess_dexcom_data(st.session_state.data)
                    # Engineer additional features
                    st.session_state.processed_data = engineer_features(st.session_state.processed_data)
                    st.success("Data processed successfully!")
                except Exception as e:
                    st.error(f"Error processing data: {e}")
        
        # Show processed data if available
        if st.session_state.processed_data is not None:
            st.subheader("Processed Data")
            st.dataframe(st.session_state.processed_data.head())
            
            # Basic statistics about the glucose data
            if 'glucose_value' in st.session_state.processed_data.columns:
                st.subheader("Glucose Statistics")
                stats = display_glucose_stats(st.session_state.processed_data)
                
                # Create columns for displaying statistics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Average Glucose", f"{stats['avg_glucose']:.1f} mg/dL")
                with col2:
                    st.metric("Min Glucose", f"{stats['min_glucose']:.1f} mg/dL")
                with col3:
                    st.metric("Max Glucose", f"{stats['max_glucose']:.1f} mg/dL")
                
                # Time in range metrics
                tir_stats = time_in_range(st.session_state.processed_data)
                st.subheader("Time in Range")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Below Range (<70 mg/dL)", f"{tir_stats['below_range']:.1f}%")
                with col2:
                    st.metric("In Range (70-180 mg/dL)", f"{tir_stats['in_range']:.1f}%")
                with col3:
                    st.metric("Above Range (>180 mg/dL)", f"{tir_stats['above_range']:.1f}%")
                
                # Glucose trend plot
                st.subheader("Glucose Trend")
                fig = px.line(
                    st.session_state.processed_data, 
                    x='timestamp', 
                    y='glucose_value',
                    title="Glucose Readings Over Time"
                )
                
                # Add range threshold lines
                fig.add_hline(y=70, line_dash="dash", line_color="red", annotation_text="Low")
                fig.add_hline(y=180, line_dash="dash", line_color="red", annotation_text="High")
                
                st.plotly_chart(fig, use_container_width=True)
    
    with tabs[1]:
        st.header("Analytics")
        
        if st.session_state.processed_data is None:
            st.warning("Please process your data first on the Data Overview tab.")
        else:
            # Daily patterns section
            st.subheader("Daily Glucose Patterns")
            
            # Convert timestamp to hour of day for analysis
            if 'hour_of_day' not in st.session_state.processed_data.columns:
                st.session_state.processed_data['hour_of_day'] = pd.to_datetime(st.session_state.processed_data['timestamp']).dt.hour
            
            # Group by hour and calculate mean glucose
            hourly_data = st.session_state.processed_data.groupby('hour_of_day')['glucose_value'].mean().reset_index()
            
            # Create hourly pattern plot
            fig = px.line(
                hourly_data, 
                x='hour_of_day', 
                y='glucose_value',
                title="Average Glucose by Hour of Day",
                labels={"hour_of_day": "Hour of Day", "glucose_value": "Average Glucose (mg/dL)"}
            )
            fig.update_layout(xaxis=dict(tickmode='linear', tick0=0, dtick=2))
            st.plotly_chart(fig, use_container_width=True)
            
            # Glucose distribution histogram
            st.subheader("Glucose Distribution")
            fig = px.histogram(
                st.session_state.processed_data, 
                x='glucose_value',
                nbins=30,
                title="Distribution of Glucose Values",
                labels={"glucose_value": "Glucose (mg/dL)"}
            )
            
            # Add range rectangle highlights
            fig.add_vrect(x0=70, x1=180, fillcolor="green", opacity=0.2, line_width=0)
            fig.add_vrect(x0=0, x1=70, fillcolor="red", opacity=0.2, line_width=0)
            fig.add_vrect(x0=180, x1=400, fillcolor="orange", opacity=0.2, line_width=0)
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Rate of change analysis
            if 'glucose_rate_of_change' in st.session_state.processed_data.columns:
                st.subheader("Glucose Rate of Change Analysis")
                
                # Distribution of rate of change
                fig = px.histogram(
                    st.session_state.processed_data, 
                    x='glucose_rate_of_change',
                    nbins=30,
                    title="Distribution of Glucose Rate of Change",
                    labels={"glucose_rate_of_change": "Rate of Change (mg/dL/min)"}
                )
                
                # Add vertical line at 0
                fig.add_vline(x=0, line_dash="solid", line_color="black")
                
                st.plotly_chart(fig, use_container_width=True)
    
    with tabs[2]:
        st.header("AI Insights")
        
        if st.session_state.processed_data is None:
            st.warning("Please process your data first on the Data Overview tab.")
        else:
            # Train model button
            if st.button("Train AI Model"):
                with st.spinner("Training model... This may take a minute"):
                    try:
                        # Train the predictive model
                        st.session_state.model = train_model(st.session_state.processed_data)
                        st.success("AI model trained successfully!")
                    except Exception as e:
                        st.error(f"Error training model: {e}")
            
            # Generate predictions if model exists
            if st.session_state.model is not None:
                st.subheader("Glucose Predictions")
                
                # Make predictions
                with st.spinner("Generating predictions..."):
                    try:
                        # Get hypoglycemia risk predictions
                        hypo_risk = predict_hypoglycemia_risk(
                            st.session_state.model,
                            st.session_state.processed_data
                        )
                        
                        # Get future glucose predictions
                        future_glucose = predict_glucose_future(
                            st.session_state.model,
                            st.session_state.processed_data
                        )
                        
                        # Store predictions in session state
                        st.session_state.predictions = {
                            'hypo_risk': hypo_risk,
                            'future_glucose': future_glucose
                        }
                        
                        # Display predictions
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            # Hypoglycemia risk gauge
                            max_risk = np.max(hypo_risk)
                            fig = go.Figure(go.Indicator(
                                mode = "gauge+number",
                                value = max_risk * 100,
                                title = {'text': "Hypoglycemia Risk (Next 30 min)"},
                                gauge = {
                                    'axis': {'range': [0, 100]},
                                    'bar': {'color': "darkblue"},
                                    'steps': [
                                        {'range': [0, 30], 'color': "green"},
                                        {'range': [30, 70], 'color': "yellow"},
                                        {'range': [70, 100], 'color': "red"}
                                    ],
                                    'threshold': {
                                        'line': {'color': "red", 'width': 4},
                                        'thickness': 0.75,
                                        'value': max_risk * 100
                                    }
                                }
                            ))
                            st.plotly_chart(fig, use_container_width=True)
                        
                        with col2:
                            # Future glucose prediction
                            last_row = st.session_state.processed_data.iloc[-1]
                            current_glucose = last_row['glucose_value']
                            predicted_glucose = future_glucose[-1]
                            
                            fig = go.Figure(go.Indicator(
                                mode = "number+delta",
                                value = predicted_glucose,
                                title = {'text': "Predicted Glucose (30 min)"},
                                delta = {'reference': current_glucose, 'relative': False},
                                number = {'suffix': " mg/dL"}
                            ))
                            st.plotly_chart(fig, use_container_width=True)
                        
                        # Get recommendations based on predictions
                        st.subheader("AI Recommendations")
                        
                        if max_risk > 0.7:
                            st.error("⚠️ High risk of hypoglycemia in the next 30 minutes. Consider consuming carbohydrates.")
                        elif max_risk > 0.3:
                            st.warning("⚠️ Moderate risk of hypoglycemia. Monitor your glucose closely.")
                        else:
                            st.success("✅ Low risk of hypoglycemia in the next 30 minutes.")
                        
                        if predicted_glucose > 250:
                            st.error("⚠️ Glucose trending very high. Check for ketones and consider correction.")
                        elif predicted_glucose > 180:
                            st.warning("⚠️ Glucose trending above target range. Consider correction if not recently eaten.")
                        elif predicted_glucose < 70:
                            st.error("⚠️ Glucose trending below range. Consider consuming 15g of fast-acting carbohydrates.")
                        else:
                            st.success("✅ Glucose prediction within target range.")
                            
                        # Encrypt predictions if key is available
                        if st.session_state.encryption_key is not None:
                            if st.button("Encrypt Predictions"):
                                with st.spinner("Encrypting predictions..."):
                                    try:
                                        # Convert predictions to JSON string
                                        pred_json = json.dumps(str(st.session_state.predictions))
                                        # Encrypt data
                                        encrypted_data = encrypt_data(pred_json, st.session_state.encryption_key)
                                        # Calculate hash for blockchain
                                        st.session_state.data_hash = generate_hash(encrypted_data)
                                        
                                        # Offer download of encrypted data
                                        st.download_button(
                                            label="Download Encrypted Predictions",
                                            data=encrypted_data,
                                            file_name="t1d_predictions.bin",
                                            mime="application/octet-stream"
                                        )
                                        
                                        st.success("Predictions encrypted successfully!")
                                        st.info(f"Data Hash: {st.session_state.data_hash}")
                                    except Exception as e:
                                        st.error(f"Error encrypting data: {e}")
                    except Exception as e:
                        st.error(f"Error generating predictions: {e}")
            else:
                st.info("Please train the AI model first to view predictions.")
    
    with tabs[3]:
        st.header("Security & Verification")
        
        # Create subtabs for different security features
        security_tabs = st.tabs(["Data Integrity", "PDF Reports", "Smart Contracts", "Zero-Knowledge Proofs", "Digital Identity", "Audit Log"])
        
        with security_tabs[0]:
            st.subheader("Blockchain Data Integrity")
            
            # Display data hash if available
            if st.session_state.data_hash:
                st.info("Your data has a unique digital fingerprint (hash):")
                st.code(st.session_state.data_hash)
                
                # Option to store hash on blockchain
                if st.button("Store Hash on Blockchain"):
                    with st.spinner("Storing hash on Ethereum Sepolia testnet..."):
                        try:
                            # Get Ethereum connection details from environment
                            infura_key = os.getenv("INFURA_API_KEY")
                            private_key = os.getenv("ETH_PRIVATE_KEY")
                            
                            if not infura_key or not private_key:
                                st.error("Missing Ethereum API keys. Please provide your Ethereum credentials.")
                                # Add fields for users to enter their own keys
                                infura_key = st.text_input("Infura API Key", type="password")
                                private_key = st.text_input("Ethereum Private Key", type="password")
                                
                                if infura_key and private_key and st.button("Submit Keys and Store Hash"):
                                    # Store hash on blockchain
                                    tx_hash = store_hash_on_blockchain(
                                        st.session_state.data_hash,
                                        infura_key,
                                        private_key
                                    )
                                    
                                    # Save transaction hash
                                    st.session_state.blockchain_tx = tx_hash
                                    
                                    st.success(f"Hash stored on Ethereum Sepolia testnet!")
                                    st.code(f"Transaction Hash: {tx_hash}")
                            else:
                                # Store hash on blockchain
                                tx_hash = store_hash_on_blockchain(
                                    st.session_state.data_hash,
                                    infura_key,
                                    private_key
                                )
                                
                                # Save transaction hash
                                st.session_state.blockchain_tx = tx_hash
                                
                                st.success(f"Hash stored on Ethereum Sepolia testnet!")
                                st.code(f"Transaction Hash: {tx_hash}")
                        except Exception as e:
                            st.error(f"Error storing hash on blockchain: {e}")
            
            # Data verification section
            st.subheader("Verify Encrypted Data")
            
            # Upload encrypted file
            encrypted_file = st.file_uploader("Upload encrypted data file", type=["bin"])
            verification_key = st.file_uploader("Upload encryption key for verification", type=["bin"])
            
            if encrypted_file is not None and verification_key is not None:
                encrypted_data = encrypted_file.read()
                key_data = verification_key.read()
                
                # Calculate hash of uploaded file
                file_hash = generate_hash(encrypted_data)
                st.info(f"File Hash: {file_hash}")
                
                # Attempt to decrypt data
                if st.button("Decrypt and Verify"):
                    with st.spinner("Decrypting and verifying data..."):
                        try:
                            # Decrypt data
                            decrypted_data = decrypt_data(encrypted_data, key_data)
                            
                            # Display decrypted data
                            st.success("Data decrypted successfully!")
                            st.json(decrypted_data)
                            
                        except Exception as e:
                            st.error(f"Error decrypting data: {e}")
            
            # Blockchain verification section
            st.subheader("Verify Blockchain Record")
            
            # Input for transaction hash
            tx_hash_input = st.text_input("Ethereum Transaction Hash", value=st.session_state.blockchain_tx if st.session_state.blockchain_tx else "")
            
            if tx_hash_input:
                if st.button("Verify Blockchain Record"):
                    with st.spinner("Verifying blockchain record..."):
                        try:
                            # Get Infura key from environment
                            infura_key = os.getenv("INFURA_API_KEY")
                            
                            if not infura_key:
                                st.error("Missing Infura API key. Please provide your Infura API key.")
                                infura_key = st.text_input("Infura API Key for Verification", type="password")
                                
                                if infura_key and st.button("Verify with Provided Key"):
                                    # Verify hash on blockchain
                                    verification_result = verify_hash(tx_hash_input, infura_key)
                                    
                                    if verification_result:
                                        st.success("Blockchain record verified!")
                                        st.json(verification_result)
                                    else:
                                        st.error("Could not verify blockchain record.")
                            else:
                                # Verify hash on blockchain
                                verification_result = verify_hash(tx_hash_input, infura_key)
                                
                                if verification_result:
                                    st.success("Blockchain record verified!")
                                    st.json(verification_result)
                                else:
                                    st.error("Could not verify blockchain record.")
                        except Exception as e:
                            st.error(f"Error verifying hash: {e}")
                            
        with security_tabs[1]:
            st.subheader("Generate Medical PDF Report")
            
            if st.session_state.processed_data is None:
                st.warning("Please process your data first to generate a PDF report.")
            else:
                # PDF generation options
                st.write("Create a secure, encrypted PDF report of your diabetes data")
                
                # Patient info (minimal to protect privacy)
                st.write("Optional: Add basic patient information")
                patient_id = st.text_input("Patient ID (non-identifying)")
                birth_year = st.number_input("Year of Birth", min_value=1900, max_value=datetime.now().year, value=2000)
                diagnosis_year = st.number_input("Year of Diagnosis", min_value=1900, max_value=datetime.now().year, value=2010)
                
                patient_info = {
                    "patient_id": patient_id,
                    "birth_year": birth_year,
                    "diagnosis_year": diagnosis_year,
                    "report_date": datetime.now().strftime("%Y-%m-%d"),
                }
                
                # Include blockchain verification if available
                include_verification = st.checkbox("Include blockchain verification", value=True)
                
                if st.button("Generate PDF Report"):
                    with st.spinner("Generating PDF report..."):
                        try:
                            # Generate the report
                            metadata = {"patient_info": patient_info} if patient_id else None
                            data_hash = st.session_state.data_hash if include_verification and st.session_state.data_hash else None
                            encryption_info = {"encrypted": True} if st.session_state.encryption_key is not None else None
                            
                            pdf_bytes = generate_diabetes_report(
                                st.session_state.processed_data,
                                metadata=metadata,
                                data_hash=data_hash,
                                encryption_info=encryption_info
                            )
                            
                            # Offer download
                            st.success("PDF report generated successfully!")
                            st.download_button(
                                label="Download PDF Report",
                                data=pdf_bytes,
                                file_name=f"t1d_report_{datetime.now().strftime('%Y%m%d')}.pdf",
                                mime="application/pdf"
                            )
                        except Exception as e:
                            st.error(f"Error generating PDF report: {e}")
                
        with security_tabs[2]:
            st.subheader("Smart Contract for Data Consent")
            
            st.write("Create and manage consent records for sharing your diabetes data")
            
            # Option to create a new consent record
            st.write("#### Create a Consent Record")
            st.write("This will record your consent to share data with a healthcare provider or researcher")
            
            # Get recipient details
            recipient_address = st.text_input("Recipient Ethereum Address (healthcare provider)")
            expiry_days = st.slider("Consent Duration (days)", 1, 365, 30)
            data_description = st.text_area("Data Description", "CGM data from T1D-Guardian")
            
            # Create a signed consent message (off-chain)
            if st.button("Create Consent Record"):
                with st.spinner("Creating consent record..."):
                    try:
                        # Calculate data hash if not already done
                        if st.session_state.processed_data is not None and not st.session_state.data_hash:
                            data_str = json.dumps(str(st.session_state.processed_data.to_dict()))
                            if st.session_state.encryption_key:
                                encrypted_data = encrypt_data(data_str, st.session_state.encryption_key)
                                st.session_state.data_hash = generate_hash(encrypted_data)
                            else:
                                st.session_state.data_hash = generate_hash(data_str)
                        
                        if not st.session_state.data_hash:
                            st.error("No data hash available. Please process data first.")
                        elif not recipient_address or not recipient_address.startswith("0x"):
                            st.error("Please enter a valid Ethereum address for the recipient")
                        else:
                            # Get Ethereum private key (in production, would use a secure wallet)
                            eth_private_key = os.getenv("ETH_PRIVATE_KEY")
                            
                            if not eth_private_key:
                                st.error("Missing Ethereum private key. Please provide your private key to sign the consent.")
                                eth_private_key = st.text_input("Ethereum Private Key for Signing", type="password")
                                
                                if eth_private_key and st.button("Sign With Provided Key"):
                                    # Create off-chain signed consent
                                    signed_consent = create_signed_consent_message(
                                        eth_private_key,
                                        recipient_address,
                                        st.session_state.data_hash,
                                        expiry_days
                                    )
                                    
                                    st.success("Consent record created and signed!")
                                    st.json(signed_consent)
                                    
                                    # Export consent as JSON
                                    consent_json = json.dumps(signed_consent)
                                    st.download_button(
                                        label="Download Consent Record",
                                        data=consent_json,
                                        file_name=f"t1d_consent_{datetime.now().strftime('%Y%m%d')}.json",
                                        mime="application/json"
                                    )
                            else:
                                # Create off-chain signed consent
                                signed_consent = create_signed_consent_message(
                                    eth_private_key,
                                    recipient_address,
                                    st.session_state.data_hash,
                                    expiry_days
                                )
                                
                                st.success("Consent record created and signed!")
                                st.json(signed_consent)
                                
                                # Export consent as JSON
                                consent_json = json.dumps(signed_consent)
                                st.download_button(
                                    label="Download Consent Record",
                                    data=consent_json,
                                    file_name=f"t1d_consent_{datetime.now().strftime('%Y%m%d')}.json",
                                    mime="application/json"
                                )
                    except Exception as e:
                        st.error(f"Error creating consent record: {e}")
            
            # Verify consent records
            st.write("#### Verify Consent Record")
            uploaded_consent = st.file_uploader("Upload consent record to verify", type=["json"])
            
            if uploaded_consent:
                try:
                    consent_data = json.load(uploaded_consent)
                    st.write("Consent Record Details:")
                    st.json(consent_data)
                    
                    # Verification requires Ethereum interaction
                    if st.button("Verify Signature"):
                        try:
                            # Extract verification parameters
                            message = consent_data.get("message")
                            signature = consent_data.get("signature")
                            owner_address = consent_data.get("owner_address")
                            recipient_address = consent_data.get("recipient_address")
                            
                            if message and signature and owner_address and recipient_address:
                                # Create Ethereum connection
                                from eth_account.messages import encode_defunct
                                from eth_account import Account
                                
                                # Verify signature
                                msg_hash = encode_defunct(text=message)
                                recovered_address = Account.recover_message(msg_hash, signature=signature)
                                
                                if recovered_address.lower() == owner_address.lower():
                                    st.success("✅ Signature verified! This consent record is authentic.")
                                    
                                    # Check if expired
                                    expiry = consent_data.get("expiry_timestamp", 0)
                                    if expiry < time.time():
                                        st.warning("⚠️ This consent has expired!")
                                    else:
                                        st.info(f"Consent valid until: {consent_data.get('human_expiry')}")
                                else:
                                    st.error("❌ Invalid signature! This consent record may be tampered with.")
                            else:
                                st.error("Missing required fields in the consent record")
                        except Exception as e:
                            st.error(f"Error verifying consent: {e}")
                except Exception as e:
                    st.error(f"Error parsing consent record: {e}")
            
        with security_tabs[3]:
            st.subheader("Zero-Knowledge Proofs")
            
            st.write("""
            Zero-knowledge proofs allow you to prove facts about your diabetes data without revealing the actual data.
            For example, you can prove your glucose stayed below a certain threshold without showing the actual values.
            """)
            
            if st.session_state.processed_data is None:
                st.warning("Please process your data first to create zero-knowledge proofs.")
            else:
                # Initialize ZK proof system if needed
                if 'zk_proof_system' not in st.session_state:
                    st.session_state.zk_proof_system = ZKGlucoseProof()
                
                # Create proof options
                st.write("#### Create a Zero-Knowledge Proof")
                proof_type = st.selectbox(
                    "Select proof type",
                    ["All values below threshold", "Time in range percentage", "Average glucose below threshold"]
                )
                
                if proof_type == "All values below threshold":
                    threshold = st.slider("Glucose threshold (mg/dL)", 70, 250, 150)
                    
                    # Date selection (optional)
                    use_specific_date = st.checkbox("Specify a date")
                    selected_date = None
                    if use_specific_date:
                        # Get date range from data
                        data_dates = pd.to_datetime(st.session_state.processed_data['timestamp']).dt.date.unique()
                        if len(data_dates) > 0:
                            min_date = min(data_dates)
                            max_date = max(data_dates)
                            selected_date = st.date_input("Select date", min(data_dates), min_value=min_date, max_value=max_date)
                            selected_date = selected_date.strftime("%Y-%m-%d")
                    
                    if st.button("Generate Proof"):
                        with st.spinner("Generating zero-knowledge proof..."):
                            proof = st.session_state.zk_proof_system.generate_proof_below_threshold(
                                st.session_state.processed_data,
                                threshold,
                                date=selected_date
                            )
                            
                            if proof["success"]:
                                if proof["all_below_threshold"]:
                                    st.success(f"✅ Proof generated: All glucose values are below {threshold} mg/dL")
                                else:
                                    st.warning(f"⚠️ Proof generated: Not all glucose values are below {threshold} mg/dL")
                                
                                # Display proof details
                                st.write(f"Reading count: {proof['reading_count']}")
                                st.write(f"Date: {proof['date'] or 'All data'}")
                                
                                # Download proof as JSON
                                proof_json = json.dumps(proof)
                                st.download_button(
                                    label="Download ZK Proof",
                                    data=proof_json,
                                    file_name=f"zk_proof_below_{threshold}_{datetime.now().strftime('%Y%m%d')}.json",
                                    mime="application/json"
                                )
                            else:
                                st.error(f"Error generating proof: {proof.get('error', 'Unknown error')}")
                
                elif proof_type == "Time in range percentage":
                    lower_bound = st.slider("Lower bound (mg/dL)", 30, 100, 70)
                    upper_bound = st.slider("Upper bound (mg/dL)", 120, 300, 180)
                    min_percentage = st.slider("Minimum time in range percentage", 0, 100, 70)
                    
                    # Date selection (optional)
                    use_specific_date = st.checkbox("Specify a date")
                    selected_date = None
                    if use_specific_date:
                        # Get date range from data
                        data_dates = pd.to_datetime(st.session_state.processed_data['timestamp']).dt.date.unique()
                        if len(data_dates) > 0:
                            min_date = min(data_dates)
                            max_date = max(data_dates)
                            selected_date = st.date_input("Select date", min(data_dates), min_value=min_date, max_value=max_date)
                            selected_date = selected_date.strftime("%Y-%m-%d")
                    
                    if st.button("Generate Proof"):
                        with st.spinner("Generating zero-knowledge proof..."):
                            proof = st.session_state.zk_proof_system.generate_proof_time_in_range(
                                st.session_state.processed_data,
                                lower_bound,
                                upper_bound,
                                date=selected_date,
                                min_percentage=min_percentage
                            )
                            
                            if proof["success"]:
                                if proof["meets_minimum"]:
                                    st.success(f"✅ Proof generated: Time in range is {proof['time_in_range_percentage']}% (minimum required: {min_percentage}%)")
                                else:
                                    st.warning(f"⚠️ Proof generated: Time in range is only {proof['time_in_range_percentage']}% (below minimum of {min_percentage}%)")
                                
                                # Display proof details
                                st.write(f"Reading count: {proof['reading_count']}")
                                st.write(f"Date: {proof['date'] or 'All data'}")
                                
                                # Download proof as JSON
                                proof_json = json.dumps(proof)
                                st.download_button(
                                    label="Download ZK Proof",
                                    data=proof_json,
                                    file_name=f"zk_proof_tir_{lower_bound}_{upper_bound}_{datetime.now().strftime('%Y%m%d')}.json",
                                    mime="application/json"
                                )
                            else:
                                st.error(f"Error generating proof: {proof.get('error', 'Unknown error')}")
                
                elif proof_type == "Average glucose below threshold":
                    threshold = st.slider("Average glucose threshold (mg/dL)", 70, 250, 140)
                    
                    # Date selection (optional)
                    use_specific_date = st.checkbox("Specify a date")
                    selected_date = None
                    if use_specific_date:
                        # Get date range from data
                        data_dates = pd.to_datetime(st.session_state.processed_data['timestamp']).dt.date.unique()
                        if len(data_dates) > 0:
                            min_date = min(data_dates)
                            max_date = max(data_dates)
                            selected_date = st.date_input("Select date", min(data_dates), min_value=min_date, max_value=max_date)
                            selected_date = selected_date.strftime("%Y-%m-%d")
                    
                    if st.button("Generate Proof"):
                        with st.spinner("Generating zero-knowledge proof..."):
                            proof = st.session_state.zk_proof_system.generate_proof_average_below(
                                st.session_state.processed_data,
                                threshold,
                                date=selected_date
                            )
                            
                            if proof["success"]:
                                if proof["average_below_threshold"]:
                                    st.success(f"✅ Proof generated: Average glucose {proof['average']} mg/dL is below {threshold} mg/dL")
                                else:
                                    st.warning(f"⚠️ Proof generated: Average glucose is above {threshold} mg/dL")
                                
                                # Display proof details
                                st.write(f"Reading count: {proof['reading_count']}")
                                st.write(f"Date: {proof['date'] or 'All data'}")
                                
                                # Download proof as JSON
                                proof_json = json.dumps(proof)
                                st.download_button(
                                    label="Download ZK Proof",
                                    data=proof_json,
                                    file_name=f"zk_proof_avg_{threshold}_{datetime.now().strftime('%Y%m%d')}.json",
                                    mime="application/json"
                                )
                            else:
                                st.error(f"Error generating proof: {proof.get('error', 'Unknown error')}")
            
        with security_tabs[4]:
            st.subheader("Decentralized Identity (DID)")
            
            st.write("""
            Decentralized Identity gives you control over your T1D data and how it's shared,
            without relying on central authorities.
            """)
            
            # Initialize DID if not already done
            if 'did_identity' not in st.session_state:
                st.session_state.did_identity = None
                st.session_state.did_registry = VerifiableDataRegistry()
            
            # Create or import DID
            did_tabs = st.tabs(["Create Identity", "Import Identity", "Manage Credentials"])
            
            with did_tabs[0]:
                st.write("#### Create a New Decentralized Identity")
                
                metadata = {
                    "name": st.text_input("Name (optional)"),
                    "description": "T1D-Guardian user identity",
                    "created": datetime.now().isoformat(),
                }
                
                if st.button("Create New Identity"):
                    with st.spinner("Creating decentralized identity..."):
                        try:
                            # Create new DID
                            did = DecentralizedIdentity()
                            did_doc = did.create_identity(metadata)
                            
                            # Store in session state
                            st.session_state.did_identity = did
                            
                            # Register with registry
                            st.session_state.did_registry.register_did(did_doc)
                            
                            st.success(f"✅ Decentralized identity created successfully! Your DID: {did.did}")
                            
                            # Export DID document
                            did_json = did.export_did_document()
                            private_key = did.export_private_key()
                            
                            # Offer downloads
                            col1, col2 = st.columns(2)
                            with col1:
                                st.download_button(
                                    label="Download DID Document",
                                    data=did_json,
                                    file_name="did_document.json",
                                    mime="application/json"
                                )
                            
                            with col2:
                                st.download_button(
                                    label="Download Private Key (KEEP SAFE!)",
                                    data=private_key,
                                    file_name="did_private_key.pem",
                                    mime="application/x-pem-file"
                                )
                                
                            st.warning("⚠️ Keep your private key safe and secure. It cannot be recovered if lost.")
                        except Exception as e:
                            st.error(f"Error creating identity: {e}")
            
            with did_tabs[1]:
                st.write("#### Import Existing Identity")
                
                did_file = st.file_uploader("Upload DID document", type=["json"])
                key_file = st.file_uploader("Upload private key (optional)", type=["pem"])
                
                if did_file and st.button("Import Identity"):
                    with st.spinner("Importing identity..."):
                        try:
                            # Load DID document
                            did_json = did_file.read().decode("utf-8")
                            
                            # Load key if provided
                            private_key = key_file.read() if key_file else None
                            
                            # Create and import DID
                            did = DecentralizedIdentity()
                            if did.import_from_json(did_json, private_key):
                                # Store in session state
                                st.session_state.did_identity = did
                                
                                # Add to registry
                                if isinstance(did_json, str):
                                    did_doc = json.loads(did_json)
                                else:
                                    did_doc = did_json
                                    
                                st.session_state.did_registry.register_did(did_doc)
                                
                                st.success(f"✅ Identity imported successfully! Your DID: {did.did}")
                            else:
                                st.error("Failed to import identity. Invalid document or key.")
                        except Exception as e:
                            st.error(f"Error importing identity: {e}")
            
            with did_tabs[2]:
                st.write("#### Create Verifiable Credentials")
                
                if st.session_state.did_identity is None:
                    st.warning("Please create or import an identity first.")
                elif st.session_state.processed_data is None:
                    st.warning("Please process your data first to create credentials.")
                else:
                    # Subject DID (could be self or another DID)
                    subject_did = st.text_input("Subject DID", value=st.session_state.did_identity.did)
                    
                    # Credential details
                    st.write("Credential Claims (information to include)")
                    avg_glucose = st.checkbox("Average Glucose", value=True)
                    time_in_range = st.checkbox("Time in Range", value=True)
                    variability = st.checkbox("Glucose Variability", value=False)
                    hypo_events = st.checkbox("Hypoglycemia Events", value=False)
                    
                    # Credential expiration
                    expiry_days = st.slider("Credential Validity (days)", 1, 365, 90)
                    
                    if st.button("Create Verifiable Credential"):
                        with st.spinner("Creating verifiable credential..."):
                            try:
                                # Prepare claims based on processed data
                                claims = {
                                    "credential_type": "GlucoseData",
                                    "issuer_name": "T1D-Guardian App",
                                    "issuance_date": datetime.now().isoformat(),
                                    "data_period": {
                                        "start": pd.to_datetime(st.session_state.processed_data['timestamp']).min().isoformat(),
                                        "end": pd.to_datetime(st.session_state.processed_data['timestamp']).max().isoformat()
                                    }
                                }
                                
                                # Add selected claims
                                if avg_glucose:
                                    glucose_avg = st.session_state.processed_data['glucose_value'].mean()
                                    claims["average_glucose"] = f"{glucose_avg:.1f} mg/dL"
                                
                                if time_in_range:
                                    tir = time_in_range(st.session_state.processed_data)
                                    claims["time_in_range"] = f"{tir['in_range']:.1f}%"
                                
                                if variability:
                                    cv = (st.session_state.processed_data['glucose_value'].std() / 
                                          st.session_state.processed_data['glucose_value'].mean()) * 100
                                    claims["variability_cv"] = f"{cv:.1f}%"
                                
                                if hypo_events:
                                    hypo_count = (st.session_state.processed_data['glucose_value'] < 70).sum()
                                    claims["hypoglycemia_events"] = int(hypo_count)
                                
                                # Create the credential
                                credential = st.session_state.did_identity.create_verifiable_credential(
                                    subject_did,
                                    claims,
                                    expiration_days=expiry_days
                                )
                                
                                st.success("✅ Verifiable credential created successfully!")
                                st.json(credential)
                                
                                # Offer download
                                cred_json = json.dumps(credential)
                                st.download_button(
                                    label="Download Verifiable Credential",
                                    data=cred_json,
                                    file_name=f"t1d_credential_{datetime.now().strftime('%Y%m%d')}.json",
                                    mime="application/json"
                                )
                            except Exception as e:
                                st.error(f"Error creating credential: {e}")
        
        # Information about privacy features
        with security_tabs[5]:
            st.subheader("Open-Source Audit Log")
            
            st.write("""
            This transparent audit log tracks all actions performed on your diabetes data by healthcare 
            providers and other authorized parties. Every data access, analysis, and sharing event is 
            recorded with timestamps and can be verified on the blockchain.
            """)
            
            # User role selection (in a real app, this would be determined by login)
            role_col1, role_col2 = st.columns([1, 3])
            with role_col1:
                user_role = st.radio("Your role:", ["Patient", "Healthcare Provider"])
                if user_role == "Patient":
                    st.session_state.user_role = "patient"
                    st.session_state.user_id = "patient_1"  # In a real app, this would be a real identifier
                else:
                    st.session_state.user_role = "healthcare_provider"
                    st.session_state.user_id = "provider_1"  # In a real app, this would be a real identifier
            
            with role_col2:
                st.info(f"Logged in as: {st.session_state.user_role.replace('_', ' ').title()} (ID: {st.session_state.user_id})")
                
                # Sample patient identifiers in a real system
                if st.session_state.user_role == "healthcare_provider":
                    patient_to_access = st.selectbox(
                        "Select patient to access:",
                        ["patient_1", "patient_2", "patient_3"]
                    )
            
            # Create tabs for audit log functions
            audit_tabs = st.tabs(["View Log", "Record Access", "Verify Records"])
            
            with audit_tabs[0]:
                st.subheader("Audit Log Entries")
                
                # Get all audit log entries
                entries = st.session_state.audit_log.get_all_entries()
                
                if entries:
                    # Create a DataFrame for display
                    df_entries = pd.DataFrame(entries)
                    
                    # Format the datetime for better readability
                    if 'human_time' in df_entries.columns:
                        df_entries = df_entries.sort_values('timestamp', ascending=False)
                    
                    # Add filters for the log
                    filter_col1, filter_col2 = st.columns(2)
                    
                    with filter_col1:
                        # Filter by actor if there are multiple
                        actors = df_entries['actor'].unique().tolist() if 'actor' in df_entries.columns else []
                        if len(actors) > 1:
                            selected_actors = st.multiselect("Filter by actor:", actors, default=actors)
                            if selected_actors:
                                df_entries = df_entries[df_entries['actor'].isin(selected_actors)]
                    
                    with filter_col2:
                        # Filter by action type
                        actions = df_entries['action'].unique().tolist() if 'action' in df_entries.columns else []
                        if len(actions) > 1:
                            selected_actions = st.multiselect("Filter by action:", actions, default=actions)
                            if selected_actions:
                                df_entries = df_entries[df_entries['action'].isin(selected_actions)]
                    
                    # Display the audit log
                    st.dataframe(df_entries, use_container_width=True)
                    
                    # Option to download the log
                    if st.download_button(
                        "Download Audit Log",
                        data=df_entries.to_csv(index=False),
                        file_name=f"t1d_audit_log_{datetime.now().strftime('%Y%m%d')}.csv",
                        mime="text/csv"
                    ):
                        st.success("Audit log downloaded successfully!")
                        
                    # Statistics about the log
                    st.subheader("Audit Log Statistics")
                    
                    # Calculate some basic statistics
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Events", len(df_entries))
                    with col2:
                        provider_actions = df_entries[df_entries['actor'].str.contains('provider')].shape[0] if 'actor' in df_entries.columns else 0
                        st.metric("Provider Actions", provider_actions)
                    with col3:
                        patient_actions = df_entries[df_entries['actor'].str.contains('patient')].shape[0] if 'actor' in df_entries.columns else 0
                        st.metric("Patient Actions", patient_actions)
                    
                else:
                    st.info("No audit log entries found. Start recording actions using the 'Record Access' tab.")
            
            with audit_tabs[1]:
                st.subheader("Record Data Access")
                
                if st.session_state.processed_data is None:
                    st.warning("Please process data first before recording access.")
                else:
                    st.write("Record a new action in the audit log:")
                    
                    # Form for creating a new audit log entry
                    action_type = st.selectbox(
                        "Action type:",
                        [
                            "Data View", 
                            "Data Analysis", 
                            "Download Report", 
                            "Prediction Generation",
                            "Data Sharing",
                            "Consent Management",
                            "Other Action"
                        ]
                    )
                    
                    # Only healthcare providers should record data access
                    if st.session_state.user_role == "healthcare_provider":
                        action_description = st.text_area(
                            "Action details:", 
                            value=f"{action_type} of diabetes data for patient {patient_to_access}"
                        )
                        
                        # Calculate data reference (hash) if not already done
                        if not st.session_state.data_hash and st.session_state.processed_data is not None:
                            data_str = json.dumps(str(st.session_state.processed_data.to_dict()))
                            st.session_state.data_hash = generate_hash(data_str)
                            
                        data_reference = st.session_state.data_hash if st.session_state.data_hash else "No data hash available"
                        
                        if st.button("Record Action"):
                            # Add the entry to the audit log
                            entry = st.session_state.audit_log.add_entry(
                                actor=st.session_state.user_id,
                                action=action_description,
                                data_reference=data_reference
                            )
                            
                            st.success("Action recorded in the audit log!")
                            st.json(entry.to_dict())
                            
                            # Option to add blockchain verification (would need API keys)
                            add_blockchain = st.checkbox("Add blockchain verification for this action")
                            
                            if add_blockchain:
                                infura_key = st.text_input("Infura API Key", type="password")
                                eth_private_key = st.text_input("Ethereum Private Key", type="password")
                                
                                if infura_key and eth_private_key and st.button("Verify on Blockchain"):
                                    # Create blockchain audit log
                                    blockchain_log = BlockchainAuditLog(
                                        log_file="t1d_blockchain_audit_log.json",
                                        infura_api_key=infura_key
                                    )
                                    
                                    # Add existing entries
                                    for existing_entry in st.session_state.audit_log.entries:
                                        blockchain_log.entries.append(existing_entry)
                                    
                                    # Add blockchain verification
                                    result = blockchain_log.add_entry_with_blockchain(
                                        actor=st.session_state.user_id,
                                        action=action_description,
                                        data_reference=data_reference,
                                        private_key=eth_private_key
                                    )
                                    
                                    if result["blockchain"]["success"]:
                                        st.success("Action verified on blockchain!")
                                        st.code(f"Transaction Hash: {result['blockchain']['tx_hash']}")
                                    else:
                                        st.error(f"Error verifying on blockchain: {result['blockchain'].get('error')}")
                    else:
                        st.info("Only healthcare providers can record data access. Please switch your role to healthcare provider to record actions.")
            
            with audit_tabs[2]:
                st.subheader("Verify Blockchain Records")
                
                st.write("""
                Verify that audit log entries have been properly recorded on the blockchain 
                for immutable proof of healthcare provider actions.
                """)
                
                # Verify a specific transaction hash
                tx_hash = st.text_input("Enter transaction hash to verify:")
                
                if tx_hash:
                    infura_key = st.text_input("Infura API Key for Verification", type="password")
                    
                    if infura_key and st.button("Verify Transaction"):
                        # Create blockchain audit log for verification
                        blockchain_log = BlockchainAuditLog(
                            log_file="t1d_blockchain_audit_log.json",
                            infura_api_key=infura_key
                        )
                        
                        # Verify the record
                        result = blockchain_log.verify_single_record(tx_hash)
                        
                        if result["verified"]:
                            st.success("✅ Blockchain record verified successfully!")
                            st.json(result)
                        else:
                            st.error(f"❌ Verification failed: {result.get('error')}")
                
                # Option to verify all blockchain records
                if st.button("Verify All Blockchain Records"):
                    infura_key = st.text_input("Infura API Key for Bulk Verification", type="password")
                    
                    if infura_key:
                        # Create blockchain audit log for verification
                        blockchain_log = BlockchainAuditLog(
                            log_file="t1d_blockchain_audit_log.json",
                            infura_api_key=infura_key
                        )
                        
                        # Load blockchain records
                        blockchain_log.load_log()
                        
                        if blockchain_log.blockchain_records:
                            # Verify all records
                            results = blockchain_log.verify_blockchain_records()
                            
                            # Display verification results
                            verified_count = sum(1 for r in results if r.get("verified", False))
                            
                            if verified_count > 0:
                                st.success(f"✅ Verified {verified_count} of {len(results)} blockchain records!")
                            else:
                                st.warning("⚠️ No blockchain records could be verified.")
                            
                            # Show detailed results
                            st.json(results)
                        else:
                            st.info("No blockchain records found to verify.")
            
        with st.expander("About Privacy & Security Features"):
            st.markdown("""
            ### Privacy & Security in T1D-Guardian
            
            T1D-Guardian protects your sensitive medical data with multiple layers of security:
            
            1. **Encryption**: All data is encrypted using AES-GCM, a secure encryption algorithm.
            2. **Blockchain Verification**: Data integrity is verified using Ethereum blockchain.
            3. **Zero-Knowledge Proofs**: Share facts about your data without revealing actual values.
            4. **Decentralized Identity**: Control your identity and data sharing permissions.
            5. **Smart Contracts**: Manage consent for who can access your data and for how long.
            6. **PDF Reports**: Generate encrypted, blockchain-verified medical reports.
            7. **Audit Logs**: Track every data access with blockchain verification.
            8. **Local Processing**: Your data never leaves your device for analysis.
            9. **No Cloud Storage**: Data is only stored locally or in encrypted form.
            
            These measures ensure your diabetes data remains private while still allowing you
            to benefit from advanced analytics and AI insights.
            """)
else:
    # Display instructions when no data is loaded
    st.info("Please upload your Dexcom CGM data CSV file to get started.")
    
    # User tutorial
    st.subheader("How to use T1D-Guardian")
    st.markdown("""
    1. **Upload Data**: Start by uploading your Dexcom CGM data from the sidebar.
    2. **Generate Encryption Key**: Create a secure key to encrypt your sensitive health data.
    3. **Process Your Data**: Transform raw data into analytics-ready format.
    4. **Explore Analytics**: View statistics and visualizations about your glucose trends.
    5. **Get AI Insights**: Train the AI model to predict future glucose levels and hypoglycemia risk.
    6. **Secure Your Data**: Encrypt your results and verify integrity using blockchain technology.
    
    Your data remains private - all processing happens locally, and encrypted data is only stored if you choose to download it.
    """)
