# T1D-Guardian

A privacy-focused Type 1 Diabetes analytics system using AI, encryption, and blockchain for data integrity verification.

## Overview

T1D-Guardian is a comprehensive platform for Type 1 Diabetes patients to analyze their glucose data while maintaining complete control over their privacy and data ownership. The application combines cutting-edge technologies including machine learning, encryption, blockchain verification, zero-knowledge proofs, and decentralized identity to create a secure and private healthcare data ecosystem.

## Key Features

### Data Processing & Analysis
- Import and process Dexcom CGM (Continuous Glucose Monitor) data
- Comprehensive glucose statistics and time-in-range analysis
- Daily patterns visualization and trend identification
- Interactive graphs and charts for data exploration

### AI & Prediction
- Machine learning models to predict future glucose values
- Hypoglycemia risk prediction
- Personalized insights and recommendations
- Secure, local model training without data leaving your device

### Privacy & Security
- End-to-end encryption for all sensitive data
- Blockchain verification for data integrity
- Zero-knowledge proofs to share insights without revealing actual data
- Decentralized Identity (DID) for verifiable credentials
- Smart contracts for managing data access consent
- Transparent audit logs for all data access events

### Reporting & Sharing
- Generate encrypted PDF medical reports
- Blockchain-verified data summaries
- Secure data sharing with healthcare providers

## Technical Architecture

T1D-Guardian is built using a modern tech stack:

- **Frontend/Application**: Streamlit for an interactive user interface
- **Data Processing**: Pandas and NumPy for glucose data analysis
- **Visualization**: Plotly for interactive charts and graphs
- **Machine Learning**: Scikit-learn for glucose prediction models
- **Encryption**: AES-GCM for securing sensitive health data
- **Blockchain Integration**: Ethereum (Sepolia testnet) for data verification
- **Identity Management**: Decentralized Identity (DID) implementation
- **Audit System**: Immutable, blockchain-verified access logs

## Privacy-First Approach

T1D-Guardian follows these core privacy principles:

1. **Local-First**: All data processing happens on your device, not in the cloud
2. **Encryption by Default**: All sensitive data is encrypted with keys only you control
3. **Verifiable Data Integrity**: Blockchain hashing ensures data hasn't been tampered with
4. **Selective Disclosure**: Zero-knowledge proofs allow sharing specific insights without revealing raw data
5. **Transparent Access Control**: Open-source audit logs track all access to your data

## Getting Started

### Prerequisites
- Python 3.10 or higher
- An Ethereum wallet and Infura API key (for blockchain features)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/PeytTheMate/t1d-guardian.git
cd t1d-guardian
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
streamlit run app.py
```

### Using the Application

1. **Upload Data**: Start by uploading your Dexcom CSV export file
2. **Generate Encryption Key**: Create a secure key to protect your data
3. **Process Data**: Pre-process your glucose data for analysis
4. **Explore Insights**: Navigate through the tabs to view statistics and visualizations
5. **Generate Predictions**: Train the AI model to get personalized predictions
6. **Secure Your Data**: Use the Security & Verification features to protect and verify your data

## Use Cases

### For Patients
- Analyze your glucose patterns and trends
- Get predictions for potential hypoglycemic events
- Securely share specific insights with healthcare providers
- Maintain complete ownership of your health data

### For Healthcare Providers
- Receive verifiable glucose data insights from patients
- Access only the data patients explicitly consent to share
- Generate comprehensive medical reports
- All access is logged and transparent to the patient

## Contributing

We welcome contributions to T1D-Guardian! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- See this Notion site for the full methodology: https://everlasting-coriander-906.notion.site/T1D_Blockchain-Documentation-1f96670fd54880fca7bce71a19c6da13
- This project was inspired by the need for privacy-preserving health data analytics
- Special thanks to the diabetes tech community
- "You can have 99 problems, but when you have a terminal health problem, you can only have 1" - idk probably an Insta Reel I saw lol