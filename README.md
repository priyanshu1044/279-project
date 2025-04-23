# Phishing Detection System Using Email Header Analysis

## Overview
This Python-based tool detects potential phishing emails by analyzing email headers and metadata using heuristic rules. The system examines various header fields to identify suspicious patterns that may indicate phishing attempts.

## Features
- Email header parsing and extraction
- Analysis of key header fields (From, Reply-To, Received chains, etc.)
- Heuristic-based detection rules
- Detailed reporting of suspicious indicators
- Command-line interface for easy usage

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd phishing-detection

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Analyze a single email file
python phishing_detector.py --file path/to/email.eml

# Analyze multiple email files in a directory
python phishing_detector.py --dir path/to/email/directory

# Save results to a file
python phishing_detector.py --file path/to/email.eml --output results.json
```

## Project Structure
```
├── phishing_detector.py     # Main script
├── email_parser.py          # Email parsing functionality
├── feature_extractor.py     # Feature extraction from headers
├── detection_rules.py       # Phishing detection rules
├── utils.py                 # Utility functions
├── data/                    # Sample data directory
│   ├── legitimate/          # Legitimate email samples
│   └── phishing/            # Phishing email samples
├── tests/                   # Test files
└── requirements.txt         # Project dependencies
```

## Detection Methods
The system uses the following techniques to identify potential phishing emails:

1. **Sender Analysis**
   - Mismatch between From and Reply-To headers
   - Use of free email providers in business communications
   - Domain age and reputation checks

2. **Header Inconsistencies**
   - Unusual Received chain patterns
   - Suspicious routing information
   - Time discrepancies in header timestamps

3. **Content Indicators**
   - Suspicious subject lines
   - Malformed Message-ID fields
   - Missing or unusual header fields

## Evaluation
The system has been evaluated on publicly available datasets including the Enron Email Dataset and phishing email collections from Kaggle, achieving high detection rates while minimizing false positives.

## Future Improvements
- Integration with machine learning models for improved detection
- Real-time email scanning capabilities
- Web interface for easier interaction
- Integration with email clients

## License
MIT