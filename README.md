# URL Security Scanner

This repository contains a URL Security Scanner that performs various security checks on URLs to identify potential threats such as XSS, SQL injection, CSRF, open redirects, directory traversal, file inclusion, command injection, and phishing indicators. Additionally, the scanner performs Nmap scans and SSL certificate checks.

## Features

- **URL Live Check:** Verify if the URL is accessible.
- **Attack Analysis:** Detects various types of attacks including XSS, SQL injection, CSRF, and more.
- **Nmap Scan:** Perform a port scan on the URL.
- **SSL Certificate Check:** Fetch and display SSL certificate details.
- **Feature Extraction:** Extract features from the URL for analysis.
- **Suspicious URL Detection:** Predict if a URL is suspicious based on its structure using a trained model.
- **Whitelist Check:** Verify if the URL is in a whitelist stored in MongoDB.


## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/yu-192/url-security-scanner.git
   cd url-security-scanner
   ```

2. Install the required libraries:
   ```sh
   pip install -r requirements.txt
   ```

3. Set up MongoDB:
   - Make sure MongoDB is installed and running on your machine.
   - Create a database named `whitelistDB` and a collection named `whitelist`.

## Usage

1. **Train the Model:**
   - Run the `train_model.py` script to train the logistic regression model using the dataset.
     ```sh
     python train_model.py
     ```

2. **Run the Scanner:**
   - Execute the `scanner.py` script to start the URL Security Scanner.
     ```sh
     python scanner.py
     ```

3. **Enter the URL to Scan:**
   - Input the URL you want to scan when prompted. The scanner will perform various checks and display the results.

## Code Overview

- `train_model.py`: Script to train the logistic regression model using a dataset of URLs.
- `scanner.py`: Main script to run the URL Security Scanner.
- `requirements.txt`: List of required Python libraries.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
    
