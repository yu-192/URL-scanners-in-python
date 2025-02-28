import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import tldextract
from urllib.parse import urlparse, parse_qs
import re
from sklearn.linear_model import LogisticRegression
import joblib
from pymongo import MongoClient
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import nmap
import datetime

# MongoDB client setup for whitelist check
client = MongoClient('mongodb://localhost:27017/')
db = client.whitelistDB
collection = db.whitelist

# Function to check if the URL is live
def url_live(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://www.google.com/',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[403, 500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        response = session.get(url, headers=headers, timeout=20)
        if 200 <= response.status_code < 300:
            return True
        else:
            return False
    except requests.RequestException as e:
        return False

# Function to analyze the URL for possible attacks
def test_url_for_attacks(url):
    xss_payloads = [
        "<script>", "</script>", "javascript:", "onerror=", "onload=", "alert(", "img src=", "iframe src=", "document.cookie", "document.write", "eval("
    ]
    sql_injection_patterns = [
        r"(\bor\b|\band\b).*?(\d+.*=\d+|\d+.*=\s*\d+|\d+.*<.*=|\d+.*>.*=|\d+.*<=.*=|\d+.*>=.*=|\d+.*<.*\d+|\d+.*>.*\d+|\d+.*<=.*\d+|\d+.*>=.*\d+)",
        r"(union|select|insert|update|delete|drop|alter|create|replace).*?(\s+from\s+|\s+into\s+|\s+table\s+|\s+database\s+)",
        r"(select|insert|update|delete|drop|alter|create|replace).*?(\bfrom\b|\binto\b|\btable\b|\bdatabase\b)"
    ]
    csrf_patterns = [
        r"<img\s+src=\"[^\"]*\".*?>",
        r"<iframe\s+src=\"[^\"]*\".*?>"
    ]
    open_redirect_patterns = [
        r"redirect=.*",
        r"url=.*"
    ]
    directory_traversal_patterns = [
        r"\.\./", r"\.\.\\", r"/../", r"\\..\\"
    ]
    file_inclusion_patterns = [
        r"(\.\./|\.\.\\|/../|\\..\\).*",
        r"((include|require)(_once)?)\s*[('|\"]"
    ]
    command_injection_patterns = [
        r";.*", r"&&.*", r"\|.*", r"`.*`"
    ]
    phishing_indicators = [
        "login", "secure", "verify", "account", "update", "bank", "password", "admin"
    ]

    def contains_xss(url):
        url_components = urlparse(url).path + urlparse(url).query
        for payload in xss_payloads:
            if payload.lower() in url_components.lower():
                return True
        return False

    def contains_sql_injection(url):
        url_components = urlparse(url).path + urlparse(url).query
        for pattern in sql_injection_patterns:
            if re.search(pattern, url_components, re.IGNORECASE):
                return True
        return False

    def contains_csrf(url):
        for pattern in csrf_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def contains_open_redirect(url):
        query_params = parse_qs(urlparse(url).query)
        for param_values in query_params.values():
            for value in param_values:
                for pattern in open_redirect_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        return True
        return False

    def contains_directory_traversal(url):
        url_components = urlparse(url).path + urlparse(url).query
        for pattern in directory_traversal_patterns:
            if re.search(pattern, url_components, re.IGNORECASE):
                return True
        return False

    def contains_file_inclusion(url):
        url_components = urlparse(url).path + urlparse(url).query
        for pattern in file_inclusion_patterns:
            if re.search(pattern, url_components, re.IGNORECASE):
                return True
        return False

    def contains_command_injection(url):
        url_components = urlparse(url).path + urlparse(url).query
        for pattern in command_injection_patterns:
            if re.search(pattern, url_components, re.IGNORECASE):
                return True
        return False

    def contains_phishing_indicators(url):
        for indicator in phishing_indicators:
            if indicator.lower() in url.lower():
                return True
        return False

    results = {}
    results['XSS'] = contains_xss(url)
    results['SQL Injection'] = contains_sql_injection(url)
    results['CSRF'] = contains_csrf(url)
    results['Open Redirect'] = contains_open_redirect(url)
    results['Directory Traversal'] = contains_directory_traversal(url)
    results['File Inclusion'] = contains_file_inclusion(url)
    results['Command Injection'] = contains_command_injection(url)
    results['Phishing Indicators'] = contains_phishing_indicators(url)
    return results

# Function to perform Nmap scan
def nmap_scan(url):
    scanner = nmap.PortScanner()
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    ip_address = socket.gethostbyname(hostname)
    scanner.scan(ip_address, arguments='-sS -p 1-100 -T4')
    scan_data = {
        'IP Address': ip_address,
        'Hostname': scanner[ip_address].hostname(),
        'Vendor': scanner[ip_address]['osmatch'][0]['name'] if 'osmatch' in scanner[ip_address] and scanner[ip_address]['osmatch'] else 'Unknown',
        'Open Ports': [],
        'Vulnerabilities': []
    }
    for proto in scanner[ip_address].all_protocols():
        for port in scanner[ip_address][proto].keys():
            port_data = scanner[ip_address][proto][port]
            scan_data['Open Ports'].append({
                'Port': port,
                'Service': port_data['name'],
                'Product': port_data.get('product', 'Unknown'),
                'Version': port_data.get('version', 'Unknown')
            })
    return scan_data

# Function to check SSL certificate
def get_ssl_certificate(url):
    hostname = url.replace("https://", "").replace("http://", "").split('/')[0]
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                cert = sslsock.getpeercert(True)
    except (ssl.SSLError, socket.error) as e:
        return None, str(e)
    cert = x509.load_der_x509_certificate(cert, default_backend())
    details = {
        "Subject": cert.subject,
        "Issuer": cert.issuer,
        "Serial Number": cert.serial_number,
        "Not Before": cert.not_valid_before_utc,
        "Not After": cert.not_valid_after_utc,
        "Signature Algorithm": cert.signature_hash_algorithm,
        "Version": cert.version,
    }
    return details, None

# Function to analyze URL
def extract_features(url):
    suspicious_words = ['login', 'secure', 'verify', 'account', 'update', 'bank', 'password', 'admin']
    features = []
    features.append(len(url))
    domain_info = tldextract.extract(url)
    features.append(domain_info.subdomain.count('.') + domain_info.domain.count('.'))
    if any(word in url.lower() for word in suspicious_words):
        features.append(1)
    else:
        features.append(0)
    if urlparse(url).scheme == "https":
        features.append(0)
    else:
        features.append(1)
    features.append(len(urlparse(url).path))
    features.append(len(urlparse(url).query))
    features.append(len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url)))
    features.append(has_ip_address(url))
    features.append(sum(c.isdigit() for c in url))
    features.append(len(set(url)))
    features.append(sum(c.isdigit() for c in url) / len(url))
    return features

def has_ip_address(url):
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    return 1 if ip_pattern.search(url) else 0

def is_suspicious_url(url, model):
    features = extract_features(url)
    prediction = model.predict([features])[0]
    print(f"Extracted Features: {features}")
    print(f"Model Prediction: {prediction}")
    return prediction == 1

def get_true_domain(url):
    domain_info = tldextract.extract(url)
    true_domain = f"{domain_info.domain}.{domain_info.suffix}"
    return true_domain

# Load the trained model
model = joblib.load('url_classifier_model.pkl')

# Function to check if URL is in whitelist
def whitelist_url(input_url):
    result = collection.find_one({"url": input_url})
    if result is not None:
        print(f"URL '{input_url}' is in the whitelist. Proceeding with structure analysis and SSL certificate check...")
        ssl_details, ssl_error = get_ssl_certificate(input_url)
        if ssl_details:
            print("\nSSL Certificate Details:")
            for key, value in ssl_details.items():
                print(f"{key}: {value}")
        else:
            print(f"\nSSL Certificate Error: {ssl_error}")

        if is_suspicious_url(input_url, model):
            print(f"\nThe URL '{input_url}' is suspicious based on its structure.")
        else:
            print(f"\nThe URL '{input_url}' appears to be safe based on its structure.")
        return True
    return False

# Main function
def main():
    url = input("Enter the URL to scan: ")
    
    if not url_live(url):
        print(f"URL {url} is not live.")
        return
    
    if whitelist_url(url):
        return
    
    print(f"URL {url} is live. Proceeding with further analysis...")
    
    ssl_details, ssl_error = get_ssl_certificate(url)
    if ssl_details:
        print("\nSSL Certificate Details:")
        for key, value in ssl_details.items():
            print(f"{key}: {value}")
    else:
        print(f"\nSSL Certificate Error: {ssl_error}")
    
    attack_results = test_url_for_attacks(url)
    detected_attacks = {attack: result for attack, result in attack_results.items() if result}
    
    if detected_attacks:
        print("\nDetected Attacks:")
        for attack, result in detected_attacks.items():
            print(f"{attack}: Detected")
    
    scan_results = nmap_scan(url)
    print("\nNmap Scan Results:")
    print(f"IP Address: {scan_results['IP Address']}")
    print(f"Hostname: {scan_results['Hostname']}")
    print(f"Vendor: {scan_results['Vendor']}")
    print("\nOpen Ports:")
    for port in scan_results['Open Ports']:
        print(f"Port: {port['Port']}, Service: {port['Service']}, Product: {port['Product']}, Version: {port['Version']}")
    
    if is_suspicious_url(url, model):
        print(f"\nThe URL '{url}' is suspicious based on its structure.")
    else:
        print(f"\nThe URL '{url}' appears to be safe based on its structure.")
    
    print(f"The true domain of the URL is: {get_true_domain(url)}")

if __name__ == "__main__":
    main()