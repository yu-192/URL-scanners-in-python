import tldextract
from urllib.parse import urlparse
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pandas as pd
import joblib

# List of suspicious words commonly found in phishing URLs
suspicious_words = ['login', 'secure', 'verify', 'account', 'update', 'bank', 'password', 'admin']

# Function to extract features from the URL for analysis
def extract_features(url):
    features = []
    
    # Feature 1: Length of the URL
    features.append(len(url))
    
    # Feature 2: Number of dots in the domain
    domain_info = tldextract.extract(url)
    features.append(domain_info.subdomain.count('.') + domain_info.domain.count('.'))
    
    # Feature 3: Check for suspicious words in the URL
    if any(word in url.lower() for word in suspicious_words):
        features.append(1)
    else:
        features.append(0)

    # Feature 4: Check if HTTPS is used (HTTPS adds a layer of security)
    if urlparse(url).scheme == "https":
        features.append(0)
    else:
        features.append(1)
    
    return features

# Load dataset
df = pd.read_csv('url_dataset.csv')

# Extract features and labels
X = df['url'].apply(extract_features).tolist()
y = df['label'].tolist()

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train the logistic regression model
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
print(classification_report(y_test, y_pred))

# Save the trained model to a file
joblib.dump(model, 'url_classifier_model.pkl')
from urllib.parse import urlparse
import re
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pandas as pd
import joblib

# List of suspicious words commonly found in phishing URLs
suspicious_words = ['login', 'secure', 'verify', 'account', 'update', 'bank', 'password', 'admin']

# Function to check if the URL contains an IP address
def has_ip_address(url):
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    return 1 if ip_pattern.search(url) else 0

# Function to extract features from the URL for analysis
def extract_features(url):
    features = []
    
    # Feature 1: Length of the URL
    features.append(len(url))
    
    # Feature 2: Number of dots in the domain
    domain_info = tldextract.extract(url)
    features.append(domain_info.subdomain.count('.') + domain_info.domain.count('.'))
    
    # Feature 3: Check for suspicious words in the URL
    if any(word in url.lower() for word in suspicious_words):
        features.append(1)
    else:
        features.append(0)

    # Feature 4: Check if HTTPS is used (HTTPS adds a layer of security)
    if urlparse(url).scheme == "https":
        features.append(0)
    else:
        features.append(1)

    # Feature 5: Length of the URL path
    features.append(len(urlparse(url).path))
    
    # Feature 6: Length of the URL query string
    features.append(len(urlparse(url).query))
    
    # Feature 7: Count of special characters in the URL
    features.append(len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url)))
    
    # Feature 8: Check for presence of IP address in the URL
    features.append(has_ip_address(url))

    # Feature 9: Number of digits in the URL
    features.append(sum(c.isdigit() for c in url))
    
    # Feature 10: Number of unique characters in the URL
    features.append(len(set(url)))

    # Feature 11: Ratio of digits to characters in the URL
    features.append(sum(c.isdigit() for c in url) / len(url))

    return features

# Load dataset
df = pd.read_csv('url_dataset.csv')

# Extract features and labels
X = df['url'].apply(extract_features).tolist()
y = df['label'].tolist()

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train the logistic regression model
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
print(classification_report(y_test, y_pred))

# Save the trained model to a file
joblib.dump(model, 'url_classifier_model.pkl')