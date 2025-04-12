import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report
import joblib
import whois
import os

def get_domain_age(url):
    """Get domain age in days using whois lookup"""
    try:
        domain = whois.whois(url)
        if domain.creation_date:
            if isinstance(domain.creation_date, list):
                creation_date = domain.creation_date[0]
            else:
                creation_date = domain.creation_date
            return (pd.Timestamp.now() - pd.Timestamp(creation_date)).days
        return 0
    except:
        return 0

def is_ip_address(url):
    """Check if URL uses an IP address instead of domain name"""
    try:
        domain = url.split('/')[2]
        parts = domain.split('.')
        return len(parts) == 4 and all(part.isdigit() for part in parts)
    except:
        return False

# Create synthetic dataset (replace with real dataset when available)
data = pd.DataFrame({
    'url': [
        'https://legit-site.com/page1',
        'http://phishing-site.com/login',
        'https://secure-bank.com',
        'http://192.168.1.1/login',
        'https://trusted-site.org',
        'http://malicious-site.net/steal-info',
        'https://real-service.com/auth',
        'http://fake-bank.com/verify',
        'https://safe-website.com',
        'http://scam-page.com/account',
        'https://official-portal.gov',
        'http://10.0.0.1/admin',
        'https://verified-store.com',
        'http://fraudulent-page.com/pay',
        'https://authentic-service.net',
        'http://compromised-site.org/login',
        'https://protected-domain.com',
        'http://evil-site.com/credentials',
        'https://valid-website.io',
        'http://dangerous-page.com/submit'
    ],
    'is_phishing': [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
})

# Feature engineering
data['url_length'] = data['url'].apply(len)
data['contains_https'] = data['url'].apply(lambda x: 1 if 'https' in x else 0)
data['domain_age'] = data['url'].apply(get_domain_age)
data['special_char_count'] = data['url'].apply(lambda x: sum(not c.isalnum() for c in x))
data['ip_address'] = data['url'].apply(is_ip_address)

# Features and target
X = data[['url_length', 'contains_https', 'domain_age', 'special_char_count', 'ip_address']]
y = data['is_phishing']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("Warning: Using synthetic dataset. For better accuracy, replace with real phishing dataset.")

# Train model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Cross-validation
cv_scores = cross_val_score(model, X, y, cv=5)
print(f"Cross-validation scores: {cv_scores}")

# Evaluate model with probabilities
y_pred = model.predict(X_test)
y_probs = model.predict_proba(X_test)[:, 1]  # Get probability of class 1 (phishing)

# Print classification report
print(classification_report(y_test, y_pred))

# Print detailed probability results
print("\n=== URL Phishing Probability Report ===")
print("URL".ljust(40) + "Phishing Probability".ljust(20) + "Actual Status")
print("-"*80)
for url, actual, prob in zip(X_test.index, y_test, y_probs):
    print(f"{data.loc[url, 'url'][:38].ljust(40)}" +
          f"{prob*100:.1f}%".ljust(20) +
          f"{'PHISHING' if actual else 'LEGITIMATE'}")
print("\nNote: Probabilities above 70% indicate high phishing risk")

# Save model
os.makedirs('model', exist_ok=True)
joblib.dump(model, 'model/phishing_model.pkl')
print("Model saved successfully to 'model/phishing_model.pkl'")
