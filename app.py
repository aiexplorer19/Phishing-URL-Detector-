from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import whois
import os

app = Flask(__name__)

# Load the trained model
model = joblib.load('model/phishing_model.pkl')

def extract_features(url):
    """Extract features from URL for prediction"""
    features = {
        'url_length': len(url),
        'contains_https': 1 if 'https' in url else 0,
        'domain_age': get_domain_age(url),
        'special_char_count': sum(not c.isalnum() for c in url),
        'ip_address': is_ip_address(url)
    }
    return pd.DataFrame([features])

def get_domain_age(url):
    """Get domain age in days"""
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
    """Check if URL uses IP address"""
    try:
        domain = url.split('/')[2]
        parts = domain.split('.')
        return len(parts) == 4 and all(part.isdigit() for part in parts)
    except:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_url():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        features = extract_features(url)
        prediction = model.predict(features)[0]
        proba = model.predict_proba(features)[0][1] * 100
        
        return jsonify({
            'is_phishing': int(prediction),
            'confidence': round(proba, 2),
            'message': '⚠️ Warning: This may be a phishing URL' if prediction else '✅ This URL appears safe',
            'features': {
                'url_length': int(features['url_length'][0]),
                'has_https': bool(features['contains_https'][0]),
                'domain_age_days': int(features['domain_age'][0]),
                'special_chars': int(features['special_char_count'][0]),
                'is_ip_address': bool(features['ip_address'][0])
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
