import streamlit as st
import joblib
import pandas as pd
import whois

# Set page config
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="wide"
)

# Load the trained model
@st.cache_resource
def load_model():
    return joblib.load('model/phishing_model.pkl')

model = load_model()

# Feature extraction functions (same as original)
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

# Streamlit UI
st.title("Phishing URL Detector 🛡️")
st.write("Check if a URL might be a phishing attempt")

url = st.text_input("Enter URL to check:", placeholder="https://example.com")

if st.button("Check URL"):
    if not url:
        st.error("Please enter a URL")
    else:
        try:
            with st.spinner("Analyzing URL..."):
                features = extract_features(url)
                prediction = model.predict(features)[0]
                proba = model.predict_proba(features)[0][1] * 100

                st.subheader("Results")
                if prediction:
                    st.error(f"⚠️ Warning: This may be a phishing URL (confidence: {proba:.2f}%)")
                else:
                    st.success(f"✅ This URL appears safe (confidence: {proba:.2f}%)")

                with st.expander("See feature details"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("**URL Length:**")
                        st.markdown("**HTTPS:**")
                        st.markdown("**Domain Age (days):**")
                        st.markdown("**Special Characters:**")
                        st.markdown("**Uses IP Address:**")
                    with col2:
                        st.markdown(f"{int(features['url_length'][0])}")
                        st.markdown(f"{'✅ Yes' if bool(features['contains_https'][0]) else '❌ No'}")
                        st.markdown(f"{int(features['domain_age'][0])}")
                        st.markdown(f"{int(features['special_char_count'][0])}")
                        st.markdown(f"{'✅ Yes' if bool(features['ip_address'][0]) else '❌ No'}")
        except Exception as e:
            st.error(f"Error analyzing URL: {str(e)}")
