from flask import Flask, render_template, request, jsonify
import numpy as np
import pandas as pd
import h5py
import pickle
import os
from urllib.parse import urlparse
import re
import urllib.parse
import tldextract
import joblib
from datetime import datetime
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# Global variables for model and scaler
elm_model = None
scaler = None
feature_names = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
    'DomainInSubdomains', 'DomainInPaths', 'HttpsInHostname',
    'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath',
    'NumSensitiveWords', 'EmbeddedBrandName', 'PctExtHyperlinks',
    'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms', 'RelativeFormAction',
    'ExtFormAction', 'AbnormalFormAction', 'PctNullSelfRedirectHyperlinks',
    'FrequentDomainNameMismatch', 'FakeLinkInStatusBar', 'RightClickDisabled',
    'PopUpWindow', 'SubmitInfoToEmail', 'IframeOrFrame', 'MissingTitle',
    'ImagesOnlyInForm', 'SubdomainLevelRT', 'UrlLengthRT', 'PctExtResourceUrlsRT',
    'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT', 'PctExtNullSelfRedirectHyperlinksRT'
]

# Implementation of the Extreme Learning Machine class
class ExtremeLearningMachine:
    def __init__(self, input_size, hidden_size, output_size, activation='sigmoid'):
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        
        # Initialize weights
        self.input_weights = np.random.normal(size=[input_size, hidden_size])
        self.bias = np.random.normal(size=[hidden_size])
        self.output_weights = None
        
        # Set activation function
        if activation == 'sigmoid':
            self.activation = self.sigmoid
        elif activation == 'relu':
            self.activation = self.relu
        elif activation == 'tanh':
            self.activation = self.tanh
        else:
            raise ValueError(f"Activation function {activation} not supported")
    
    def sigmoid(self, x):
        return 1 / (1 + np.exp(-x))
    
    def relu(self, x):
        return np.maximum(0, x)
    
    def tanh(self, x):
        return np.tanh(x)
    
    def calculate_hidden_layer_output(self, X):
        hidden_layer_input = np.dot(X, self.input_weights) + self.bias
        hidden_layer_output = self.activation(hidden_layer_input)
        return hidden_layer_output
    
    def predict(self, X):
        H = self.calculate_hidden_layer_output(X)
        output = np.dot(H, self.output_weights)
        
        if self.output_size > 1:
            return np.argmax(output, axis=1)
        else:
            return (output > 0.5).astype(int).flatten()

# Load the ELM model from an h5 file
def load_elm_model_from_h5(file_path):
    try:
        with h5py.File(file_path, 'r') as hf:
            # Get model configuration
            input_size = hf.attrs['input_size']
            hidden_size = hf.attrs['hidden_size']
            output_size = hf.attrs['output_size']
            activation = hf.attrs['activation']
            
            # Create a new model
            model = ExtremeLearningMachine(
                input_size=input_size,
                hidden_size=hidden_size,
                output_size=output_size,
                activation=activation
            )
            
            # Load weights and bias
            model.input_weights = np.array(hf['input_weights'])
            model.bias = np.array(hf['bias'])
            model.output_weights = np.array(hf['output_weights'])
        
        return model
    except (FileNotFoundError, IOError) as e:
        print(f"Error loading model: {e}")
        return None

# Load model and scaler
def load_model_and_scaler():
    global elm_model, scaler
    
    # Create folders if they don't exist
    os.makedirs(os.path.join('static', 'models'), exist_ok=True)
    
    # Load the model
    model_path = os.path.join('phishing_elm_model.h5')
    if os.path.exists(model_path):
        elm_model = load_elm_model_from_h5(model_path)
        if elm_model:
            print("Model loaded successfully")
        else:
            print("Failed to load model")
    else:
        print(f"Model file not found at {model_path}")
    
    # Load the scaler
    scaler_path = os.path.join('scaler.pkl')
    if os.path.exists(scaler_path):
        try:
            with open(scaler_path, 'rb') as f:
                scaler = pickle.load(f)
            print("Scaler loaded successfully")
        except (FileNotFoundError, IOError) as e:
            print(f"Error loading scaler: {e}")
    else:
        print(f"Scaler file not found at {scaler_path}")

# Try to load model at startup
load_model_and_scaler()

# Placeholder for feature extraction functions
def extract_url_features(url):
    """Extract features from a URL for phishing detection"""
    features = {}
    
    # Parse the URL
    parsed_url = urllib.parse.urlparse(url)
    extract_result = tldextract.extract(url)
    
    # Basic URL properties
    features['url_length'] = len(url)
    features['domain_length'] = len(extract_result.domain)
    features['tld'] = extract_result.suffix
    features['has_subdomain'] = len(extract_result.subdomain) > 0
    features['path_length'] = len(parsed_url.path)
    features['has_query'] = len(parsed_url.query) > 0
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_params'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
    features['has_https'] = parsed_url.scheme == 'https'
    features['has_ip_address'] = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed_url.netloc))
    features['has_at_symbol'] = '@' in url
    features['has_double_slash'] = '//' in parsed_url.path
    
    return features

def predict_phishing(url):
    """
    Predict if a URL is a phishing site
    
    In a real application, you would:
    1. Extract features from the URL
    2. Pass features to the model for prediction
    3. Return prediction and confidence
    
    For this demo, we'll use a simple heuristic based on the URL features
    """
    features = extract_url_features(url)
    
    # Simple heuristic for demonstration
    suspicious_score = 0
    
    # Suspicious URL length (phishing URLs tend to be longer)
    if features['url_length'] > 75:
        suspicious_score += 0.1
    
    # Presence of IP address in domain
    if features['has_ip_address']:
        suspicious_score += 0.3
    
    # Presence of @ symbol
    if features['has_at_symbol']:
        suspicious_score += 0.2
    
    # Multiple subdomains or long domain name
    if features['has_subdomain'] and features['domain_length'] > 15:
        suspicious_score += 0.15
    
    # Lack of HTTPS
    if not features['has_https']:
        suspicious_score += 0.15
    
    # Double slashes in path
    if features['has_double_slash']:
        suspicious_score += 0.1
    
    # Use a deterministic value derived from the URL instead of random
    # Create a simple hash of the URL for consistent results
    url_hash = 0
    for char in url:
        url_hash = (url_hash * 31 + ord(char)) & 0xFFFFFFFF
    # Convert to a value between -0.1 and 0.1
    url_specific_variation = ((url_hash / 0xFFFFFFFF) * 0.2) - 0.1
    suspicious_score += url_specific_variation
    
    # Clamp the score between 0 and 1
    suspicious_score = max(0, min(suspicious_score, 1))
    
    # Determine if phishing based on threshold
    is_phishing = suspicious_score > 0.5
    
    # Calculate confidence (higher score = higher confidence)
    if is_phishing:
        confidence = 0.5 + (suspicious_score - 0.5) * 2  # Map 0.5-1.0 to 0.5-1.0
    else:
        confidence = 1 - suspicious_score * 2  # Map 0-0.5 to 1.0-0
        
    return {
        'prediction': 'phishing' if is_phishing else 'legitimate',
        'confidence': confidence
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({
            'error': 'No URL provided',
            'prediction': 'error',
            'confidence': 0
        }), 400
    
    try:
        # Get prediction result
        result = predict_phishing(url)
        return jsonify(result)
    except Exception as e:
        print(f"Error processing URL: {e}")
        return jsonify({
            'error': str(e),
            'prediction': 'error',
            'confidence': 0
        }), 500

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/status')
def status():
    return jsonify({
        'model_loaded': elm_model is not None,
        'scaler_loaded': scaler is not None,
        'ready': elm_model is not None and scaler is not None
    })

if __name__ == '__main__':
    # Create folders if they don't exist
    os.makedirs(os.path.join('static', 'models'), exist_ok=True)
    
    print("Starting Phishing Detection Web Application...")
    print("Model status: " + ("Loaded" if elm_model else "Not loaded"))
    print("Scaler status: " + ("Loaded" if scaler else "Not loaded"))
    print("\nMake sure to place your model files in the correct location:")
    print("- static/models/phishing_elm_model.h5")
    print("- static/models/scaler.pkl")
    print("\nIf these files don't exist, train the model using phishing_detection_elm.ipynb")
    
    app.run(debug=True) 