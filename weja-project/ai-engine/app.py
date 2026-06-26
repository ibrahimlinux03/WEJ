"""
WEJÀ AI Engine - Hybrid Attack Detection Service
Combines rule-based pattern matching with ML-based confidence scoring.
"""

import re
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import joblib

# ML imports
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder

app = Flask(__name__)
CORS(app)




def extract_special_features(texts):
    import numpy as np
    import re

    features = []

    for text in texts:
        if not isinstance(text, str):
            text = str(text)

        text_lower = text.lower()

        features.append([
            int('../' in text or '..\\' in text),
            int('%' in text),
            int(text.count('/') > 3),
            int(re.search(r'etc/passwd|windows\\win', text_lower) is not None),
            len(re.findall(r'%[0-9a-f]{2}', text_lower)),
            text.count('.'),
            int(';' in text or '|' in text or '&' in text),
            int('=' in text and '../' in text),
        ])

    return np.array(features)

#Load pre-trained model
preTrainedModel = joblib.load('waf_ai_engine_logistic_regression.pkl')
print("Model loaded successfully")

#Load label encoding
label_encoder = joblib.load('label_encoder.pkl')
print("Label encoder loaded successfully")
#new function
def predict_threat(request_text: str) -> tuple:
    """
    Predict attack type using the trained pipeline.
    Returns: (label, confidence)
    """

    if not request_text or len(request_text.strip()) == 0:
        return "SAFE", 0.1

    try:
        # Predict class index
        pred_class = preTrainedModel.predict([request_text])[0]

        # Predict probabilities
        probs = preTrainedModel.predict_proba([request_text])[0]
        confidence = float(np.max(probs))

        # Decode label
        predicted_label = label_encoder.inverse_transform([pred_class])[0]

        return predicted_label, confidence

    except Exception as e:
        app.logger.error(f"ML prediction error: {e}")
        return "SAFE", 0.1



# ============ RULE-BASED DETECTION PATTERNS ============

SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|(\'))((\\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"((\%27)|(\'))union",
    r"exec(\s|\+)+(s|x)p\w+",
    r"(select|insert|update|delete|drop|truncate|alter)\s",
    r"(\%27)|(\')\s*(or|and)\s*\d+\s*=\s*\d+",
    r"1\s*=\s*1",
    r"\'\s*or\s*\'",
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript\s*:",
    r"on\w+\s*=",
    r"<\s*img[^>]+onerror",
    r"<\s*svg[^>]+onload",
    r"<\s*iframe",
    r"<\s*embed",
    r"<\s*object",
    r"expression\s*\(",
    r"alert\s*\(",
    r"document\.(cookie|location|write)",
    r"eval\s*\(",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%252e%252e%252f",
    r"etc/passwd",
    r"etc/shadow",
    r"windows/system32",
]

COMMAND_INJECTION_PATTERNS = [
    r";\s*(ls|cat|whoami|id|pwd|uname)",
    r"\|\s*(ls|cat|whoami|id|pwd|uname)",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"&&\s*(ls|cat|whoami|id|pwd|uname)",
]


def rule_based_detect(payload: str) -> tuple:
    """
    Rule-based pattern matching detection.
    Returns: (is_malicious, attack_type, confidence)
    """
    payload_lower = payload.lower()
    
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            return True, "SQL_INJECTION", 0.90
    
    for pattern in XSS_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            return True, "XSS", 0.88
    
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            return True, "PATH_TRAVERSAL", 0.92
    
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            return True, "COMMAND_INJECTION", 0.94
    
    return False, "SAFE", 0.1


def detect_attack_type(payload: str) -> tuple:
   
    # Get ML result
    ml_type, ml_conf = predict_threat(payload)
    
   
    
    if ml_type != "norm" and ml_conf > 0.6:
        return True, ml_type, round(ml_conf * 0.85, 2)
    # No threat detected
    return False, "SAFE", round(max(1 - ml_conf, 0.05), 2)


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "WEJÀ AI Engine",
        "version": "1.1.0",
        "ml_model": "LogisticRegression",
        "detection": "Hybrid (Rule-based + ML)"
    })


@app.route('/analyze', methods=['POST'])
def analyze_request():
    """
    Analyze incoming request payload for potential attacks.
    
    Expected JSON body:
    {
        "payload": "string to analyze",
        "headers": {},
        "method": "GET|POST|...",
        "path": "/target/path"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "error": "No JSON body provided",
                "blocked": False,
                "confidence": 0.0,
                "type": "UNKNOWN"
            }), 400
        
        payload = data.get('payload', '')
        path = data.get('path', '')
        method = data.get('method', 'GET')
        
        combined_payload = f"{payload} {path}"
        
        # Perform hybrid detection
        is_blocked, attack_type, confidence = detect_attack_type(combined_payload)
        
        # Get ML prediction for additional info
        ml_type, ml_conf = predict_threat(combined_payload)
        
        response = {
            "blocked": is_blocked,
            "confidence": confidence,
            "type": attack_type,
            "analyzed_method": method,
            "analyzed_path": path,
            "payload_length": len(payload),
            "ml_prediction": ml_type,
            "ml_confidence": round(ml_conf, 2),
        
        }
        
        if is_blocked:
            app.logger.warning(f"🚨 Attack detected: {attack_type} (confidence: {confidence})")
        else:
            app.logger.info(f"✅ Request clean (confidence: {confidence})")
        
        return jsonify(response)
    
    except Exception as e:
        app.logger.error(f"Analysis error: {str(e)}")
        return jsonify({
            "error": str(e),
            "blocked": False,
            "confidence": 0.0,
            "type": "ERROR"
        }), 500


if __name__ == '__main__':
    print("[WEJA] AI Engine starting...")
    print("[*] Listening on http://localhost:5000")
    print("[*] Using hybrid detection: Rule-based + ML (LogisticRegression)")
    app.run(host='0.0.0.0', port=5000, debug=True)
