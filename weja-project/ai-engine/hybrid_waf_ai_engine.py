
"""
WEJÀ AI Engine - Hybrid WAF
Refactored hybrid engine:
- Weighted rule engine
- Early exit on very high rule confidence
- Logistic Regression fallback
- Decision fusion
"""

import re
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib

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

# -----------------------------
# Load ML assets
# -----------------------------
preTrainedModel = joblib.load("waf_ai_engine_logistic_regression.pkl")
label_encoder = joblib.load("label_encoder.pkl")

# -----------------------------
# ML prediction
# -----------------------------
def predict_threat(request_text: str):
    if not request_text.strip():
        return "SAFE", 0.1

    pred = preTrainedModel.predict([request_text])[0]
    probs = preTrainedModel.predict_proba([request_text])[0]
    conf = float(np.max(probs))
    label = label_encoder.inverse_transform([pred])[0]
    return label, conf

# -----------------------------
# Weighted rules
# -----------------------------
SQLI_PATTERNS = [
    # Comment markers and string terminators
    (r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(\/\*)|(\*\/)|(;--)|(\%3B--)", 20),
    
    # Equals with quotes or comments
    (r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;)|(\/\*))", 30),
    
    # 'or' and 'and' with whitespace variants
    (r"(\b(or|and|xor)\b\s+\w+\s*=\s*\w+)", 35),
    (r"(\w*\s*(or|and|xor)\s+\w+\s*=\s*\w+)", 30),
    
    # Union-based injections
    (r"((\%27)|(\')|(\%22)|(\"))\s*(union|UNION)\s+(all|ALL)?\s*select", 45),
    (r"(union|UNION)\s+(all|ALL)?\s*select\s+.*?\s+from", 40),
    
    # Stored procedures
    (r"(exec|EXEC)\s*(\s|\+)+(s|x)p_\w+", 50),
    (r"(exec|EXECUTE)\s*(\s|\+)*\(.*?\)", 40),
    
    # DML/DDL statements
    (r"\b(select|insert|update|delete|drop|truncate|alter|create|rename|replace)\s+", 25),
    
    # Always true conditions
    (r"(1\s*=\s*1|1\s*=\s*'1'|1\s*=\s*\"1\"|'1'\s*=\s*'1'|\"1\"\s*=\s*\"1\")", 35),
    (r"(\'\s*(or|and|xor)\s*\'|\"\s*(or|and|xor)\s*\")", 35),
    
    # Time-based attacks
    (r"\b(sleep|benchmark|pg_sleep|waitfor)\s*\(", 45),
    (r"waitfor\s+delay\s+['\"]\d+:\d+:\d+['\"]", 50),
    
    # Error-based injections
    (r"\b(convert|cast)\s*\(.*?\s+as\s+", 35),
    (r"\b(extractvalue|updatexml|floor)\s*\(.*?,.*?\)", 40),
    
    # Stacked queries
    (r";\s*(select|insert|update|delete|drop|truncate|alter|exec|execute)", 35),
    
    # Database-specific functions
    (r"\b(database|user|version|current_user|system_user)\s*\(\)", 30),
    (r"\b(@@version|@@datadir|@@basedir)\b", 35),
    
    # Hex/encoding evasion
    (r"0x[0-9a-fA-F]{4,}", 30),
    (r"char\s*\([\d,]+\)", 25),
    (r"unicode\s*\(['\"][^'\"]+['\"]\)", 25),
    
    # Boolean-based blind
    (r"(\b(and|or|xor)\b\s+.*?\s*[=<>!]+\s*.*?\s*(and|or|xor)?\s*\w+\s*[=<>!]+\s*\w+)", 35),
    (r"\b(substr|mid|left|right)\s*\(.*?,\s*\d+,\s*\d+\)\s*[=<>]", 35),
    
    # Information schema access
    (r"\b(information_schema|sys\.|master\.|mysql\.|performance_schema)\b", 40),
    
    # Out-of-band attacks
    (r"\b(load_file|into\s+outfile|into\s+dumpfile)\b", 50),
    (r"\b(xp_cmdshell|xp_regread|xp_regwrite)\b", 50),
    
    # Space evasion
    (r"\w+\s*\+\s*\w+\s*=\s*\w+", 25),  # 'or'+'1'='1'
    (r"(\/\*.*?\*\/)", 20),  # Inline comments
]

XSS_PATTERNS = [
    (r"<script[^>]*>.*?</script>",50),
    (r"javascript\s*:",35),
    (r"on\w+\s*=",25),
    (r"<\s*img[^>]+onerror",40),
    (r"<\s*svg[^>]+onload",40),
    (r"alert\s*\(",25),
    (r"eval\s*\(",40),
]

PATH_PATTERNS = [
    (r"\.\./",40),
    (r"\.\.\\",40),
    (r"%2e%2e%2f",40),
    (r"etc/passwd",60),
    (r"etc/shadow",60),
    (r"windows/system32",60),
]

CMD_PATTERNS = [
    (r";\s*(ls|cat|whoami|id|pwd|uname)",50),
    (r"\|\s*(ls|cat|whoami|id|pwd|uname)",50),
    (r"`[^`]+`",50),
    (r"\$\([^)]+\)",50),
    (r"&&\s*(ls|cat|whoami|id|pwd|uname)",50),
]

ATTACKS = {
    "sqli": SQLI_PATTERNS,
    "xss": XSS_PATTERNS,
    "path-traversal": PATH_PATTERNS,
    "cmdi": CMD_PATTERNS,
}

def calculate_rule_confidence(payload, patterns):
    score = 0
    matched = []

    for regex, weight in patterns:
        if re.search(regex, payload, re.IGNORECASE):
            score += weight
            matched.append(regex)

    return min(score/100.0,1.0), matched

def rule_based_detect(payload):
    payload = payload.lower()

    best_attack = "SAFE"
    best_conf = 0
    best_matches = []

    for attack, patterns in ATTACKS.items():
        conf, matches = calculate_rule_confidence(payload, patterns)
        if conf > best_conf:
            best_attack = attack
            best_conf = conf
            best_matches = matches

    return best_conf>0,best_attack,best_conf,best_matches

# -----------------------------
# Hybrid decision
# -----------------------------
def detect_attack_type(payload):

    rule_hit, rule_type, rule_conf, matches = rule_based_detect(payload)

    if rule_hit and rule_conf >= 0.95:
        return {
            "blocked": True,
            "type": rule_type,
            "confidence": round(rule_conf,2),
            "rule_confidence": round(rule_conf,2),
            "ml_confidence": None,
            "ml_prediction": None,
            "matched_rules": matches,
            "decision":"RULE_ONLY"
        }

    ml_type, ml_conf = predict_threat(payload)

    blocked=False
    final_type="SAFE"
    final_conf=max(1-ml_conf,0.05)
    decision="SAFE"

    if rule_hit:
        if ml_type==rule_type:
            blocked=True
            final_type=rule_type
            final_conf=0.4*rule_conf+0.6*ml_conf
            decision="FUSION"
        elif ml_conf>=0.9 and ml_type!="norm":
            blocked=True
            final_type=ml_type
            final_conf=ml_conf
            decision="ML_OVERRIDE"
        elif rule_conf>=0.6:
            blocked=True
            final_type=rule_type
            final_conf=rule_conf
            decision="RULE_PRIORITY"
    elif ml_type!="norm" and ml_conf>=0.75:
        blocked=True
        final_type=ml_type
        final_conf=ml_conf
        decision="ML_ONLY"

    return {
        "blocked":blocked,
        "type":final_type,
        "confidence":round(final_conf,2),
        "rule_confidence":round(rule_conf,2),
        "ml_prediction":ml_type,
        "ml_confidence":round(ml_conf,2),
        "matched_rules":matches,
        "decision":decision
    }

@app.route("/health")
def health():
    return jsonify({
        "status":"healthy",
        "engine":"Hybrid WAF",
        "ml":"Logistic Regression",
        "rules":"Weighted Rule Engine"
    })

@app.route("/analyze",methods=["POST"])
def analyze():
    try:
        data=request.get_json()
        payload=data.get("payload","")
        path=data.get("path","")
        method=data.get("method","GET")

        combined=f"{payload} {path}"

        result=detect_attack_type(combined)

        result.update({
            "payload_length":len(payload),
            "analyzed_method":method,
            "analyzed_path":path
        })

        return jsonify(result)

    except Exception as e:
        return jsonify({
            "blocked":False,
            "type":"ERROR",
            "confidence":0,
            "error":str(e)
        }),500

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000,debug=True)
