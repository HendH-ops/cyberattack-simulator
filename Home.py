import streamlit as st
import time
import random
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from collections import deque

# Page config
st.set_page_config(
    page_title="Cyber Attack Simulator",
    page_icon="🛡️",
    layout="wide"
)

# Authentication
def check_password():
    """Returns `True` if the user had the correct password."""

    def password_entered():
        """Checks whether a password entered by the user is correct."""
        if st.session_state["username"] == "simulator" and st.session_state["password"] == "tallinn2025":
            st.session_state["password_correct"] = True
            del st.session_state["password"]  # Don't store password
            del st.session_state["username"]  # Don't store username
        else:
            st.session_state["password_correct"] = False

    # First run, show inputs for username + password.
    if "password_correct" not in st.session_state:
        st.text_input("Username", on_change=password_entered, key="username")
        st.text_input("Password", type="password", on_change=password_entered, key="password")
        return False
    # Password not correct, show input + error.
    elif not st.session_state["password_correct"]:
        st.text_input("Username", on_change=password_entered, key="username")
        st.text_input("Password", type="password", on_change=password_entered, key="password")
        st.error("😕 User not known or password incorrect")
        return False
    # Password correct.
    else:
        return True

if not check_password():
    st.stop()  # Do not continue if check_password is not True.

# Initialize session state
if 'attack_history' not in st.session_state:
    st.session_state.attack_history = deque(maxlen=100)
if 'ai_model' not in st.session_state:
    st.session_state.ai_model = RandomForestClassifier(n_estimators=100)
    st.session_state.model_initialized = False

def prepare_attack_features(attack_data):
    """Convert attack data into numerical features"""
    attack_types = ['ddos', 'sql', 'xss', 'scan', 'password', 'mitm']
    attack_type = [1 if attack_data['type'] == t else 0 for t in attack_types]
    intensity = float(attack_data.get('intensity', 0.5))
    duration = float(attack_data.get('duration', 1))
    return np.array(attack_type + [intensity, duration]).reshape(1, -1)

def calculate_risk_level(probability):
    """Convert probability to risk level"""
    if probability < 0.3:
        return 'LOW'
    elif probability < 0.7:
        return 'MEDIUM'
    return 'HIGH'

def generate_countermeasures(attack_type, risk_prob):
    """Generate specific countermeasures based on attack type and risk"""
    countermeasures = {
        'ddos': ['Enable DDoS protection', 'Increase bandwidth', 'Implement rate limiting'],
        'sql': ['Update WAF rules', 'Implement input validation', 'Use prepared statements'],
        'xss': ['Enable CSP', 'Implement XSS filters', 'Sanitize inputs'],
        'scan': ['Configure firewall', 'Hide service banners', 'Implement port knocking'],
        'password': ['Implement 2FA', 'Enforce strong passwords', 'Add rate limiting'],
        'mitm': ['Enforce HTTPS', 'Implement certificate pinning', 'Enable HSTS']
    }
    measures = countermeasures.get(attack_type, [])
    num_measures = 1 if risk_prob < 0.3 else (2 if risk_prob < 0.7 else 3)
    return random.sample(measures, min(num_measures, len(measures)))

def simulate_attack(attack_type, target, params):
    """Simulate different types of attacks"""
    if attack_type == 'ddos':
        packets = int(params.get('intensity', 0.5) * 1000)
        time.sleep(1)
        success_rate = random.uniform(0.7, 0.99)
        return {
            "success": True,
            "packets_sent": packets,
            "success_rate": success_rate,
            "target_status": "overwhelmed" if success_rate > 0.8 else "stressed"
        }
    elif attack_type == 'sql':
        time.sleep(1)
        return {
            "success": True,
            "vulnerable_fields": ["username", "password", "search"],
            "data_exposed": random.randint(100, 1000)
        }
    elif attack_type == 'xss':
        time.sleep(1)
        return {
            "success": True,
            "payload_executed": True,
            "affected_pages": random.randint(1, 5)
        }
    return {"error": "Invalid attack type"}

def analyze_attack(attack_data):
    """Analyze attack and provide AI insights"""
    features = prepare_attack_features(attack_data)
    
    if not st.session_state.model_initialized:
        risk = random.uniform(0.3, 0.8)
    else:
        risk = st.session_state.ai_model.predict_proba(features)[0][1]
    
    countermeasures = generate_countermeasures(attack_data['type'], risk)
    
    st.session_state.attack_history.append({
        'features': features[0],
        'success': risk > 0.5
    })
    
    if len(st.session_state.attack_history) >= 10:
        X = np.array([d['features'] for d in st.session_state.attack_history])
        y = np.array([d['success'] for d in st.session_state.attack_history])
        st.session_state.ai_model.fit(X, y)
        st.session_state.model_initialized = True
    
    return {
        'risk_level': calculate_risk_level(risk),
        'success_probability': float(risk),
        'countermeasures': countermeasures
    }

# UI Components
st.title("🛡️ Cyber Attack Simulator")

# Sidebar for attack configuration
with st.sidebar:
    st.header("Attack Configuration")
    attack_type = st.selectbox(
        "Attack Type",
        ["ddos", "sql", "xss", "scan", "password", "mitm"]
    )
    target = st.text_input("Target", "example.com")
    intensity = st.slider("Attack Intensity", 0.1, 1.0, 0.5)
    duration = st.slider("Duration (seconds)", 1, 60, 10)

# Main content
col1, col2 = st.columns(2)

with col1:
    st.header("Attack Simulation")
    if st.button("Launch Attack"):
        with st.spinner("Simulating attack..."):
            attack_data = {
                'type': attack_type,
                'target': target,
                'intensity': intensity,
                'duration': duration
            }
            
            # Simulate attack
            attack_result = simulate_attack(attack_type, target, attack_data)
            
            # Get AI analysis
            ai_analysis = analyze_attack(attack_data)
            
            # Display results
            st.subheader("Attack Results")
            st.json(attack_result)
            
            st.subheader("AI Analysis")
            st.metric("Risk Level", ai_analysis['risk_level'])
            st.metric("Success Probability", f"{ai_analysis['success_probability']:.2%}")
            
            st.subheader("Recommended Countermeasures")
            for measure in ai_analysis['countermeasures']:
                st.write(f"• {measure}")

with col2:
    st.header("Attack History")
    if st.session_state.attack_history:
        history_data = list(st.session_state.attack_history)
        st.write(f"Total attacks simulated: {len(history_data)}")
        st.write(f"Model trained: {'Yes' if st.session_state.model_initialized else 'No'}")
    else:
        st.write("No attacks simulated yet") 