import streamlit as st
import time
import random
import pandas as pd
import plotly.express as px
from datetime import datetime
from utils import init_language, COMMON_TRANSLATIONS

# Page config
st.set_page_config(
    page_title="Cyber Attack Simulator",
    page_icon="🛡️",
    layout="wide"
)

# Page-specific translations
PAGE_TRANSLATIONS = {
    "en": {
        "page_title": "Cyber Attack Simulator",
        "description": """
This tool simulates various types of cyber attacks to test system security.
Select an attack type to begin testing:
- Scan: Analyze target system for vulnerabilities
- XSS: Test for Cross-Site Scripting vulnerabilities
- SQL: Test for SQL Injection vulnerabilities
- DDoS: Test system resilience against DDoS attacks
""",
        "attack_type": "Attack Type",
        "target_website": "Target Website",
        "start_attack": "Start Attack",
        "scanning": "Scanning...",
        "attack_results": "Attack Results",
        "attack_history": "Attack History",
        "no_history": "No attack history available yet",
        "vulnerabilities": "Vulnerabilities",
        "severity": "Severity",
        "impact": "Impact",
        "recommendations": "Recommendations",
        "attack_trends": "Attack Trends",
        "success_rate": "Success Rate",
        "attack_count": "Attack Count"
    },
    "et": {
        "page_title": "Küberrünnakute Simulaator",
        "description": """
See tööriist simuleerib erinevaid küberrünnakuid süsteemi turvalisuse testimiseks.
Vali rünnaku tüüp testimise alustamiseks:
- Skaneerimine: Analüüsi sihtsüsteemi haavatavusi
- XSS: Testi veebilehtede skriptide süstimise haavatavusi
- SQL: Testi SQL süstimise haavatavusi
- DDoS: Testi süsteemi vastupidavust DDoS rünnakutele
""",
        "attack_type": "Rünnaku Tüüp",
        "target_website": "Sihtleht",
        "start_attack": "Alusta Rünnakut",
        "scanning": "Skaneerin...",
        "attack_results": "Rünnaku Tulemused",
        "attack_history": "Rünnakute Ajalugu",
        "no_history": "Rünnakute ajalugu puudub",
        "vulnerabilities": "Haavatavused",
        "severity": "Raskusaste",
        "impact": "Mõju",
        "recommendations": "Soovitused",
        "attack_trends": "Rünnakute Trendid",
        "success_rate": "Õnnestumise Määr",
        "attack_count": "Rünnakute Arv"
    }
}

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
    st.session_state.attack_history = []

# Get current language and translations
lang = init_language()
texts = {**COMMON_TRANSLATIONS[lang], **PAGE_TRANSLATIONS[lang]}

def simulate_attack(target, attack_type):
    """Simulate a cyber attack"""
    time.sleep(1)
    
    # Common vulnerabilities
    vulnerabilities = {
        "scan": [
            "Open Ports",
            "Outdated Software",
            "Weak Passwords",
            "Missing Security Headers",
            "Exposed Services"
        ],
        "xss": [
            "Reflected XSS",
            "Stored XSS",
            "DOM-based XSS",
            "Input Validation Issues"
        ],
        "sql": [
            "SQL Injection",
            "Database Configuration Issues",
            "Exposed Database Credentials"
        ],
        "ddos": [
            "Resource Exhaustion",
            "Connection Flood",
            "Application Layer Vulnerabilities"
        ]
    }
    
    # Generate random results
    found_vulnerabilities = random.sample(
        vulnerabilities[attack_type],
        random.randint(1, len(vulnerabilities[attack_type]))
    )
    
    return {
        "success": random.random() > 0.3,  # 70% chance of success
        "vulnerabilities": found_vulnerabilities,
        "severity": random.choice(["Low", "Medium", "High", "Critical"]),
        "impact": random.choice(["Minimal", "Moderate", "Significant", "Severe"]),
        "recommendations": [
            "Update all software to latest versions",
            "Implement proper input validation",
            "Configure firewall rules",
            "Enable security headers",
            "Regular security audits"
        ]
    }

# UI Components
st.title(f"🛡️ {texts['page_title']}")
st.markdown(texts['description'])

# Attack Configuration
col1, col2 = st.columns(2)

with col1:
    target = st.text_input(texts['target_website'], "example.com")
    
with col2:
    attack_type = st.selectbox(
        texts['attack_type'],
        ["scan", "xss", "sql", "ddos"],
        index=0
    )

# Launch Attack Button
if st.button(texts['start_attack']):
    with st.spinner(texts['scanning']):
        # Perform the attack
        results = simulate_attack(target, attack_type)
        
        # Store in history
        st.session_state.attack_history.append({
            "timestamp": datetime.now(),
            "target": target,
            "type": attack_type,
            "success": results["success"],
            "severity": results["severity"]
        })
        
        # Display Results
        st.header(texts['attack_results'])
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Attack success
            if results["success"]:
                st.success("Attack Successful!")
            else:
                st.error("Attack Failed - Target Defenses Active")
            
            # Vulnerabilities found
            st.subheader(texts['vulnerabilities'])
            for vuln in results["vulnerabilities"]:
                st.write(f"• {vuln}")
            
            # Severity and impact
            st.metric(texts['severity'], results["severity"])
            st.metric(texts['impact'], results["impact"])
        
        with col2:
            # Recommendations
            st.subheader(texts['recommendations'])
            for rec in results["recommendations"]:
                st.write(f"• {rec}")
            
            # Create visualization of attack trends
            if st.session_state.attack_history:
                history_df = pd.DataFrame(st.session_state.attack_history)
                fig = px.line(history_df,
                            x='timestamp',
                            y='success',
                            title=texts['attack_trends'])
                st.plotly_chart(fig, use_container_width=True)

# Attack History
st.header(texts['attack_history'])
if st.session_state.attack_history:
    history_df = pd.DataFrame(st.session_state.attack_history)
    st.dataframe(history_df, use_container_width=True)
    
    # History visualization
    fig = px.bar(history_df,
                 x='timestamp',
                 y=['success'],
                 title=texts['attack_trends'])
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info(texts['no_history']) 