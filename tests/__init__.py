import streamlit as st

# Common translations for all pages
COMMON_TRANSLATIONS = {
    "en": {
        "scan_history": "Scan History",
        "no_history": "No scan history available",
        "target_website": "Target Website",
        "start_scan": "Start Scan",
        "scan_results": "Scan Results",
        "scanning": "Scanning...",
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
        "scan_history": "Skannimise Ajalugu",
        "no_history": "Skannimise ajalugu pole saadaval",
        "target_website": "Sihtleht",
        "start_scan": "Alusta Skannimist",
        "scan_results": "Skannimise Tulemused",
        "scanning": "Skannimine...",
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

def init_language():
    """Initialize language settings"""
    if 'language' not in st.session_state:
        st.session_state.language = "en"
    return st.session_state.language
