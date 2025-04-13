import streamlit as st

def init_language():
    """Initialize language selection in the sidebar"""
    if 'language' not in st.session_state:
        st.session_state.language = 'en'
    
    lang = st.sidebar.checkbox("Eesti keel", value=st.session_state.language == 'et')
    st.session_state.language = 'et' if lang else 'en'
    return st.session_state.language

# Shared translations that are common across pages
COMMON_TRANSLATIONS = {
    "en": {
        "target_website": "Target Website",
        "start_scan": "Start Scan",
        "scanning": "Scanning...",
        "scan_results": "Scan Results",
        "scan_history": "Scan History",
        "no_history": "No scan history available yet",
        "depth": "Depth",
        "basic": "Basic",
        "standard": "Standard",
        "deep": "Deep"
    },
    "et": {
        "target_website": "Sihtleht",
        "start_scan": "Alusta Skaneerimist",
        "scanning": "Skaneerin...",
        "scan_results": "Tulemused",
        "scan_history": "Ajalugu",
        "no_history": "Ajalugu puudub",
        "depth": "Sügavus",
        "basic": "Lihtne",
        "standard": "Tavaline",
        "deep": "Põhjalik"
    }
} 