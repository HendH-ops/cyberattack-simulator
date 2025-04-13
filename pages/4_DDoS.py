import streamlit as st
import time
import random
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from utils import init_language, COMMON_TRANSLATIONS

# Page config
st.set_page_config(
    page_title="DDoS Test",
    page_icon="🌊",
    layout="wide"
)

# Page-specific translations
PAGE_TRANSLATIONS = {
    "en": {
        "page_title": "DDoS Test",
        "description": """
This tool simulates Distributed Denial of Service (DDoS) attacks to test system resilience.
Test different types of DDoS attacks:
- TCP Flood
- UDP Flood
- HTTP Flood
- SYN Flood
- ICMP Flood
""",
        "ddos_method": "DDoS Method",
        "duration": "Test Duration (seconds)",
        "packets_per_second": "Packets per Second (thousands)",
        "traffic_analysis": "Traffic Analysis",
        "server_analysis": "Server Response Analysis",
        "total_packets": "Total Packets Sent",
        "success_rate": "Success Rate",
        "target_status": "Target Status",
        "traffic_time": "Traffic Over Time",
        "response_time": "Server Response Times",
        "packets_second": "Packets/Second",
        "response_ms": "Response Time (ms)",
        "time": "Time"
    },
    "et": {
        "page_title": "DDoS Test",
        "description": """
See tööriist simuleerib hajutatud teenusetõkestusründeid (DDoS) süsteemi vastupidavuse testimiseks.
Testi erinevaid DDoS rünnakute tüüpe:
- TCP Üleujutus
- UDP Üleujutus
- HTTP Üleujutus
- SYN Üleujutus
- ICMP Üleujutus
""",
        "ddos_method": "DDoS Meetod",
        "duration": "Testi Kestus (sekundites)",
        "packets_per_second": "Pakette Sekundis (tuhandetes)",
        "traffic_analysis": "Liikluse Analüüs",
        "server_analysis": "Serveri Vastuse Analüüs",
        "total_packets": "Saadetud Pakette Kokku",
        "success_rate": "Õnnestumise Määr",
        "target_status": "Sihtmärgi Olek",
        "traffic_time": "Liiklus Aja Jooksul",
        "response_time": "Serveri Vastuse Ajad",
        "packets_second": "Pakette/Sekundis",
        "response_ms": "Vastuse Aeg (ms)",
        "time": "Aeg"
    }
}

# Initialize session state
if 'ddos_history' not in st.session_state:
    st.session_state.ddos_history = []

# Get current language and translations
lang = init_language()
texts = {**COMMON_TRANSLATIONS[lang], **PAGE_TRANSLATIONS[lang]}

def simulate_ddos(target, method, duration, packets_per_second):
    """Simulate a DDoS test"""
    time.sleep(1)
    
    # Generate traffic data
    timestamps = pd.date_range(start='now', periods=duration, freq='1S')
    traffic = [random.gauss(packets_per_second, packets_per_second * 0.1) for _ in range(duration)]
    
    success_rate = random.uniform(0.7, 0.99)
    server_response_times = [random.uniform(100, 2000) for _ in range(duration)]
    
    return {
        "timestamps": timestamps,
        "traffic": traffic,
        "success_rate": success_rate,
        "response_times": server_response_times,
        "packets_sent": sum(traffic),
        "target_status": "overwhelmed" if success_rate > 0.8 else "stressed"
    }

# UI Components
st.title(f"🌊 {texts['page_title']}")
st.markdown(texts['description'])

# Test Configuration
col1, col2, col3 = st.columns(3)

with col1:
    target = st.text_input(texts['target_website'], "example.com")
    
with col2:
    method = st.selectbox(
        texts['ddos_method'],
        ["TCP Flood", "UDP Flood", "HTTP Flood", "SYN Flood", "ICMP Flood"],
        index=0
    )
    
with col3:
    duration = st.slider(texts['duration'], 5, 60, 10)
    packets_per_second = st.slider(texts['packets_per_second'], 1, 100, 10) * 1000

# Launch Test Button
if st.button(texts['start_scan']):
    with st.spinner(texts['scanning']):
        # Perform the test
        results = simulate_ddos(target, method, duration, packets_per_second)
        
        # Store in history
        st.session_state.ddos_history.append({
            "timestamp": datetime.now(),
            "target": target,
            "method": method,
            "duration": duration,
            "packets_sent": results["packets_sent"],
            "success_rate": results["success_rate"]
        })
        
        # Display Results
        st.header(texts['scan_results'])
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader(texts['traffic_analysis'])
            
            # Traffic over time
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=results["timestamps"],
                y=results["traffic"],
                name="Traffic",
                fill='tozeroy'
            ))
            fig.update_layout(
                title=texts['traffic_time'],
                xaxis_title=texts['time'],
                yaxis_title=texts['packets_second']
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Summary metrics
            st.metric(texts['total_packets'], f"{results['packets_sent']:,.0f}")
            st.metric(texts['success_rate'], f"{results['success_rate']:.1%}")
            
        with col2:
            st.subheader(texts['server_analysis'])
            
            # Response time graph
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=results["timestamps"],
                y=results["response_times"],
                name=texts['response_time'],
                line=dict(color='red')
            ))
            fig.update_layout(
                title=texts['response_time'],
                xaxis_title=texts['time'],
                yaxis_title=texts['response_ms']
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Target status
            st.info(f"{texts['target_status']}: {results['target_status'].upper()}")

# Test History
st.header(texts['scan_history'])
if st.session_state.ddos_history:
    history_df = pd.DataFrame(st.session_state.ddos_history)
    st.dataframe(history_df, use_container_width=True)
    
    # History visualization
    fig = px.line(history_df, 
                  x='timestamp', 
                  y=['packets_sent', 'success_rate'],
                  title=texts['scan_history'])
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info(texts['no_history']) 