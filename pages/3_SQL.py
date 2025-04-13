import streamlit as st
import time
import random
import pandas as pd
import plotly.express as px
from datetime import datetime
from utils import init_language, COMMON_TRANSLATIONS

# Page config
st.set_page_config(
    page_title="SQL Injection Test",
    page_icon="💉",
    layout="wide"
)

# Page-specific translations
PAGE_TRANSLATIONS = {
    "en": {
        "page_title": "SQL Injection Test",
        "description": """
This tool simulates SQL injection attacks to test database security.
Test different types of SQL injections:
- Union Based
- Error Based
- Blind Boolean
- Time Based
- Stacked Queries
""",
        "injection_type": "Injection Type",
        "test_parameters": "Test Parameters",
        "vulnerability_analysis": "Vulnerability Analysis",
        "database_detected": "Detected Database",
        "severity_level": "Severity Level",
        "discovered_tables": "Discovered Tables",
        "vulnerable_params": "Vulnerable Parameters",
        "data_leak_analysis": "Data Leak Analysis",
        "table": "Table",
        "database_structure": "Database Structure Overview",
        "tables_found": "Tables Found",
        "vulnerabilities": "Vulnerabilities"
    },
    "et": {
        "page_title": "SQL Süstimine Test",
        "description": """
See tööriist simuleerib SQL süstimisrünnakuid andmebaasi turvalisuse testimiseks.
Testi erinevaid SQL süstimise tüüpe:
- Ühenduspõhine (Union Based)
- Veapõhine (Error Based)
- Pimesüstimine (Blind Boolean)
- Ajapõhine (Time Based)
- Mitmiksüstimine (Stacked Queries)
""",
        "injection_type": "Süstimise Tüüp",
        "test_parameters": "Testi Parameetrid",
        "vulnerability_analysis": "Haavatavuse Analüüs",
        "database_detected": "Tuvastatud Andmebaas",
        "severity_level": "Raskusaste",
        "discovered_tables": "Leitud Tabelid",
        "vulnerable_params": "Haavatavad Parameetrid",
        "data_leak_analysis": "Andmelekke Analüüs",
        "table": "Tabel",
        "database_structure": "Andmebaasi Struktuuri Ülevaade",
        "tables_found": "Leitud Tabelid",
        "vulnerabilities": "Haavatavused"
    }
}

# Initialize session state
if 'sql_history' not in st.session_state:
    st.session_state.sql_history = []

# Get current language and translations
lang = init_language()
texts = {**COMMON_TRANSLATIONS[lang], **PAGE_TRANSLATIONS[lang]}

def simulate_sql_injection(target, injection_type, parameters):
    """Simulate SQL injection test"""
    time.sleep(1)
    
    # Common database tables to "discover"
    sample_tables = ["users", "accounts", "customers", "products", "orders", "employees"]
    sample_columns = {
        "users": ["id", "username", "password", "email"],
        "accounts": ["id", "user_id", "balance", "account_type"],
        "customers": ["id", "name", "address", "phone"],
    }
    
    # Generate test results
    discovered_tables = random.sample(sample_tables, random.randint(2, 4))
    vulnerable_params = random.sample(parameters, random.randint(1, len(parameters)))
    
    # Generate sample data leaks
    data_leaks = []
    for table in discovered_tables[:2]:  # Show leaks from up to 2 tables
        if table in sample_columns:
            columns = sample_columns[table]
            num_records = random.randint(3, 8)
            for _ in range(num_records):
                data_leaks.append({
                    "table": table,
                    "data": {col: f"sample_{col}_{random.randint(1000, 9999)}" for col in columns}
                })
    
    return {
        "success": True,
        "discovered_tables": discovered_tables,
        "vulnerable_parameters": vulnerable_params,
        "data_leaks": data_leaks,
        "database_type": random.choice(["MySQL", "PostgreSQL", "MSSQL", "Oracle"]),
        "severity": random.choice(["Low", "Medium", "High", "Critical"])
    }

# UI Components
st.title(f"💉 {texts['page_title']}")
st.markdown(texts['description'])

# Test Configuration
col1, col2 = st.columns(2)

with col1:
    target = st.text_input(texts['target_website'], "http://example.com/login")
    injection_type = st.selectbox(
        texts['injection_type'],
        ["Union Based", "Error Based", "Blind Boolean", "Time Based", "Stacked Queries"],
        index=0
    )

with col2:
    parameters = st.multiselect(
        texts['test_parameters'],
        ["username", "password", "search", "id", "category", "order"],
        default=["username", "password"]
    )

# Launch Test Button
if st.button(texts['start_scan']):
    with st.spinner(texts['scanning']):
        # Perform the test
        results = simulate_sql_injection(target, injection_type, parameters)
        
        # Store in history
        st.session_state.sql_history.append({
            "timestamp": datetime.now(),
            "target": target,
            "injection_type": injection_type,
            "tables_found": len(results["discovered_tables"]),
            "vulnerabilities": len(results["vulnerable_parameters"]),
            "severity": results["severity"]
        })
        
        # Display Results
        st.header(texts['scan_results'])
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader(texts['vulnerability_analysis'])
            
            # Database info
            st.info(f"{texts['database_detected']}: {results['database_type']}")
            st.error(f"{texts['severity_level']}: {results['severity']}")
            
            # Discovered tables
            st.write(f"📊 {texts['discovered_tables']}:")
            for table in results["discovered_tables"]:
                st.code(table)
            
            # Vulnerable parameters
            st.write(f"🎯 {texts['vulnerable_params']}:")
            for param in results["vulnerable_parameters"]:
                st.code(param)
        
        with col2:
            st.subheader(texts['data_leak_analysis'])
            
            if results["data_leaks"]:
                for leak in results["data_leaks"]:
                    with st.expander(f"{texts['table']}: {leak['table']}"):
                        st.json(leak["data"])
            
            # Create visualization of data structure
            tables_data = []
            for table in results["discovered_tables"]:
                tables_data.append({
                    "table": table,
                    "columns": len(sample_columns.get(table, [])),
                    "type": "Structure"
                })
            
            if tables_data:
                df_tables = pd.DataFrame(tables_data)
                fig = px.bar(df_tables, 
                           x='table', 
                           y='columns',
                           title=texts['database_structure'])
                st.plotly_chart(fig, use_container_width=True)

# Test History
st.header(texts['scan_history'])
if st.session_state.sql_history:
    history_df = pd.DataFrame(st.session_state.sql_history)
    st.dataframe(history_df, use_container_width=True)
    
    # History visualization
    fig = px.line(history_df, 
                  x='timestamp', 
                  y=[texts['tables_found'], texts['vulnerabilities']],
                  title=texts['scan_history'])
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info(texts['no_history']) 