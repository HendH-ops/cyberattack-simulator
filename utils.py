import streamlit as st
import hashlib

def check_auth():
    """Returns `True` if the user is authenticated."""
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    return st.session_state["authenticated"]

def login_page():
    """Shows the login page and returns True if login is successful."""
    lang = init_language()
    texts = COMMON_TRANSLATIONS[lang]
    
    st.title("🔐 " + ("Sisselogimine" if lang == "et" else "Login"))
    
    if "login_attempts" not in st.session_state:
        st.session_state["login_attempts"] = 0
    
    username = st.text_input("Kasutajanimi" if lang == "et" else "Username")
    password = st.text_input("Parool" if lang == "et" else "Password", type="password")
    
    if st.button("Logi sisse" if lang == "et" else "Login"):
        # In production, you should use proper password hashing and database
        if username == st.secrets["username"] and password == st.secrets["password"]:
            st.session_state["authenticated"] = True
            st.session_state["login_attempts"] = 0
            st.experimental_rerun()
        else:
            st.session_state["login_attempts"] += 1
            st.error("Vale kasutajanimi või parool" if lang == "et" else "Invalid username or password")
            if st.session_state["login_attempts"] >= 3:
                st.error("Liiga palju ebaõnnestunud katseid. Palun proovige hiljem uuesti." if lang == "et" else "Too many failed attempts. Please try again later.")
                st.stop()
    
    return st.session_state["authenticated"]

def require_auth():
    """Requires authentication to access the page."""
    if not check_auth():
        login_page()
        st.stop()

def init_language():
    """Initialize language selection in the sidebar"""
    if 'language' not in st.session_state:
        st.session_state.language = 'en'
    
    lang = st.sidebar.checkbox("Eesti keel", value=st.session_state.language == 'et')
    st.session_state.language = 'et' if lang else 'en'
    return st.session_state.language

# Common translations
COMMON_TRANSLATIONS = {
    "en": {
        "page_title": "Cyber Attack Simulator",
        "description": "A tool to simulate and analyze potential cyber attacks",
        "scan_type": "Scan Type",
        "quick_scan": "Quick Scan",
        "detailed_scan": "Detailed Scan",
        "start_scan": "Start Scan",
        "scanning": "Scanning...",
        "scan_completed": "Scan completed!",
        "simulated_note": "Note: These are simulated results for demonstration purposes.",
        "response_time": "Response Time",
        "seconds": "seconds",
        "basic_overview": "Basic Technology Overview",
        "quick_overview": "Quick overview of the main technologies used on the website.",
        "detected_tech": "Detected Technologies",
        "comprehensive_analysis": "Comprehensive analysis of all technologies detected on the website.",
        "ai_recommendations": "AI-Powered Test Recommendations",
        "recommendations_based": "Based on the scan results, here are recommended tests to perform:",
        "risk_tests": "Risk Tests",
        "description": "Description",
        "reason": "Reason",
        "suggested_tests": "Suggested Tests",
        "vulnerability_scanning": "Vulnerability scanning for",
        "configuration_review": "Configuration review of related components",
        "automated_testing": "Automated security testing tools",
        "go_to_test": "Go to",
        "test_not_implemented": "Test page not yet implemented",
        "network_analysis": "Network Analysis",
        "network_description": "Analysis of network performance, connections, and security configurations.",
        "connection_details": "Connection Details",
        "connection_description": "Basic information about the connection to the server.",
        "performance_metrics": "Performance Metrics",
        "performance_description": "Key metrics about page loading and response times.",
        "security_headers": "Security Headers",
        "security_description": "Security-related HTTP headers that protect against common attacks.",
        "dns_info": "DNS Information",
        "dns_description": "Domain name resolution performance and status.",
        "ssl_info": "SSL/TLS Information",
        "ssl_description": "Details about the SSL/TLS certificate and security configuration.",
        "issuer": "Issuer",
        "valid_until": "Valid Until",
        "protocol": "Protocol",
        "cipher": "Cipher",
        "seo_analysis": "SEO Analysis",
        "seo_description": "Search Engine Optimization analysis of the website content.",
        "meta_tags": "Meta Tags",
        "meta_description": "Meta tags help search engines understand your content.",
        "headers_structure": "Headers Structure",
        "headers_description": "Proper header hierarchy is important for SEO and accessibility.",
        "links_analysis": "Links Analysis",
        "links_description": "Distribution of internal and external links on the page.",
        "image_optimization": "Image Optimization",
        "image_description": "Status of image alt texts for accessibility and SEO.",
        "accessibility_analysis": "Accessibility Analysis",
        "accessibility_description": "Evaluation of website accessibility features and compliance.",
        "aria_implementation": "ARIA Implementation",
        "aria_description": "ARIA attributes help make content accessible to screen readers.",
        "form_accessibility": "Form Accessibility",
        "form_description": "Proper form labeling is crucial for accessibility.",
        "image_accessibility": "Image Accessibility",
        "image_access_description": "Alt texts help visually impaired users understand images.",
        "keyboard_navigation": "Keyboard Navigation",
        "keyboard_description": "Elements that can be accessed via keyboard navigation.",
        "performance_analysis": "Performance Analysis",
        "performance_description": "Detailed analysis of website performance metrics and optimization opportunities.",
        "page_size": "Page Size",
        "page_size_description": "Total size of the webpage and its compression status.",
        "resource_count": "Resource Count",
        "resource_description": "Number of different types of resources used on the page.",
        "loading_times": "Loading Times",
        "loading_description": "Key timing metrics for page loading performance.",
        "caching": "Caching",
        "caching_description": "Browser caching configuration for better performance.",
        "port_scan": "Port Scan Results",
        "port_description": "Analysis of open network ports and potential security implications.",
        "open_ports": "Open Ports",
        "open_ports_description": "Ports that are currently accepting connections.",
        "closed_ports": "Closed/Filtered Ports",
        "closed_ports_description": "Ports that are either closed or filtered by a firewall.",
        "scan_history": "Scan History",
        "scan_statistics": "Scan Statistics",
        "no_history": "No scan history available"
    },
    "et": {
        "page_title": "Küberrünnaku Simulaator",
        "description": "Tööriist potentsiaalsete küberrünnakute simuleerimiseks ja analüüsimiseks",
        "scan_type": "Skannimise Tüüp",
        "quick_scan": "Kiirskann",
        "detailed_scan": "Detailne Skann",
        "start_scan": "Alusta Skannimist",
        "scanning": "Skannimine...",
        "scan_completed": "Skannimine lõpetatud!",
        "simulated_note": "Märkus: Need on simuleeritud tulemused demonstratsiooni eesmärgil.",
        "response_time": "Vastuse Aeg",
        "seconds": "sekundit",
        "basic_overview": "Põhiline Tehnoloogia Ülevaade",
        "quick_overview": "Kiire ülevaade veebilehel kasutatavatest põhitehnoloogiatest.",
        "detected_tech": "Tuvastatud Tehnoloogiad",
        "comprehensive_analysis": "Põhjalik analüüs kõigist veebilehel tuvastatud tehnoloogiatest.",
        "ai_recommendations": "AI-põhised Testimissoovitused",
        "recommendations_based": "Skannimistulemuste põhjal on soovitatavad järgmised testid:",
        "risk_tests": "Riskitaseme Testid",
        "description": "Kirjeldus",
        "reason": "Põhjus",
        "suggested_tests": "Soovitatavad Testid",
        "vulnerability_scanning": "Turvanõrkuste skannimine",
        "configuration_review": "Seadistuste läbivaatus",
        "automated_testing": "Automatiseeritud turvatestid",
        "go_to_test": "Mine testile",
        "test_not_implemented": "Testi leht pole veel loodud",
        "network_analysis": "Võrgu Analüüs",
        "network_description": "Võrgu jõudluse, ühenduste ja turvaseadistuste analüüs.",
        "connection_details": "Ühenduse Detailid",
        "connection_description": "Põhiteave serveriga ühenduse kohta.",
        "performance_metrics": "Jõudluse Mõõdikud",
        "performance_description": "Põhilised mõõdikud lehe laadimise ja vastuse aja kohta.",
        "security_headers": "Turva Päised",
        "security_description": "Turvapäised, mis kaitsevad tavaliste rünnakute eest.",
        "dns_info": "DNS Info",
        "dns_description": "Domeeninime lahendamise jõudlus ja olek.",
        "ssl_info": "SSL/TLS Info",
        "ssl_description": "SSL/TLS sertifikaadi ja turvaseadistuste detailid.",
        "issuer": "Väljaandja",
        "valid_until": "Kehtiv Kuni",
        "protocol": "Protokoll",
        "cipher": "Šifr",
        "seo_analysis": "SEO Analüüs",
        "seo_description": "Otsingumootorite optimeerimise analüüs veebilehe sisu kohta.",
        "meta_tags": "Meta Sildid",
        "meta_description": "Meta sildid aitavad otsingumootoritel mõista teie sisu.",
        "headers_structure": "Päiste Struktuur",
        "headers_description": "Õige päiste hierarhia on oluline nii SEO kui ka ligipääsetavuse jaoks.",
        "links_analysis": "Linkide Analüüs",
        "links_description": "Sise- ja välislinkide jaotus lehel.",
        "image_optimization": "Piltide Optimeerimine",
        "image_description": "Piltide alt-tekstide olek ligipääsetavuse ja SEO jaoks.",
        "accessibility_analysis": "Ligipääsetavuse Analüüs",
        "accessibility_description": "Veebilehe ligipääsetavuse funktsioonide ja vastavuse hindamine.",
        "aria_implementation": "ARIA Rakendamine",
        "aria_description": "ARIA atribuudid aitavad ekraanilugijatel sisu mõista.",
        "form_accessibility": "Vormide Ligipääsetavus",
        "form_description": "Õige vormide märgistus on oluline ligipääsetavuse jaoks.",
        "image_accessibility": "Piltide Ligipääsetavus",
        "image_access_description": "Alt-tekstid aitavad nägemispuudega kasutajatel pilte mõista.",
        "keyboard_navigation": "Klaviatuuri Navigatsioon",
        "keyboard_description": "Elemendid, mida saab klaviatuuri kaudu kasutada.",
        "performance_analysis": "Jõudluse Analüüs",
        "performance_description": "Põhjalik analüüs veebilehe jõudluse mõõdikutest ja optimeerimisvõimalustest.",
        "page_size": "Lehe Suurus",
        "page_size_description": "Veebilehe kogusuurus ja selle tihendamise olek.",
        "resource_count": "Ressursside Arv",
        "resource_description": "Erinevate tüüpi ressursside arv lehel.",
        "loading_times": "Laadimise Ajad",
        "loading_description": "Põhilised mõõdikud lehe laadimise jõudluse kohta.",
        "caching": "Vahemälu",
        "caching_description": "Brauseri vahemälu seadistus parema jõudluse jaoks.",
        "port_scan": "Portide Skannimise Tulemused",
        "port_description": "Avatud võrgupartide analüüs ja võimalikud turvariskid.",
        "open_ports": "Avatud Pordid",
        "open_ports_description": "Pordid, mis aktiivselt vastuvõtavad ühendusi.",
        "closed_ports": "Suletud/Filtreeritud Pordid",
        "closed_ports_description": "Pordid, mis on kas suletud või tulemüüri poolt filtreeritud.",
        "scan_history": "Skannimise Ajalugu",
        "scan_statistics": "Skannimise Statistika",
        "no_history": "Skannimise ajalugu pole saadaval"
    }
} 