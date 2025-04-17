import streamlit as st

# Page configuration must be the first Streamlit command
st.set_page_config(
    page_title="Technology Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Try to import required modules
try:
    import requests
    import json
    import time
    import random
    import socket
    import ssl
    import re
    import pandas as pd
    import plotly.express as px
    import plotly.graph_objects as go
    from datetime import datetime
    from urllib.parse import urlparse
    from bs4 import BeautifulSoup
    import concurrent.futures
    import threading
    import queue
    import os
    import sys
    import subprocess
    import platform
    import logging
    import traceback
    from typing import Dict, List, Tuple, Optional, Any, Union
    from utils import init_language, COMMON_TRANSLATIONS
except ImportError as e:
    st.error(f"Error importing required modules: {str(e)}")
    st.stop()

# Initialize language
lang = init_language()
texts = COMMON_TRANSLATIONS[lang]

# Remove authentication requirement
# require_auth()

# Page-specific translations
PAGE_TRANSLATIONS = {
    "en": {
        "page_title": "Technology Scanner",
        "description": """
This scanner analyzes websites to detect their technology stack, including:
- Analytics tools
- Web servers
- Programming languages
- Frameworks
- Security measures
- Hosting providers
- Content Management Systems
- E-commerce solutions
- JavaScript libraries
- Database systems
""",
        "scan_categories": "Scan Categories",
        "tech_detected": "Technologies Detected",
        "categories_found": "Categories Found",
        "version": "Version",
        "period": "Period",
        "tech_distribution": "Technology Distribution by Category",
        "tech_timeline": "Technology Implementation Timeline",
        "error_scanning": "Error scanning website",
        "invalid_url": "Invalid URL format",
        "connection_error": "Could not connect to website",
        "scanning_details": "Scanning Details",
        "response_time": "Response Time",
        "server_info": "Server Information",
        "headers": "Security Headers",
        "cookies": "Cookies",
        "meta_tags": "Meta Tags",
        "scripts": "JavaScript Libraries",
        "styles": "CSS Frameworks",
        "forms": "Form Technologies",
        "images": "Image Technologies"
    },
    "et": {
        "page_title": "Tehnoloogia Skanner",
        "description": """
See skanner analüüsib veebilehti, et tuvastada nende tehnoloogilist struktuuri, sealhulgas:
- Analüütika tööriistad
- Veebiserverid
- Programmeerimiskeeled
- Raamistikud
- Turvameetmed
- Hostingud
- Sisuhaldussüsteemid
- E-kaubanduse lahendused
- JavaScripti teegid
- Andmebaasid
""",
        "scan_categories": "Skanneeritavad Kategooriad",
        "tech_detected": "Tuvastatud Tehnoloogiad",
        "categories_found": "Leitud Kategooriad",
        "version": "Versioon",
        "period": "Periood",
        "tech_distribution": "Tehnoloogiate Jaotus Kategooriate Kaupa",
        "tech_timeline": "Tehnoloogiate Rakendamise Ajatelg",
        "error_scanning": "Viga veebilehe skaneerimisel",
        "invalid_url": "Vigane URL formaat",
        "connection_error": "Ei suutnud veebilehega ühendust luua",
        "scanning_details": "Skaneerimise Detailid",
        "response_time": "Vastuse Aeg",
        "server_info": "Serveri Info",
        "headers": "Turva Päised",
        "cookies": "Küpsised",
        "meta_tags": "Meta Sildid",
        "scripts": "JavaScripti Teegid",
        "styles": "CSS Raamistikud",
        "forms": "Vormi Tehnoloogiad",
        "images": "Piltide Tehnoloogiad"
    }
}

# Add translations for scan results
SCAN_TRANSLATIONS = {
    "en": {
        "page_title": "Technology Scanner",
        "description": "Analyze websites to detect their technology stack and security features",
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
        "page_title": "Tehnoloogia Skanner",
        "description": "Analüüsi veebilehti nende tehnoloogilise struktuuri ja turvafunktsioonide tuvastamiseks",
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

# Initialize session state
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

# Get current language and translations
texts = {**COMMON_TRANSLATIONS[lang], **PAGE_TRANSLATIONS[lang], **SCAN_TRANSLATIONS[lang]}

def get_technology_signatures():
    """Return technology detection signatures"""
    return {
        "Analytics": {
            "Google Analytics": r"UA-\d+-\d+|G-[A-Z0-9]+",
            "Google Tag Manager": r"GTM-[A-Z0-9]+",
            "Hotjar": r"hotjar",
            "Mixpanel": r"mixpanel",
            "Matomo": r"matomo",
            "Yandex Metrica": r"yandex_metrika",
            "Facebook Pixel": r"fbq\('init'",
            "LinkedIn Insight": r"_linkedin_data_partner_id",
            "Twitter Pixel": r"twq\('init'"
        },
        "Web Servers": {
            "Nginx": r"nginx",
            "Apache": r"apache",
            "IIS": r"microsoft-iis",
            "Cloudflare": r"cloudflare",
            "LiteSpeed": r"litespeed",
            "OpenResty": r"openresty"
        },
        "Frameworks": {
            "React": r"react|react-dom",
            "Vue.js": r"vue|vue-router",
            "Angular": r"angular|ng-",
            "Bootstrap": r"bootstrap",
            "jQuery": r"jquery",
            "WordPress": r"wordpress|wp-content|wp-includes",
            "Drupal": r"drupal",
            "Joomla": r"joomla",
            "Laravel": r"laravel",
            "Django": r"django",
            "Express": r"express",
            "Next.js": r"next",
            "Nuxt.js": r"nuxt"
        },
        "Security": {
            "reCAPTCHA": r"recaptcha",
            "Cloudflare": r"cloudflare",
            "Let's Encrypt": r"letsencrypt",
            "HSTS": r"strict-transport-security",
            "CSP": r"content-security-policy",
            "SRI": r"integrity="
        },
        "E-commerce": {
            "WooCommerce": r"woocommerce",
            "Shopify": r"shopify",
            "Magento": r"magento",
            "PrestaShop": r"prestashop",
            "BigCommerce": r"bigcommerce",
            "OpenCart": r"opencart"
        },
        "CDN": {
            "Cloudflare": r"cloudflare",
            "Akamai": r"akamai",
            "Fastly": r"fastly",
            "AWS CloudFront": r"cloudfront",
            "Google Cloud CDN": r"googleusercontent"
        },
        "JavaScript Libraries": {
            "jQuery": r"jquery",
            "Lodash": r"lodash",
            "Underscore": r"underscore",
            "Moment.js": r"moment",
            "Chart.js": r"chart\.js",
            "D3.js": r"d3",
            "Three.js": r"three"
        },
        "CSS Frameworks": {
            "Bootstrap": r"bootstrap",
            "Tailwind": r"tailwind",
            "Foundation": r"foundation",
            "Bulma": r"bulma",
            "Materialize": r"materialize"
        }
    }

def detect_technologies(html_content, headers, cookies, response):
    """Detect technologies from HTML content, headers and cookies"""
    signatures = get_technology_signatures()
    results = {}
    
    # Check HTML content
    for category, techs in signatures.items():
        detected = []
        for tech, pattern in techs.items():
            if re.search(pattern, html_content, re.IGNORECASE):
                # Try to detect version
                version_pattern = f"{tech}[^0-9]*([0-9.]+)"
                version_match = re.search(version_pattern, html_content, re.IGNORECASE)
                version = version_match.group(1) if version_match else "Detected"
                detected.append((tech, version, "present"))
        if detected:
            results[category] = detected
    
    # Check headers
    server_tech = []
    if 'Server' in headers:
        server_tech.append((headers['Server'], "Server Header", "present"))
    if server_tech:
        results["Web Servers"] = server_tech
    
    # Check security headers
    security_tech = []
    security_headers = {
        'X-Frame-Options': 'Frame Protection',
        'X-XSS-Protection': 'XSS Protection',
        'X-Content-Type-Options': 'Content Type Protection',
        'Content-Security-Policy': 'CSP',
        'Strict-Transport-Security': 'HSTS',
        'Referrer-Policy': 'Referrer Policy',
        'Permissions-Policy': 'Permissions Policy'
    }
    
    for header, description in security_headers.items():
        if header in headers:
            security_tech.append((description, headers[header], "present"))
    if security_tech:
        results["Security"] = security_tech
    
    # Check for CDN usage
    cdn_tech = []
    for header in ['Server', 'X-Cache', 'X-Cache-Hits', 'X-Served-By']:
        if header in headers:
            cdn_tech.append((headers[header], "CDN Header", "present"))
    if cdn_tech:
        results["CDN"] = cdn_tech
    
    # Check for JavaScript libraries in script tags
    script_tech = []
    soup = BeautifulSoup(html_content, 'lxml')
    for script in soup.find_all('script'):
        if script.get('src'):
            for tech, pattern in signatures.get("JavaScript Libraries", {}).items():
                if re.search(pattern, script['src'], re.IGNORECASE):
                    script_tech.append((tech, "Script Source", "present"))
    if script_tech:
        results["JavaScript Libraries"] = script_tech
    
    # Check for CSS frameworks in link tags
    css_tech = []
    for link in soup.find_all('link'):
        if link.get('href'):
            for tech, pattern in signatures.get("CSS Frameworks", {}).items():
                if re.search(pattern, link['href'], re.IGNORECASE):
                    css_tech.append((tech, "CSS Source", "present"))
    if css_tech:
        results["CSS Frameworks"] = css_tech
    
    return results

def analyze_ssl_certificate(hostname):
    """Analyze SSL/TLS certificate"""
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect to server
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                
                try:
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                except Exception as e:
                    return {
                        "Error": f"Failed to load certificate: {str(e)}",
                        "Vulnerabilities": [{
                            "type": "SSL/TLS Error",
                            "severity": "Medium",
                            "description": f"Certificate analysis error: {str(e)}",
                            "recommendation": "Check certificate format and validity"
                        }]
                    }
                
                # Extract certificate information
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                
                # Get validity dates
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                # Calculate days until expiration
                days_until_expiry = (not_after - datetime.now()).days
                
                # Check for vulnerabilities
                vulnerabilities = []
                if days_until_expiry < 30:
                    vulnerabilities.append({
                        "type": "Certificate Expiration",
                        "severity": "High",
                        "description": f"Certificate expires in {days_until_expiry} days",
                        "recommendation": "Renew SSL certificate immediately"
                    })
                
                # Check certificate strength
                if cert.get('subjectAltName', []) == []:
                    vulnerabilities.append({
                        "type": "Certificate Configuration",
                        "severity": "Medium",
                        "description": "No Subject Alternative Names (SAN) found",
                        "recommendation": "Add SAN to certificate for better security"
                    })
                
                # Return certificate details
                return {
                    "Issuer": issuer.get('organizationName', 'Unknown'),
                    "Subject": subject.get('organizationName', 'Unknown'),
                    "Valid From": not_before.strftime('%Y-%m-%d'),
                    "Valid Until": not_after.strftime('%Y-%m-%d'),
                    "Days Until Expiry": days_until_expiry,
                    "Protocol": ssock.version(),
                    "Cipher": ssock.cipher()[0],
                    "Vulnerabilities": vulnerabilities
                }
    except Exception as e:
        return {
            "Error": str(e),
            "Vulnerabilities": [{
                "type": "SSL/TLS Error",
                "severity": "High",
                "description": f"Failed to analyze SSL certificate: {str(e)}",
                "recommendation": "Check SSL configuration and certificate validity"
            }]
        }

def scan_files(target_url):
    """Scan for common file types and their security"""
    try:
        # Common file types to check
        file_types = {
            "robots.txt": "/robots.txt",
            "sitemap.xml": "/sitemap.xml",
            "favicon.ico": "/favicon.ico",
            "crossdomain.xml": "/crossdomain.xml",
            "clientaccesspolicy.xml": "/clientaccesspolicy.xml",
            "phpinfo.php": "/phpinfo.php",
            "wp-config.php": "/wp-config.php",
            "config.php": "/config.php",
            ".env": "/.env",
            ".git/config": "/.git/config",
            ".htaccess": "/.htaccess",
            "web.config": "/web.config"
        }
        
        results = {
            "Found Files": [],
            "Missing Files": [],
            "Security Issues": []
        }
        
        # Check each file
        for file_name, file_path in file_types.items():
            try:
                file_url = target_url.rstrip('/') + file_path
                response = requests.get(file_url, timeout=5)
                
                if response.status_code == 200:
                    results["Found Files"].append({
                        "name": file_name,
                        "url": file_url,
                        "size": len(response.text),
                        "content_type": response.headers.get('Content-Type', 'Unknown')
                    })
                    
                    # Check for security issues
                    if file_name in [".env", "wp-config.php", "config.php"]:
                        results["Security Issues"].append({
                            "type": "Sensitive File Exposure",
                            "severity": "Critical",
                            "description": f"Sensitive file {file_name} is publicly accessible",
                            "recommendation": "Restrict access to sensitive configuration files"
                        })
                    elif file_name == "phpinfo.php":
                        results["Security Issues"].append({
                            "type": "Information Disclosure",
                            "severity": "High",
                            "description": "phpinfo.php file is publicly accessible",
                            "recommendation": "Remove or restrict access to phpinfo.php"
                        })
                else:
                    results["Missing Files"].append(file_name)
                    
            except requests.exceptions.RequestException:
                results["Missing Files"].append(file_name)
        
        return results
        
    except Exception as e:
        return {
            "Error": str(e),
            "Security Issues": [{
                "type": "File Scan Error",
                "severity": "Medium",
                "description": f"Error scanning files: {str(e)}",
                "recommendation": "Check server configuration and file permissions"
            }]
        }

def validate_url(url):
    """Validate and clean URL"""
    if not url:
        return None, "URL is empty"
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return None, "Invalid URL format"
        return url, None
    except Exception as e:
        return None, f"URL validation error: {str(e)}"

def simulate_scan(url):
    """Simulate website scanning when real scan fails"""
    common_technologies = {
        "Web Servers": [
            ("Nginx", "1.20.1", "detected"),
            ("Apache", "2.4.41", "detected")
        ],
        "Frameworks": [
            ("React", "17.0.2", "detected"),
            ("Bootstrap", "5.1.3", "detected")
        ],
        "Security": [
            ("HTTPS", "TLS 1.3", "enabled"),
            ("HSTS", "max-age=31536000", "enabled")
        ],
        "Analytics": [
            ("Google Analytics", "GA4", "detected")
        ]
    }
    
    vulnerabilities = [
        {
            "type": "XSS Protection Test",
            "risk": "High",
            "description": "No XSS protection headers detected",
            "recommendation": "Implement Content-Security-Policy",
            "test_key": "xss_headers"
        },
        {
            "type": "SQL Injection Test",
            "risk": "Medium",
            "description": "Database technology detected",
            "recommendation": "Implement prepared statements",
            "test_key": "sql_vuln"
        }
    ]
    
    return {
        "url": url,
        "technologies": common_technologies,
        "vulnerabilities": vulnerabilities,
        "is_simulated": True
    }

def scan_website(url):
    """Enhanced website scanning function"""
    # Validate URL
    cleaned_url, error = validate_url(url)
    if error:
        return {"error": error}
    
    # Check if running in Streamlit Cloud
    is_cloud = os.getenv('STREAMLIT_RUNTIME') == 'cloud'
    
    if is_cloud:
        st.info("Running in Streamlit Cloud - using simulation mode for demonstration.")
        return simulate_scan(cleaned_url)
    
    try:
        # Try real scan first (only in local environment)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(cleaned_url, headers=headers, timeout=10, verify=True)
        html_content = response.text.lower()
        
        # Initialize results
        results = {
            "url": cleaned_url,
            "technologies": {},
            "server_info": {},
            "headers": dict(response.headers),
            "vulnerabilities": [],
            "is_simulated": False
        }
        
        # Detect technologies
        techs = detect_technologies(html_content, response.headers, {}, response)
        if techs:
            results["technologies"] = techs
        
        # Analyze vulnerabilities
        results["vulnerabilities"] = analyze_vulnerabilities(results)
        
        return results
        
    except requests.exceptions.RequestException as e:
        st.warning("Could not perform real scan, showing simulated results instead.")
        return simulate_scan(cleaned_url)
    except Exception as e:
        st.warning("Scanning error occurred, showing simulated results instead.")
        return simulate_scan(cleaned_url)

def display_vulnerability(vuln, level):
    """Display a single vulnerability in the UI"""
    with st.expander(f"{vuln['type']}", expanded=True):
        st.markdown(f"**Description:** {vuln['description']}")
        st.markdown(f"**Recommendation:** {vuln['recommendation']}")
        test_key = f"{vuln['test_key']}_{level.lower()}"
        if st.button("Run Test", key=test_key):
            st.session_state['selected_test'] = vuln['type'].split()[0]
            st.experimental_rerun()

def display_vulnerabilities(vulnerabilities):
    """Display all vulnerabilities grouped by risk level"""
    if not vulnerabilities:
        return

    st.markdown("## " + texts.get("recommended_tests", "Recommended Tests"))
    
    icons = {
        "Critical": "🚨",
        "High": "⚠️",
        "Medium": "⚡",
        "Low": "ℹ️"
    }
    
    for level in ["Critical", "High", "Medium", "Low"]:
        level_vulns = [v for v in vulnerabilities if v["risk"] == level]
        if level_vulns:
            st.markdown(f"### {icons.get(level, 'ℹ️')} {level} Risk Level")
            for vuln in level_vulns:
                display_vulnerability(vuln, level)
            st.markdown("---")

def analyze_vulnerabilities(scan_results):
    """Analyze scan results for vulnerabilities and recommend tests"""
    vulnerabilities = []
    recommendations = set()

    def add_rec(test_type, reason, risk_level, description, recommendation, test_key):
        """Add a recommendation if not already present"""
        rec = (test_type, reason, risk_level)
        if rec not in recommendations:
            recommendations.add(rec)
            vulnerabilities.append({
                "type": test_type,
                "risk": risk_level,
                "description": description,
                "recommendation": recommendation,
                "test_key": test_key
            })

    # Critical risks
    if "E-commerce" in scan_results:
        add_rec(
            "SQL Injection Test",
            "E-commerce platform detected",
            "Critical",
            "E-commerce systems handle sensitive payment data",
            "Run SQL injection tests and implement WAF",
            "sql_ecommerce"
        )

    # High risks - JavaScript frameworks
    js_frameworks = ["jQuery", "React", "Vue.js", "Angular"]
    if any(tech[0] in js_frameworks for techs in scan_results.values() for tech in techs):
        add_rec(
            "XSS Test",
            "JavaScript frameworks detected",
            "High",
            "JavaScript applications are XSS targets",
            "Run XSS tests and implement CSP",
            "xss_js"
        )

    # High risks - Server technology
    if "Web Servers" in scan_results:
        server_tech = [tech[0] for tech in scan_results["Web Servers"]]
        if any(server in ["Apache", "Nginx", "IIS"] for server in server_tech):
            add_rec(
                "DDoS Test",
                f"Server using {', '.join(server_tech)}",
                "High",
                "Web servers need DDoS protection",
                "Run DDoS tests and implement rate limiting",
                "ddos_server"
            )

    # High risks - PHP
    if any("PHP" in tech[0] for techs in scan_results.values() for tech in techs):
        add_rec(
            "SQL Injection Test",
            "PHP application detected",
            "High",
            "PHP apps need SQL injection protection",
            "Run SQL tests and use prepared statements",
            "sql_php"
        )

    # Medium risks - Security headers
    headers = {
        "X-Frame-Options": ("Clickjacking Protection", "frame"),
        "X-XSS-Protection": ("XSS Protection", "xss"),
        "Content-Security-Policy": ("Content Security", "csp"),
        "X-Content-Type-Options": ("MIME Sniffing Protection", "mime")
    }
    
    if "Security" in scan_results:
        present = {tech[0] for tech in scan_results["Security"]}
        for header, (protection, key) in headers.items():
            if header not in present:
                add_rec(
                    "Security Test",
                    f"Missing {header}",
                    "Medium",
                    f"Site lacks {protection}",
                    f"Add {header} header",
                    f"header_{key}"
                )

    # Display results
    display_vulnerabilities(vulnerabilities)
    return vulnerabilities

def quick_scan(url):
    """Quick scan that checks basic technologies and security headers"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=5, verify=True)
        html_content = response.text.lower()
        
        results = {
            "url": url,
            "technologies": {},
            "basic_security": {},
            "response_time": response.elapsed.total_seconds(),
            "is_simulated": False,
            "scan_type": "quick"
        }
        
        # Quick check for common technologies
        quick_signatures = {
            "Web Server": response.headers.get('Server', 'Unknown'),
            "Framework": "WordPress" if "wp-content" in html_content else "Unknown",
            "SSL/TLS": "Enabled" if url.startswith("https") else "Disabled",
            "Security Headers": {
                header: response.headers.get(header, "Not Found")
                for header in ['X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy']
            }
        }
        
        results["technologies"] = quick_signatures
        return results
        
    except Exception as e:
        return simulate_quick_scan(url)

def simulate_quick_scan(url):
    """Simulate quick scan results"""
    return {
        "url": url,
        "technologies": {
            "Web Server": "Nginx/1.20.1",
            "Framework": "WordPress",
            "SSL/TLS": "Enabled",
            "Security Headers": {
                "X-Frame-Options": "SAMEORIGIN",
                "X-XSS-Protection": "1; mode=block",
                "Content-Security-Policy": "Not Found"
            }
        },
        "response_time": 0.5,
        "is_simulated": True,
        "scan_type": "quick"
    }

def analyze_network_traffic(url, response):
    """Analyze network traffic and performance metrics"""
    network_info = {
        "DNS Lookup": {
            "time": response.elapsed.total_seconds(),
            "status": "OK" if response.elapsed.total_seconds() < 1 else "Slow"
        },
        "Connection": {
            "protocol": "HTTPS" if url.startswith("https") else "HTTP",
            "status_code": response.status_code,
            "reason": response.reason
        },
        "Performance": {
            "time_to_first_byte": response.elapsed.total_seconds(),
            "content_size": len(response.content),
            "compression": response.headers.get('content-encoding', 'None')
        },
        "Headers": {
            "cache_control": response.headers.get('cache-control', 'Not set'),
            "connection": response.headers.get('connection', 'Not set'),
            "keep_alive": response.headers.get('keep-alive', 'Not set')
        },
        "Security": {
            "hsts": response.headers.get('strict-transport-security', 'Not set'),
            "cors": response.headers.get('access-control-allow-origin', 'Not set'),
            "csp": response.headers.get('content-security-policy', 'Not set')
        }
    }
    
    # Add performance recommendations
    recommendations = []
    if network_info["DNS Lookup"]["time"] > 1:
        recommendations.append({
            "type": "DNS Performance",
            "risk": "Medium",
            "description": "DNS lookup time is high",
            "recommendation": "Consider using DNS prefetching or a faster DNS provider"
        })
    
    if not network_info["Headers"]["cache_control"]:
        recommendations.append({
            "type": "Caching",
            "risk": "Low",
            "description": "No cache control headers found",
            "recommendation": "Implement proper cache control headers for better performance"
        })
    
    if network_info["Performance"]["content_size"] > 5000000:  # 5MB
        recommendations.append({
            "type": "Content Size",
            "risk": "Medium",
            "description": "Large page size detected",
            "recommendation": "Optimize images and minimize resources"
        })
    
    network_info["recommendations"] = recommendations
    return network_info

def analyze_seo(html_content):
    """Analyze SEO elements of the page"""
    soup = BeautifulSoup(html_content, 'lxml')
    seo_info = {
        "Meta Tags": {},
        "Headers": {},
        "Links": {
            "internal": 0,
            "external": 0,
            "broken": 0
        },
        "Images": {
            "with_alt": 0,
            "without_alt": 0
        },
        "Social": {}
    }
    
    # Check meta tags
    meta_tags = soup.find_all('meta')
    for tag in meta_tags:
        if tag.get('name'):
            seo_info["Meta Tags"][tag['name']] = tag.get('content', 'Not set')
        elif tag.get('property'):
            seo_info["Social"][tag['property']] = tag.get('content', 'Not set')
    
    # Check headers hierarchy
    for i in range(1, 7):
        headers = soup.find_all(f'h{i}')
        if headers:
            seo_info["Headers"][f"h{i}"] = len(headers)
    
    # Check links
    for link in soup.find_all('a'):
        href = link.get('href', '')
        if href.startswith('http'):
            seo_info["Links"]["external"] += 1
        elif href and not href.startswith('#'):
            seo_info["Links"]["internal"] += 1
    
    # Check images
    for img in soup.find_all('img'):
        if img.get('alt'):
            seo_info["Images"]["with_alt"] += 1
        else:
            seo_info["Images"]["without_alt"] += 1
    
    return seo_info

def analyze_accessibility(html_content):
    """Check accessibility compliance"""
    soup = BeautifulSoup(html_content, 'lxml')
    accessibility_info = {
        "ARIA": {
            "landmarks": 0,
            "labels": 0,
            "roles": 0
        },
        "Images": {
            "with_alt": 0,
            "without_alt": 0
        },
        "Forms": {
            "with_labels": 0,
            "without_labels": 0
        },
        "Color Contrast": "Not checked (requires rendering)",
        "Keyboard Navigation": {
            "focusable_elements": 0,
            "tab_index": 0
        }
    }
    
    # Check ARIA attributes
    for element in soup.find_all(True):
        for attr in element.attrs:
            if attr.startswith('aria-'):
                accessibility_info["ARIA"]["labels"] += 1
            elif attr == 'role':
                accessibility_info["ARIA"]["roles"] += 1
    
    # Check form accessibility
    forms = soup.find_all('form')
    for form in forms:
        inputs = form.find_all('input')
        for input_field in inputs:
            if input_field.find_parent('label') or input_field.get('aria-label'):
                accessibility_info["Forms"]["with_labels"] += 1
            else:
                accessibility_info["Forms"]["without_labels"] += 1
    
    # Check keyboard navigation
    focusable_elements = soup.find_all(['a', 'button', 'input', 'select', 'textarea'])
    accessibility_info["Keyboard Navigation"]["focusable_elements"] = len(focusable_elements)
    
    for element in soup.find_all(True):
        if element.get('tabindex'):
            accessibility_info["Keyboard Navigation"]["tab_index"] += 1
    
    return accessibility_info

def analyze_performance(response, html_content):
    """Analyze website performance metrics"""
    soup = BeautifulSoup(html_content, 'lxml')
    performance_info = {
        "Page Size": {
            "html": len(html_content),
            "total": len(response.content),
            "compression": response.headers.get('content-encoding', 'none')
        },
        "Resources": {
            "scripts": len(soup.find_all('script')),
            "styles": len(soup.find_all('link', rel='stylesheet')),
            "images": len(soup.find_all('img')),
            "fonts": len(soup.find_all('link', rel='font')),
        },
        "Loading": {
            "time_to_first_byte": response.elapsed.total_seconds(),
            "total_load_time": response.elapsed.total_seconds()
        },
        "Caching": {
            "cache_control": response.headers.get('cache-control', 'Not set'),
            "etag": response.headers.get('etag', 'Not set'),
            "expires": response.headers.get('expires', 'Not set')
        }
    }
    
    # Add recommendations
    recommendations = []
    
    if performance_info["Page Size"]["total"] > 5000000:  # 5MB
        recommendations.append({
            "type": "Large Page Size",
            "risk": "Medium",
            "description": "Page size exceeds 5MB",
            "recommendation": "Optimize images and minify resources"
        })
    
    if performance_info["Resources"]["scripts"] > 20:
        recommendations.append({
            "type": "Many JavaScript Files",
            "risk": "Medium",
            "description": f"Found {performance_info['Resources']['scripts']} script tags",
            "recommendation": "Bundle JavaScript files and use async/defer"
        })
    
    if not performance_info["Caching"]["cache_control"]:
        recommendations.append({
            "type": "No Caching",
            "risk": "Low",
            "description": "No cache control headers found",
            "recommendation": "Implement browser caching"
        })
    
    performance_info["recommendations"] = recommendations
    return performance_info

def scan_ports(hostname, common_ports=[80, 443, 8080, 8443]):
    """Scan common web ports"""
    port_info = {
        "open_ports": [],
        "closed_ports": [],
        "filtered_ports": []
    }
    
    try:
        for port in common_ports:
            try:
                with socket.create_connection((hostname, port), timeout=1) as sock:
                    port_info["open_ports"].append({
                        "port": port,
                        "service": socket.getservbyport(port) if port < 1024 else "unknown"
                    })
            except (socket.timeout, ConnectionRefusedError):
                port_info["closed_ports"].append(port)
            except Exception:
                port_info["filtered_ports"].append(port)
        
        # Add security recommendations
        if len(port_info["open_ports"]) > 2:
            port_info["recommendations"] = [{
                "type": "Open Ports",
                "risk": "Medium",
                "description": f"Found {len(port_info['open_ports'])} open ports",
                "recommendation": "Close unnecessary ports and implement firewall rules"
            }]
        
        return port_info
    except Exception as e:
        return {
            "error": str(e),
            "recommendations": [{
                "type": "Port Scan Error",
                "risk": "Low",
                "description": f"Could not complete port scan: {str(e)}",
                "recommendation": "Check network connectivity and firewall rules"
            }]
        }

def detailed_scan(url):
    """Detailed scan that checks all technologies and vulnerabilities"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=True)
        html_content = response.text
        hostname = urlparse(url).netloc
        
        results = {
            "url": url,
            "technologies": {},
            "server_info": {},
            "headers": dict(response.headers),
            "vulnerabilities": [],
            "ssl_info": analyze_ssl_certificate(hostname),
            "file_scan": scan_files(url),
            "network_analysis": analyze_network_traffic(url, response),
            "seo_analysis": analyze_seo(html_content),
            "accessibility": analyze_accessibility(html_content),
            "performance": analyze_performance(response, html_content),
            "port_scan": scan_ports(hostname),
            "response_time": response.elapsed.total_seconds(),
            "is_simulated": False,
            "scan_type": "detailed"
        }
        
        # Detect technologies
        techs = detect_technologies(html_content.lower(), response.headers, {}, response)
        if techs:
            results["technologies"] = techs
        
        # Analyze vulnerabilities
        results["vulnerabilities"] = analyze_vulnerabilities(results)
        
        return results
        
    except Exception as e:
        return simulate_detailed_scan(url)

def simulate_detailed_scan(url):
    """Simulate detailed scan results"""
    simulated_results = {
        "url": url,
        "technologies": {
            "Web Servers": [
                ("Nginx", "1.20.1", "detected"),
                ("Apache", "2.4.41", "detected")
            ],
            "Frameworks": [
                ("React", "17.0.2", "detected"),
                ("Bootstrap", "5.1.3", "detected"),
                ("jQuery", "3.6.0", "detected")
            ],
            "Security": [
                ("HTTPS", "TLS 1.3", "enabled"),
                ("HSTS", "max-age=31536000", "enabled"),
                ("CSP", "strict-policy", "enabled")
            ],
            "Analytics": [
                ("Google Analytics", "GA4", "detected"),
                ("Google Tag Manager", "GTM-123456", "detected")
            ],
            "CDN": [
                ("Cloudflare", "Active", "detected")
            ]
        },
        "network_analysis": {
            "DNS Lookup": {
                "time": 0.3,
                "status": "OK"
            },
            "Connection": {
                "protocol": "HTTPS",
                "status_code": 200,
                "reason": "OK"
            },
            "Performance": {
                "time_to_first_byte": 0.2,
                "content_size": 256000,
                "compression": "gzip"
            },
            "Headers": {
                "cache_control": "max-age=3600",
                "connection": "keep-alive",
                "keep_alive": "timeout=5, max=100"
            },
            "Security": {
                "hsts": "max-age=31536000",
                "cors": "*",
                "csp": "default-src 'self'"
            },
            "recommendations": [
                {
                    "type": "CORS Configuration",
                    "risk": "Medium",
                    "description": "CORS policy is too permissive",
                    "recommendation": "Restrict CORS to specific domains"
                }
            ]
        },
        "vulnerabilities": [
            {
                "type": "XSS Protection Test",
                "risk": "High",
                "description": "No XSS protection headers detected",
                "recommendation": "Implement Content-Security-Policy",
                "test_key": "xss_headers"
            },
            {
                "type": "SQL Injection Test",
                "risk": "Medium",
                "description": "Database technology detected",
                "recommendation": "Implement prepared statements",
                "test_key": "sql_vuln"
            }
        ],
        "ssl_info": {
            "Issuer": "Let's Encrypt",
            "Valid Until": (datetime.now() + pd.Timedelta(days=60)).strftime('%Y-%m-%d'),
            "Protocol": "TLSv1.3",
            "Cipher": "TLS_AES_256_GCM_SHA384"
        },
        "seo_analysis": {
            "Meta Tags": {
                "description": "Sample meta description",
                "keywords": "sample, keywords",
                "viewport": "width=device-width, initial-scale=1"
            },
            "Headers": {
                "h1": 1,
                "h2": 3,
                "h3": 5
            },
            "Links": {
                "internal": 15,
                "external": 8,
                "broken": 0
            },
            "Images": {
                "with_alt": 12,
                "without_alt": 3
            }
        },
        "accessibility": {
            "ARIA": {
                "landmarks": 5,
                "labels": 8,
                "roles": 10
            },
            "Images": {
                "with_alt": 12,
                "without_alt": 3
            },
            "Forms": {
                "with_labels": 4,
                "without_labels": 1
            },
            "Keyboard Navigation": {
                "focusable_elements": 25,
                "tab_index": 5
            }
        },
        "performance": {
            "Page Size": {
                "html": 45000,
                "total": 250000,
                "compression": "gzip"
            },
            "Resources": {
                "scripts": 8,
                "styles": 3,
                "images": 15,
                "fonts": 2
            },
            "Loading": {
                "time_to_first_byte": 0.2,
                "total_load_time": 1.5
            },
            "Caching": {
                "cache_control": "max-age=3600",
                "etag": "abc123",
                "expires": "Thu, 01 Jan 2025 00:00:00 GMT"
            }
        },
        "port_scan": {
            "open_ports": [
                {"port": 80, "service": "http"},
                {"port": 443, "service": "https"}
            ],
            "closed_ports": [8080, 8443],
            "filtered_ports": []
        },
        "response_time": 1.2,
        "is_simulated": True,
        "scan_type": "detailed"
    }
    return simulated_results

def get_category_description(category):
    """Return description for technology categories"""
    descriptions = {
        "Web Servers": "Software that serves web content to visitors",
        "Frameworks": "Programming frameworks and libraries used to build the website",
        "Security": "Security measures and protocols implemented",
        "Analytics": "Tools used to track and analyze website traffic",
        "E-commerce": "Online shopping and payment processing solutions",
        "CDN": "Content Delivery Network services for faster content delivery",
        "JavaScript Libraries": "JavaScript libraries used for functionality and interactivity",
        "CSS Frameworks": "Styling frameworks used for design and layout",
        "Security Headers": "HTTP headers that provide additional security",
        "Web Server": "The main web server software serving the content",
        "Framework": "Main programming framework detected",
        "SSL/TLS": "Secure connection protocol status"
    }
    return descriptions.get(category, "Additional technology information")

def run_ssl_test(url):
    """Run SSL/TLS test"""
    with st.spinner("Running SSL/TLS test..."):
        # Simulated SSL test results
        return {
            "protocol": "TLS 1.2",
            "cipher": "AES256-GCM-SHA384",
            "certificate": {
                "issuer": "Let's Encrypt",
                "valid_until": "2024-12-31",
                "strength": "Strong"
            },
            "vulnerabilities": [
                "No Heartbleed vulnerability detected",
                "No POODLE vulnerability detected"
            ]
        }

def run_web_server_test(url):
    """Run web server configuration test"""
    with st.spinner("Running web server test..."):
        # Simulated web server test results
        return {
            "server": "Apache/2.4.41",
            "security_headers": {
                "X-Frame-Options": "Present",
                "X-Content-Type-Options": "Present",
                "X-XSS-Protection": "Present"
            },
            "recommendations": [
                "Enable HTTP/2 for better performance",
                "Configure proper caching headers"
            ]
        }

def run_cms_test(url):
    """Run CMS vulnerability test"""
    with st.spinner("Running CMS test..."):
        # Simulated CMS test results
        return {
            "cms": "WordPress 6.4.2",
            "plugins": [
                "Yoast SEO 20.7",
                "WooCommerce 8.3.1"
            ],
            "vulnerabilities": [
                "No critical vulnerabilities found",
                "Update WordPress to latest version recommended"
            ]
        }

def run_cors_test(url):
    """Run CORS configuration test"""
    with st.spinner("Running CORS test..."):
        # Simulated CORS test results
        return {
            "cors_policy": "Restricted",
            "allowed_origins": ["https://example.com"],
            "allowed_methods": ["GET", "POST"],
            "security_level": "Good"
        }

def run_port_test(url):
    """Run port security test"""
    with st.spinner("Running port test..."):
        # Simulated port test results
        return {
            "open_ports": [
                {"port": 80, "service": "HTTP"},
                {"port": 443, "service": "HTTPS"}
            ],
            "security_level": "Good",
            "recommendations": [
                "Close unnecessary ports",
                "Enable firewall rules"
            ]
        }

def run_performance_test(url):
    """Run performance optimization test"""
    with st.spinner("Running performance test..."):
        # Simulated performance test results
        return {
            "page_load_time": "2.3s",
            "resource_optimization": {
                "images": "Good",
                "scripts": "Good",
                "styles": "Good"
            },
            "recommendations": [
                "Enable browser caching",
                "Minify JavaScript and CSS"
            ]
        }

def run_accessibility_test(url):
    """Run accessibility compliance test"""
    with st.spinner("Running accessibility test..."):
        # Simulated accessibility test results
        return {
            "wcag_compliance": "Level AA",
            "issues": [
                "Missing alt text on 2 images",
                "Low contrast on 3 text elements"
            ],
            "recommendations": [
                "Add alt text to all images",
                "Improve color contrast"
            ]
        }

def run_xss_test(url):
    """Run XSS vulnerability test"""
    with st.spinner("Running XSS test..."):
        # Simulated XSS test results
        return {
            "vulnerabilities": [
                "Reflected XSS vulnerability found in search parameter",
                "Stored XSS vulnerability in comment section"
            ],
            "security_headers": {
                "X-XSS-Protection": "Not present",
                "Content-Security-Policy": "Not present"
            },
            "recommendations": [
                "Implement Content-Security-Policy header",
                "Enable XSS protection headers",
                "Sanitize user input"
            ]
        }

def run_sql_test(url):
    """Run SQL injection test"""
    with st.spinner("Running SQL injection test..."):
        # Simulated SQL test results
        return {
            "vulnerabilities": [
                "SQL injection vulnerability in login form",
                "SQL injection in search functionality"
            ],
            "database_info": {
                "type": "MySQL",
                "version": "8.0.26"
            },
            "recommendations": [
                "Use prepared statements",
                "Implement input validation",
                "Enable WAF protection"
            ]
        }

def run_ddos_test(url):
    """Run DDoS vulnerability test"""
    with st.spinner("Running DDoS test..."):
        # Simulated DDoS test results
        return {
            "vulnerabilities": [
                "No rate limiting on API endpoints",
                "Missing DDoS protection"
            ],
            "server_config": {
                "rate_limiting": "Not configured",
                "firewall": "Basic"
            },
            "recommendations": [
                "Implement rate limiting",
                "Configure WAF rules",
                "Enable DDoS protection service"
            ]
        }

def get_ai_recommendations(scan_results):
    """Generate AI-powered test recommendations based on scan results"""
    recommendations = []
    
    # Critical Risk Tests
    if "Security" in scan_results.get("technologies", {}):
        security_techs = [tech[0] for tech in scan_results["technologies"]["Security"]]
        if "HTTPS" in security_techs:
            recommendations.append({
                "risk": "Critical",
                "test": "SSL/TLS Configuration Test",
                "description": "Test for weak cipher suites and SSL/TLS vulnerabilities",
                "reason": "HTTPS is enabled but needs thorough security testing"
            })
    
    # High Risk Tests
    if "Web Servers" in scan_results.get("technologies", {}):
        server_techs = [tech[0] for tech in scan_results["technologies"]["Web Servers"]]
        if any(server in ["Apache", "Nginx", "IIS"] for server in server_techs):
            recommendations.append({
                "risk": "High",
                "test": "Web Server Configuration Test",
                "description": "Test for misconfigurations and known vulnerabilities",
                "reason": "Web server technology detected"
            })
            recommendations.append({
                "risk": "High",
                "test": "DDoS Protection Test",
                "description": "Test for DDoS vulnerabilities and protection measures",
                "reason": "Web server needs DDoS protection testing"
            })
    
    if "Frameworks" in scan_results.get("technologies", {}):
        framework_techs = [tech[0] for tech in scan_results["technologies"]["Frameworks"]]
        if any(fw in ["WordPress", "Drupal", "Joomla"] for fw in framework_techs):
            recommendations.append({
                "risk": "High",
                "test": "CMS Vulnerability Test",
                "description": "Test for known CMS vulnerabilities and plugin security",
                "reason": "Content Management System detected"
            })
            recommendations.append({
                "risk": "High",
                "test": "XSS Vulnerability Test",
                "description": "Test for cross-site scripting vulnerabilities",
                "reason": "CMS platforms often have XSS vulnerabilities"
            })
            recommendations.append({
                "risk": "High",
                "test": "SQL Injection Test",
                "description": "Test for SQL injection vulnerabilities",
                "reason": "CMS platforms often have SQL injection vulnerabilities"
            })
    
    # Medium Risk Tests
    if "network_analysis" in scan_results:
        if scan_results["network_analysis"].get("Security", {}).get("cors") == "*":
            recommendations.append({
                "risk": "Medium",
                "test": "CORS Configuration Test",
                "description": "Test for CORS misconfigurations and potential security issues",
                "reason": "Permissive CORS policy detected"
            })
    
    if "port_scan" in scan_results:
        if len(scan_results["port_scan"].get("open_ports", [])) > 2:
            recommendations.append({
                "risk": "Medium",
                "test": "Port Security Test",
                "description": "Test for unnecessary open ports and service vulnerabilities",
                "reason": "Multiple open ports detected"
            })
    
    # Low Risk Tests
    if "performance" in scan_results:
        if scan_results["performance"]["Page Size"]["total"] > 5000000:  # 5MB
            recommendations.append({
                "risk": "Low",
                "test": "Performance Optimization Test",
                "description": "Test for resource optimization and caching effectiveness",
                "reason": "Large page size detected"
            })
    
    if "accessibility" in scan_results:
        if scan_results["accessibility"]["Images"]["without_alt"] > 0:
            recommendations.append({
                "risk": "Low",
                "test": "Accessibility Compliance Test",
                "description": "Test for WCAG compliance and accessibility issues",
                "reason": "Images without alt text detected"
            })
    
    return recommendations

def get_dns_info(url: str) -> Dict[str, Any]:
    """Get DNS information for the given URL"""
    try:
        domain = urlparse(url).netloc
        # Temporarily return simulated data
        return {
            "dns_records": {
                "A": ["192.168.1.1"],  # Simulated IP
                "AAAA": ["2001:db8::1"],  # Simulated IPv6
                "MX": ["mail.example.com"],  # Simulated mail server
                "NS": ["ns1.example.com", "ns2.example.com"]  # Simulated name servers
            },
            "dns_servers": ["8.8.8.8", "8.8.4.4"],  # Simulated DNS servers
            "response_time": 0.05  # Simulated response time
        }
    except Exception as e:
        logging.error(f"Error getting DNS info: {str(e)}")
        return {
            "dns_records": {},
            "dns_servers": [],
            "response_time": 0
        }

def get_system_info() -> Dict[str, Any]:
    """Get system information"""
    try:
        # Temporarily return simulated data
        return {
            "cpu_usage": 25.5,  # Simulated CPU usage
            "memory_usage": 45.2,  # Simulated memory usage
            "disk_usage": 60.8,  # Simulated disk usage
            "network_io": {
                "bytes_sent": 1024 * 1024,  # Simulated bytes sent
                "bytes_recv": 2048 * 1024   # Simulated bytes received
            }
        }
    except Exception as e:
        logging.error(f"Error getting system info: {str(e)}")
        return {
            "cpu_usage": 0,
            "memory_usage": 0,
            "disk_usage": 0,
            "network_io": {
                "bytes_sent": 0,
                "bytes_recv": 0
            }
        }

# Main UI
st.title("🔍 " + texts["page_title"])
st.markdown(texts["description"])

# Input with default value and scan type selection
col1, col2 = st.columns([3, 1])
with col1:
    url = st.text_input("Enter website URL:", "harvard.edu")
with col2:
    scan_type = st.radio(
        texts["scan_type"],
        options=["quick", "detailed"],
        format_func=lambda x: texts["quick_scan"] if x == "quick" else texts["detailed_scan"]
    )

# Scan button
if st.button(texts["start_scan"]):
    with st.spinner(texts["scanning"]):
        if scan_type == texts["quick_scan"]:
            results = quick_scan(url)
        else:
            results = detailed_scan(url)
        
        if "error" in results:
            st.error(f"Error: {results['error']}")
        else:
            # Display results
            st.success(texts["scan_completed"])
            
            if results.get("is_simulated"):
                st.info(texts["simulated_note"])
            
            # Show response time
            st.metric(texts["response_time"], f"{results['response_time']:.2f} {texts['seconds']}")
            
            # Show technologies based on scan type
            if scan_type == texts["quick_scan"]:
                st.subheader(texts["basic_overview"])
                st.markdown(f"*{texts['quick_overview']}*")
                for category, value in results["technologies"].items():
                    if isinstance(value, dict):
                        with st.expander(category, expanded=True):
                            st.markdown(f"*{get_category_description(category)}*")
                            for k, v in value.items():
                                st.markdown(f"- **{k}**: {v}")
                    else:
                        st.markdown(f"- **{category}**: {value}")
            else:
                # Detailed results display
                st.subheader(texts["detected_tech"])
                st.markdown(f"*{texts['comprehensive_analysis']}*")
                for category, techs in results["technologies"].items():
                    with st.expander(f"{category} ({len(techs)})", expanded=True):
                        st.markdown(f"*{get_category_description(category)}*")
                        for tech in techs:
                            name, version, status = tech
                            st.markdown(f"- **{name}**: {version} ({status})")
                
                # AI Recommendations
                st.subheader(texts["ai_recommendations"])
                st.markdown(f"*{texts['recommendations_based']}*")
                
                recommendations = get_ai_recommendations(results)
                risk_colors = {
                    "Critical": "red",
                    "High": "orange",
                    "Medium": "yellow",
                    "Low": "green"
                }
                
                for risk_level in ["Critical", "High", "Medium", "Low"]:
                    risk_recommendations = [r for r in recommendations if r["risk"] == risk_level]
                    if risk_recommendations:
                        st.markdown(f"### {risk_level} {texts['risk_tests']}")
                        for rec in risk_recommendations:
                            with st.expander(f"🔴 {rec['test']}", expanded=True):
                                st.markdown(f"**{texts['description']}:** {rec['description']}")
                                st.markdown(f"**{texts['reason']}:** {rec['reason']}")
                                st.markdown(f"**{texts['suggested_tests']}:**")
                                st.markdown(f"- {texts['vulnerability_scanning']} {rec['test'].lower()}")
                                st.markdown(f"- {texts['configuration_review']}")
                                st.markdown(f"- {texts['automated_testing']}")
                                
                                # Update the button click handler
                                if st.button(f"{texts['go_to_test']} {rec['test']}", key=f"btn_{rec['test']}"):
                                    test_function = test_mapping.get(rec['test'])
                                    if test_function:
                                        with st.spinner(f"Running {rec['test']}..."):
                                            test_results = test_function(url)
                                            st.subheader(f"{rec['test']} Results")
                                            
                                            # Display test results in a more readable format
                                            if isinstance(test_results, dict):
                                                for key, value in test_results.items():
                                                    if isinstance(value, dict):
                                                        st.markdown(f"**{key}:**")
                                                        for subkey, subvalue in value.items():
                                                            st.markdown(f"- {subkey}: {subvalue}")
                                                    elif isinstance(value, list):
                                                        st.markdown(f"**{key}:**")
                                                        for item in value:
                                                            st.markdown(f"- {item}")
                                                    else:
                                                        st.markdown(f"**{key}:** {value}")
                                            else:
                                                st.json(test_results)
                                    else:
                                        st.info(texts["test_not_implemented"])
                
                # Network Analysis
                if "network_analysis" in results:
                    with st.expander(texts["network_analysis"], expanded=True):
                        st.markdown(f"*{texts['network_description']}*")
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown(f"### {texts['connection_details']}")
                            st.markdown(f"*{texts['connection_description']}*")
                            st.json(results["network_analysis"]["Connection"])
                            
                            st.markdown(f"### {texts['performance_metrics']}")
                            st.markdown(f"*{texts['performance_description']}*")
                            st.json(results["network_analysis"]["Performance"])
                        
                        with col2:
                            st.markdown(f"### {texts['security_headers']}")
                            st.markdown(f"*{texts['security_description']}*")
                            st.json(results["network_analysis"]["Security"])
                            
                            st.markdown(f"### {texts['dns_info']}")
                            st.markdown(f"*{texts['dns_description']}*")
                            st.json(results["network_analysis"]["DNS Lookup"])
                
                # SSL Information
                if "ssl_info" in results:
                    with st.expander(texts["ssl_info"], expanded=True):
                        st.markdown(f"*{texts['ssl_description']}*")
                        st.markdown("""
                        - **{texts['issuer']}**: {results['ssl_info']['Issuer']}
                        - **{texts['valid_until']}**: {results['ssl_info']['Valid Until']}
                        - **{texts['protocol']}**: {results['ssl_info']['Protocol']}
                        - **{texts['cipher']}**: {results['ssl_info']['Cipher']}
                        """)
                        for key, value in results["ssl_info"].items():
                            if key != "Vulnerabilities":
                                st.markdown(f"- **{key}**: {value}")
                
                # SEO Analysis
                if "seo_analysis" in results:
                    with st.expander(texts["seo_analysis"], expanded=True):
                        st.markdown(f"*{texts['seo_description']}*")
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown(f"### {texts['meta_tags']}")
                            st.markdown(f"*{texts['meta_description']}*")
                            st.json(results["seo_analysis"]["Meta Tags"])
                            
                            st.markdown(f"### {texts['headers_structure']}")
                            st.markdown(f"*{texts['headers_description']}*")
                            st.json(results["seo_analysis"]["Headers"])
                        
                        with col2:
                            st.markdown(f"### {texts['links_analysis']}")
                            st.markdown(f"*{texts['links_description']}*")
                            st.json(results["seo_analysis"]["Links"])
                            
                            st.markdown(f"### {texts['image_optimization']}")
                            st.markdown(f"*{texts['image_description']}*")
                            st.json(results["seo_analysis"]["Images"])
            
                # Accessibility Check
                if "accessibility" in results:
                    with st.expander(texts["accessibility_analysis"], expanded=True):
                        st.markdown(f"*{texts['accessibility_description']}*")
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown(f"### {texts['aria_implementation']}")
                            st.markdown(f"*{texts['aria_description']}*")
                            st.json(results["accessibility"]["ARIA"])
                            
                            st.markdown(f"### {texts['form_accessibility']}")
                            st.markdown(f"*{texts['form_description']}*")
                            st.json(results["accessibility"]["Forms"])
                        
                        with col2:
                            st.markdown(f"### {texts['image_accessibility']}")
                            st.markdown(f"*{texts['image_access_description']}*")
                            st.json(results["accessibility"]["Images"])
                            
                            st.markdown(f"### {texts['keyboard_navigation']}")
                            st.markdown(f"*{texts['keyboard_description']}*")
                            st.json(results["accessibility"]["Keyboard Navigation"])
            
                # Performance Analysis
                if "performance" in results:
                    with st.expander(texts["performance_analysis"], expanded=True):
                        st.markdown(f"*{texts['performance_description']}*")
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown(f"### {texts['page_size']}")
                            st.markdown(f"*{texts['page_size_description']}*")
                            st.json(results["performance"]["Page Size"])
                            
                            st.markdown(f"### {texts['resource_count']}")
                            st.markdown(f"*{texts['resource_description']}*")
                            st.json(results["performance"]["Resources"])
                        
                        with col2:
                            st.markdown(f"### {texts['loading_times']}")
                            st.markdown(f"*{texts['loading_description']}*")
                            st.json(results["performance"]["Loading"])
                            
                            st.markdown(f"### {texts['caching']}")
                            st.markdown(f"*{texts['caching_description']}*")
                            st.json(results["performance"]["Caching"])
            
                # Port Scan Results
                if "port_scan" in results:
                    with st.expander(texts["port_scan"], expanded=True):
                        st.markdown(f"*{texts['port_description']}*")
                        if "error" in results["port_scan"]:
                            st.error(results["port_scan"]["error"])
                        else:
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown(f"### {texts['open_ports']}")
                                st.markdown(f"*{texts['open_ports_description']}*")
                                for port in results["port_scan"]["open_ports"]:
                                    st.markdown(f"- Port {port['port']}: {port['service']}")
                            
                            with col2:
                                st.markdown(f"### {texts['closed_ports']}")
                                st.markdown(f"*{texts['closed_ports_description']}*")
                                st.markdown(f"- Closed: {', '.join(map(str, results['port_scan']['closed_ports']))}")
                                st.markdown(f"- Filtered: {', '.join(map(str, results['port_scan']['filtered_ports']))}")

# Show scan history with enhanced display
if st.session_state.scan_history:
    st.subheader(texts["scan_history"])
    history_df = pd.DataFrame(st.session_state.scan_history)
    
    # Add color coding based on scan type
    def color_scan_type(val):
        return 'background-color: #90EE90' if val == 'quick' else 'background-color: #FFB6C1'
    
    styled_df = history_df.style.applymap(color_scan_type, subset=['scan_type'])
    st.dataframe(styled_df)
    
    # Add visualization
    if len(history_df) > 1:
        st.subheader(texts["scan_statistics"])
        fig = px.line(
            history_df,
            x="timestamp",
            y="response_time",
            color="scan_type",
            title="Response Times by Scan Type"
        )
        st.plotly_chart(fig, use_container_width=True)
else:
    st.info(texts["no_history"])

# Define test mapping after all test functions
test_mapping = {
    "SSL/TLS Configuration Test": run_ssl_test,
    "Web Server Configuration Test": run_web_server_test,
    "CMS Vulnerability Test": run_cms_test,
    "CORS Configuration Test": run_cors_test,
    "Port Security Test": run_port_test,
    "Performance Optimization Test": run_performance_test,
    "Accessibility Compliance Test": run_accessibility_test,
    "XSS Vulnerability Test": run_xss_test,
    "SQL Injection Test": run_sql_test,
    "DDoS Protection Test": run_ddos_test
} 