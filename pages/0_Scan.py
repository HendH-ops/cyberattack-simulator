import streamlit as st
import time
import random
import pandas as pd
import plotly.express as px
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin
import ssl
import socket
import OpenSSL
from utils import init_language, COMMON_TRANSLATIONS

# Page config
st.set_page_config(
    page_title="Technology Scanner",
    page_icon="🔍",
    layout="wide"
)

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

# Initialize session state
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

# Get current language and translations
lang = init_language()
texts = {**COMMON_TRANSLATIONS[lang], **PAGE_TRANSLATIONS[lang]}

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
    
    try:
        # Try real scan first
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
        if any(tech in ["Apache", "Nginx", "IIS"] for tech in server_tech):
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

# Main UI
st.title("🔍 " + texts["page_title"])
st.markdown(texts["description"])

# Input with default value
url = st.text_input("Enter website URL:", "harvard.edu")

# Scan button
if st.button("Start Scan"):
    with st.spinner("Scanning..."):
        results = scan_website(url)
        
        if "error" in results:
            st.error(f"Error: {results['error']}")
        else:
            # Display results
            st.success("Scan completed!")
            
            if results.get("is_simulated"):
                st.info("Note: These are simulated results for demonstration purposes.")
            
            # Show technologies
            if "technologies" in results:
                st.subheader("Detected Technologies")
                
                for category, techs in results["technologies"].items():
                    with st.expander(f"{category} ({len(techs)})", expanded=True):
                        for tech in techs:
                            name, version, status = tech
                            st.markdown(f"- **{name}**: {version} ({status})")
            
            # Show vulnerabilities
            if "vulnerabilities" in results:
                display_vulnerabilities(results["vulnerabilities"])
            
            # Add to scan history
            scan_entry = {
                "timestamp": datetime.now(),
                "url": results["url"],
                "technologies": len([tech for techs in results.get("technologies", {}).values() for tech in techs]),
                "vulnerabilities": len(results.get("vulnerabilities", [])),
                "is_simulated": results.get("is_simulated", False)
            }
            st.session_state.scan_history.append(scan_entry)

# Show scan history
if st.session_state.scan_history:
    st.subheader("Scan History")
    history_df = pd.DataFrame(st.session_state.scan_history)
    st.dataframe(history_df)
else:
    st.info(texts['no_history']) 