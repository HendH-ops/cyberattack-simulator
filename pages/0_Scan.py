import streamlit as st
import time
import random
import pandas as pd
import plotly.express as px
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
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
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                
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

def basic_scan(target_url):
    """Perform basic website scan"""
    try:
        # Validate URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # Make request
        start_time = time.time()
        response = requests.get(target_url, timeout=10)
        response_time = time.time() - start_time
        
        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}")
        
        # Parse HTML
        soup = BeautifulSoup(response.text, 'lxml')
        html_content = response.text.lower()
        
        # Basic technology detection
        results = detect_technologies(html_content, response.headers, response.cookies, response)
        
        # Basic scanning details
        results["Scanning Details"] = {
            "Response Time": f"{response_time:.2f} seconds",
            "Status Code": response.status_code,
            "Content Type": response.headers.get('Content-Type', 'Unknown'),
            "Server": response.headers.get('Server', 'Unknown'),
            "SSL/TLS": "Yes" if target_url.startswith('https://') else "No"
        }
        
        return results
        
    except requests.exceptions.RequestException as e:
        raise Exception(f"{texts['connection_error']}: {str(e)}")
    except Exception as e:
        raise Exception(f"{texts['error_scanning']}: {str(e)}")

def advanced_scan(target_url):
    """Perform advanced website scan"""
    try:
        # Validate URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # Extract hostname for SSL analysis
        hostname = urlparse(target_url).netloc
        
        # Make request
        start_time = time.time()
        response = requests.get(target_url, timeout=10)
        response_time = time.time() - start_time
        
        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}")
        
        # Parse HTML
        soup = BeautifulSoup(response.text, 'lxml')
        html_content = response.text.lower()
        
        # Advanced technology detection
        results = detect_technologies(html_content, response.headers, response.cookies, response)
        
        # Analyze SSL certificate
        ssl_info = analyze_ssl_certificate(hostname)
        
        # Scan for files
        file_scan_results = scan_files(target_url)
        
        # Advanced scanning details
        results["Scanning Details"] = {
            "Response Time": f"{response_time:.2f} seconds",
            "Status Code": response.status_code,
            "Content Type": response.headers.get('Content-Type', 'Unknown'),
            "Server": response.headers.get('Server', 'Unknown'),
            "Content Length": f"{len(response.text):,} bytes",
            "SSL/TLS": "Yes" if target_url.startswith('https://') else "No",
            "Redirects": len(response.history) if response.history else 0
        }
        
        # Add SSL details
        if "Error" not in ssl_info:
            results["SSL Details"] = {
                "Issuer": ssl_info["Issuer"],
                "Valid From": ssl_info["Valid From"],
                "Valid Until": ssl_info["Valid Until"],
                "Days Until Expiry": ssl_info["Days Until Expiry"],
                "Protocol": ssl_info["Protocol"],
                "Cipher": ssl_info["Cipher"]
            }
        
        # Add SSL vulnerabilities to main vulnerabilities
        if "Vulnerabilities" in ssl_info:
            if "Vulnerabilities" not in results:
                results["Vulnerabilities"] = []
            results["Vulnerabilities"].extend(ssl_info["Vulnerabilities"])
        
        # Add file scan results to main results
        if "Found Files" in file_scan_results:
            results["Files"] = file_scan_results["Found Files"]
        if "Security Issues" in file_scan_results:
            if "Vulnerabilities" not in results:
                results["Vulnerabilities"] = []
            results["Vulnerabilities"].extend(file_scan_results["Security Issues"])
        
        return results
        
    except requests.exceptions.RequestException as e:
        raise Exception(f"{texts['connection_error']}: {str(e)}")
    except Exception as e:
        raise Exception(f"{texts['error_scanning']}: {str(e)}")

def analyze_vulnerabilities(scan_results):
    """Analyze potential vulnerabilities based on scan results"""
    vulnerabilities = []
    recommendations = []
    
    # Check for missing security headers
    if "Security" not in scan_results:
        vulnerabilities.append({
            "type": "Security Headers",
            "severity": "High",
            "description": "No security headers detected",
            "recommendation": "Implement security headers like X-Frame-Options, X-XSS-Protection, and X-Content-Type-Options"
        })
    
    # Check for outdated technologies
    outdated_techs = {
        "jQuery": "Consider upgrading to modern JavaScript frameworks",
        "Bootstrap": "Update to latest version for security patches",
        "WordPress": "Ensure WordPress and plugins are up to date"
    }
    
    for category, techs in scan_results.items():
        if category == "Scanning Details":
            continue
            
        for tech, version, _ in techs:
            if tech in outdated_techs:
                vulnerabilities.append({
                    "type": "Outdated Technology",
                    "severity": "Medium",
                    "description": f"Using potentially outdated {tech}",
                    "recommendation": outdated_techs[tech]
                })
    
    # Check for analytics and tracking
    if "Analytics" not in scan_results:
        vulnerabilities.append({
            "type": "Analytics",
            "severity": "Low",
            "description": "No analytics tools detected",
            "recommendation": "Consider implementing analytics for better user behavior tracking"
        })
    
    # Generate test recommendations
    if "Security" not in scan_results:
        recommendations.append("XSS Test")
    if "Databases" in scan_results:
        recommendations.append("SQL Injection Test")
    if "Web Servers" in scan_results:
        recommendations.append("DDoS Test")
    
    return vulnerabilities, recommendations

# UI Components
st.title(f"🔍 {texts['page_title']}")
st.markdown(texts['description'])

# Scan Configuration
target_url = st.text_input(texts['target_website'], "harvard.edu")

# Scan Mode Selection
scan_mode = st.radio(
    "Select Scan Mode:",
    ["Basic Scan", "Advanced Scan"],
    horizontal=True
)

if scan_mode == "Basic Scan":
    st.info("Basic scan will check for common technologies and basic security headers.")
else:
    st.info("Advanced scan includes SSL analysis, detailed security checks, and performance metrics.")

col1, col2 = st.columns([2, 1])

with col1:
    scan_type = st.multiselect(
        texts['scan_categories'],
        ["Analytics", "Web Servers", "Programming Languages", "Frameworks", 
         "Security", "Hosting", "CMS", "E-commerce", "JavaScript Libraries", "Databases"],
        default=["Analytics", "Web Servers", "Programming Languages", "Frameworks"]
    )

with col2:
    scan_depth = st.select_slider(
        texts['depth'],
        options=[texts['basic'], texts['standard'], texts['deep']],
        value=texts['standard']
    )

# Launch Scan Button
if st.button(texts['start_scan']):
    with st.spinner(texts['scanning']):
        try:
            # Perform the scan based on selected mode
            if scan_mode == "Basic Scan":
                scan_results = basic_scan(target_url)
            else:
                scan_results = advanced_scan(target_url)
            
            # Store in history
            st.session_state.scan_history.append({
                "timestamp": datetime.now(),
                "target": target_url,
                "mode": scan_mode,
                "technologies": sum(len(techs) for techs in scan_results.values() if isinstance(techs, list)),
                "categories": len([k for k, v in scan_results.items() if isinstance(v, list)])
            })
            
            # Display Results
            st.header(texts['scan_results'])
            
            # Summary metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric(texts['tech_detected'], 
                         sum(len(techs) for techs in scan_results.values() if isinstance(techs, list)))
            with col2:
                st.metric(texts['categories_found'], 
                         len([k for k, v in scan_results.items() if isinstance(v, list)]))
            with col3:
                if "Scanning Details" in scan_results:
                    st.metric(texts['response_time'], 
                             scan_results["Scanning Details"]["Response Time"])
            
            # Detailed results
            for category, technologies in scan_results.items():
                if category == "Scanning Details":
                    continue
                    
                with st.expander(f"{category} ({len(technologies)})"):
                    for tech, version, period in technologies:
                        st.markdown(f"""
                        **{tech}**  
                        {texts['version']}: `{version}`  
                        {texts['period']}: *{period}*
                        """)
            
            # Scanning Details
            if "Scanning Details" in scan_results:
                with st.expander(texts['scanning_details']):
                    for key, value in scan_results["Scanning Details"].items():
                        st.write(f"**{key}:** {value}")
            
            # SSL Details (only in advanced scan)
            if scan_mode == "Advanced Scan" and "SSL Details" in scan_results:
                with st.expander("🔒 SSL/TLS Certificate Details"):
                    for key, value in scan_results["SSL Details"].items():
                        st.write(f"**{key}:** {value}")
            
            # Technology Distribution
            tech_distribution = {
                category: len(techs) 
                for category, techs in scan_results.items() 
                if category != "Scanning Details"
            }
            
            if tech_distribution:
                fig = px.pie(
                    values=list(tech_distribution.values()),
                    names=list(tech_distribution.keys()),
                    title=texts['tech_distribution']
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Vulnerability Analysis (only in advanced scan)
            if scan_mode == "Advanced Scan":
                st.header("Vulnerability Analysis")
                vulnerabilities, recommendations = analyze_vulnerabilities(scan_results)
                
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        with st.expander(f"⚠️ {vuln['type']} - {vuln['severity']} Risk"):
                            st.write(f"**Description:** {vuln['description']}")
                            st.write(f"**Recommendation:** {vuln['recommendation']}")
                else:
                    st.success("No significant vulnerabilities detected in the scan")
                
                # Test Recommendations
                st.header("Recommended Tests")
                if recommendations:
                    st.write("Based on the scan results, we recommend running the following tests:")
                    for test in recommendations:
                        st.write(f"- {test}")
                    
                    # Test selection
                    selected_test = st.selectbox(
                        "Select a test to run:",
                        recommendations
                    )
                    
                    if st.button("Run Selected Test"):
                        if selected_test == "XSS Test":
                            st.switch_page("pages/2_XSS.py")
                        elif selected_test == "SQL Injection Test":
                            st.switch_page("pages/3_SQL.py")
                        elif selected_test == "DDoS Test":
                            st.switch_page("pages/4_DDoS.py")
                else:
                    st.info("No specific tests recommended based on current scan results")
            
            # File Scan Results (only in advanced scan)
            if scan_mode == "Advanced Scan" and "Files" in scan_results:
                with st.expander("📁 File Scan Results"):
                    if scan_results["Files"]:
                        st.write("Found Files:")
                        for file in scan_results["Files"]:
                            st.write(f"- {file['name']} ({file['size']} bytes)")
                    else:
                        st.info("No additional files found")
            
        except Exception as e:
            st.error(str(e))

# Scan History
st.header(texts['scan_history'])
if st.session_state.scan_history:
    history_df = pd.DataFrame(st.session_state.scan_history)
    st.dataframe(history_df, use_container_width=True)
    
    # History visualization
    fig = px.line(
        history_df,
        x="timestamp",
        y=["technologies", "categories"],
        title=texts['scan_history']
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info(texts['no_history']) 