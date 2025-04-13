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

def scan_website(url, depth="basic"):
    """Scan website for technologies and vulnerabilities"""
    try:
        # Validate and clean URL
        if not url:
            return {
                "error": "Invalid URL",
                "message": "URL cannot be empty",
                "vulnerabilities": []
            }
            
        # Remove any whitespace
        url = url.strip()
        
        # Add https:// if not present
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Parse URL to validate
        try:
            parsed_url = urlparse(url)
            if not parsed_url.netloc:
                return {
                    "error": "Invalid URL",
                    "message": "Please enter a valid website address",
                    "vulnerabilities": []
                }
        except Exception as e:
            return {
                "error": "Invalid URL",
                "message": f"URL parsing error: {str(e)}",
                "vulnerabilities": []
            }
            
        # Initialize results
        results = {
            "technologies": [],
            "vulnerabilities": [],
            "server_info": {},
            "ssl_info": {},
            "headers": {}
        }
        
        # Make request with custom headers and longer timeout
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=30, verify=True)
            response.raise_for_status()  # Raise an exception for bad status codes
        except requests.exceptions.SSLError as e:
            return {
                "error": "SSL Error",
                "message": f"SSL verification failed: {str(e)}",
                "vulnerabilities": [{
                    "type": "SSL/TLS Error",
                    "severity": "High",
                    "description": "SSL/TLS connection failed",
                    "recommendation": "Check SSL/TLS configuration and certificate"
                }]
            }
        except requests.exceptions.ConnectionError as e:
            return {
                "error": "Connection Error",
                "message": f"Could not connect to {url}. Please check if the website is accessible.",
                "vulnerabilities": [{
                    "type": "Connection Error",
                    "severity": "High",
                    "description": "Failed to establish connection",
                    "recommendation": "Verify the website address and ensure it's accessible"
                }]
            }
        except requests.exceptions.Timeout as e:
            return {
                "error": "Timeout Error",
                "message": "The request timed out. The website might be slow or unresponsive.",
                "vulnerabilities": [{
                    "type": "Performance Issue",
                    "severity": "Medium",
                    "description": "Website response time exceeded 30 seconds",
                    "recommendation": "Check website performance and server response time"
                }]
            }
        except requests.exceptions.RequestException as e:
            return {
                "error": "Request Error",
                "message": f"Error making request: {str(e)}",
                "vulnerabilities": [{
                    "type": "Connection Error",
                    "severity": "High",
                    "description": f"Request failed: {str(e)}",
                    "recommendation": "Check the website address and try again"
                }]
            }

        # Continue with the rest of the scanning logic...
        soup = BeautifulSoup(response.text, 'lxml')
        html_content = response.text.lower()
        
        # Initialize technologies list
        technologies = []
        
        # Database Detection
        database_patterns = {
            'mysql': {
                'patterns': ['mysql', 'mysqli', 'pdo_mysql'],
                'name': 'MySQL',
                'category': 'Databases'
            },
            'postgresql': {
                'patterns': ['postgresql', 'pgsql', 'postgres'],
                'name': 'PostgreSQL',
                'category': 'Databases'
            },
            'mongodb': {
                'patterns': ['mongodb', 'mongo'],
                'name': 'MongoDB',
                'category': 'Databases'
            },
            'redis': {
                'patterns': ['redis'],
                'name': 'Redis',
                'category': 'Databases'
            },
            'oracle': {
                'patterns': ['oracle', 'oci8'],
                'name': 'Oracle',
                'category': 'Databases'
            }
        }
        
        for db, info in database_patterns.items():
            if any(pattern in html_content for pattern in info['patterns']):
                technologies.append({
                    "name": info['name'],
                    "category": info['category'],
                    "version": "Unknown",
                    "period": f"{datetime.now().year}-{datetime.now().year + 1}",
                    "confidence": 75
                })
        
        # Cloud Services Detection
        cloud_patterns = {
            'aws': {
                'patterns': ['amazonaws.com', 'aws-', 'cloudfront.net', 's3.amazonaws'],
                'name': 'Amazon Web Services',
                'category': 'Cloud Services'
            },
            'azure': {
                'patterns': ['azure.com', 'windowsazure.com', 'msft.net'],
                'name': 'Microsoft Azure',
                'category': 'Cloud Services'
            },
            'gcp': {
                'patterns': ['googleusercontent.com', 'appspot.com', 'googleapis.com'],
                'name': 'Google Cloud Platform',
                'category': 'Cloud Services'
            },
            'cloudflare': {
                'patterns': ['cloudflare.com', 'cloudflare-'],
                'name': 'Cloudflare',
                'category': 'Cloud Services'
            },
            'digitalocean': {
                'patterns': ['digitalocean.com', 'digitaloceanspaces.com'],
                'name': 'DigitalOcean',
                'category': 'Cloud Services'
            }
        }
        
        for cloud, info in cloud_patterns.items():
            if any(pattern in html_content or pattern in str(response.headers) for pattern in info['patterns']):
                technologies.append({
                    "name": info['name'],
                    "category": info['category'],
                    "version": "N/A",
                    "period": f"{datetime.now().year}-{datetime.now().year + 1}",
                    "confidence": 85
                })
        
        # Framework Detection with Version
        framework_patterns = {
            'laravel': {
                'patterns': ['laravel', 'csrf-token'],
                'version_pattern': r'Laravel[\/\s]?([\d\.]+)',
                'name': 'Laravel',
                'category': 'Frameworks'
            },
            'django': {
                'patterns': ['django', 'csrfmiddlewaretoken'],
                'version_pattern': r'Django[\/\s]?([\d\.]+)',
                'name': 'Django',
                'category': 'Frameworks'
            },
            'react': {
                'patterns': ['react.development.js', 'react.production.min.js'],
                'version_pattern': r'React[\/\s]?([\d\.]+)',
                'name': 'React',
                'category': 'Frameworks'
            },
            'vue': {
                'patterns': ['vue.js', 'vue.min.js'],
                'version_pattern': r'Vue[\/\s]?([\d\.]+)',
                'name': 'Vue.js',
                'category': 'Frameworks'
            },
            'angular': {
                'patterns': ['angular.js', 'angular.min.js', 'ng-app'],
                'version_pattern': r'Angular[\/\s]?([\d\.]+)',
                'name': 'Angular',
                'category': 'Frameworks'
            },
            'spring': {
                'patterns': ['spring.js', 'spring-boot'],
                'version_pattern': r'Spring[\/\s]?([\d\.]+)',
                'name': 'Spring',
                'category': 'Frameworks'
            }
        }
        
        for framework, info in framework_patterns.items():
            if any(pattern in html_content for pattern in info['patterns']):
                # Try to find version
                version = "Unknown"
                version_match = re.search(info['version_pattern'], html_content)
                if version_match:
                    version = version_match.group(1)
                
                technologies.append({
                    "name": info['name'],
                    "category": info['category'],
                    "version": version,
                    "period": f"{datetime.now().year}-{datetime.now().year + 1}",
                    "confidence": 90
                })
        
        # JavaScript Library Detection (enhanced)
        js_patterns = {
            'jquery': {
                'patterns': ['jquery'],
                'version_pattern': r'jQuery[\/\s]?([\d\.]+)',
                'name': 'jQuery',
                'category': 'JavaScript Libraries'
            },
            'bootstrap': {
                'patterns': ['bootstrap'],
                'version_pattern': r'Bootstrap[\/\s]?([\d\.]+)',
                'name': 'Bootstrap',
                'category': 'JavaScript Libraries'
            },
            'moment': {
                'patterns': ['moment.js'],
                'version_pattern': r'Moment[\/\s]?([\d\.]+)',
                'name': 'Moment.js',
                'category': 'JavaScript Libraries'
            }
        }
        
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src', '')
            for js, info in js_patterns.items():
                if any(pattern in src.lower() or pattern in str(script).lower() for pattern in info['patterns']):
                    # Try to find version
                    version = "Unknown"
                    version_match = re.search(info['version_pattern'], str(script))
                    if version_match:
                        version = version_match.group(1)
                    
                    technologies.append({
                        "name": info['name'],
                        "category": info['category'],
                        "version": version,
                        "period": f"{datetime.now().year}-{datetime.now().year + 1}",
                        "confidence": 90
                    })
        
        # Add all detected technologies to results
        results["technologies"].extend(technologies)
        
        # Check for HTTP vs HTTPS
        if not url.startswith('https://'):
            results["vulnerabilities"].append({
                "type": "Insecure Protocol",
                "severity": "High",
                "description": "Website is using HTTP instead of HTTPS",
                "recommendation": "Enable HTTPS and redirect all HTTP traffic to HTTPS"
            })
        
        # Check for security headers
        security_headers = {
            'X-Frame-Options': 'Missing clickjacking protection',
            'X-XSS-Protection': 'Missing XSS protection',
            'X-Content-Type-Options': 'Missing MIME-type protection',
            'Strict-Transport-Security': 'Missing HSTS protection',
            'Content-Security-Policy': 'Missing CSP protection'
        }
        
        for header, description in security_headers.items():
            if header not in response.headers:
                results["vulnerabilities"].append({
                    "type": f"Missing {header}",
                    "severity": "Medium",
                    "description": description,
                    "recommendation": f"Add {header} header to improve security"
                })
        
        # Check for server information disclosure
        if 'Server' in response.headers:
            server = response.headers['Server']
            if any(tech in server.lower() for tech in ['apache', 'nginx', 'iis']):
                results["vulnerabilities"].append({
                    "type": "Information Disclosure",
                    "severity": "Low",
                    "description": f"Server header reveals technology: {server}",
                    "recommendation": "Configure server to hide version information"
                })
        
        # Check for cookies without secure flag
        for cookie in response.cookies:
            if not cookie.secure:
                results["vulnerabilities"].append({
                    "type": "Insecure Cookie",
                    "severity": "Medium",
                    "description": f"Cookie '{cookie.name}' is set without Secure flag",
                    "recommendation": "Set Secure flag for all cookies"
                })
        
        # Get SSL info and vulnerabilities
        ssl_info = analyze_ssl_certificate(url.split('://')[1].split('/')[0])
        if "Vulnerabilities" in ssl_info:
            results["vulnerabilities"].extend(ssl_info["Vulnerabilities"])
        results["ssl_info"] = ssl_info
        
        # Store all findings
        results["vulnerabilities"] = results["vulnerabilities"]
        results["server_info"] = {
            "server": response.headers.get('Server', 'Unknown'),
            "x-powered-by": response.headers.get('X-Powered-By', 'Unknown'),
            "content-type": response.headers.get('Content-Type', 'Unknown')
        }
        results["headers"] = dict(response.headers)
        
        return results
        
    except requests.exceptions.SSLError:
        return {
            "error": "SSL Error",
            "message": "Could not establish secure connection to the website",
            "vulnerabilities": [{
                "type": "SSL/TLS Error",
                "severity": "High",
                "description": "SSL/TLS connection failed",
                "recommendation": "Check SSL/TLS configuration and certificate"
            }]
        }
    except requests.exceptions.ConnectionError:
        return {
            "error": "Connection Error",
            "message": "Could not connect to the website",
            "vulnerabilities": [{
                "type": "Connection Error",
                "severity": "High",
                "description": "Failed to establish connection",
                "recommendation": "Check if the website is accessible"
            }]
        }
    except Exception as e:
        return {
            "error": "Scan Error",
            "message": str(e),
            "vulnerabilities": [{
                "type": "Scan Error",
                "severity": "Unknown",
                "description": f"Error during scan: {str(e)}",
                "recommendation": "Check the error message and try again"
            }]
        }

def analyze_vulnerabilities(scan_results):
    """Analyze scan results for vulnerabilities and recommend tests based on risk levels"""
    vulnerabilities = []
    recommendations = set()  # Using a set to prevent duplicates
    
    # Helper function to add recommendation
    def add_recommendation(test_type, reason, risk_level, description, recommendation, test_key):
        recommendation_tuple = (test_type, reason, risk_level)
        if recommendation_tuple not in recommendations:
            recommendations.add(recommendation_tuple)
            vulnerabilities.append({
                "type": test_type,
                "risk": risk_level,
                "description": description,
                "recommendation": recommendation,
                "test_key": test_key
            })
            return True
        return False

    # Critical Risk Checks
    if "E-commerce" in scan_results:
        add_recommendation(
            "SQL Injection Test",
            "E-commerce platform detected",
            "Critical",
            "E-commerce systems handle sensitive payment data and require thorough security testing",
            "Run comprehensive SQL injection tests and implement WAF protection",
            "sql_ecommerce_critical"
        )

    # High Risk Checks
    # JavaScript Framework Security
    if any(tech[0] in ["jQuery", "React", "Vue.js", "Angular"] for techs in scan_results.values() for tech in techs):
        add_recommendation(
            "XSS Test",
            "JavaScript frameworks detected",
            "High",
            "JavaScript-heavy applications are common targets for XSS attacks",
            "Run XSS tests and implement Content Security Policy (CSP)",
            "xss_js_high"
        )

    # Server Technology
    if "Web Servers" in scan_results:
        server_tech = [tech[0] for tech in scan_results["Web Servers"]]
        if any(tech in ["Apache", "Nginx", "IIS"] for tech in server_tech):
            add_recommendation(
                "DDoS Test",
                f"Server using {', '.join(server_tech)}",
                "High",
                "Web servers need protection against DDoS attacks",
                "Run DDoS simulation tests and implement rate limiting",
                "ddos_server_high"
            )

    # PHP Security
    if any("PHP" in tech[0] for techs in scan_results.values() for tech in techs):
        add_recommendation(
            "SQL Injection Test",
            "PHP application detected",
            "High",
            "PHP applications need proper SQL injection protection",
            "Run SQL injection tests and use prepared statements",
            "sql_php_high"
        )

    # SSL/TLS Security
    if not any(tech[0] == "HSTS" for techs in scan_results.get("Security", []) for tech in techs):
        add_recommendation(
            "SSL Test",
            "Missing HSTS protection",
            "High",
            "Site is vulnerable to SSL/TLS downgrade attacks",
            "Enable HSTS and configure SSL/TLS properly",
            "ssl_hsts_high"
        )

    # Medium Risk Checks
    # Security Headers
    required_headers = {
        "X-Frame-Options": ("Clickjacking Protection", "frame_protection"),
        "X-XSS-Protection": ("XSS Protection", "xss_protection"),
        "Content-Security-Policy": ("Content Security", "csp_protection"),
        "X-Content-Type-Options": ("MIME Sniffing Protection", "mime_protection")
    }
    
    if "Security" in scan_results:
        present_headers = {tech[0] for tech in scan_results["Security"]}
        for header, (protection, key) in required_headers.items():
            if header not in present_headers:
                add_recommendation(
                    "Security Header Test",
                    f"Missing {header}",
                    "Medium",
                    f"Site lacks {protection}",
                    f"Implement {header} header with appropriate values",
                    f"header_{key}_medium"
                )

    # Database Security
    if any(tech["name"] in ["MySQL", "PostgreSQL", "MongoDB"] for tech in scan_results.get("technologies", [])):
        add_recommendation(
            "Database Security Test",
            "Database system detected",
            "Medium",
            "Database systems need proper security configuration",
            "Run database security assessment and implement proper access controls",
            "db_security_medium"
        )

    # Low Risk Checks
    # Information Disclosure
    if "Server" in scan_results.get("server_info", {}):
        add_recommendation(
            "Information Disclosure Test",
            "Server information visible",
            "Low",
            "Server is revealing technology information",
            "Configure server to hide version information",
            "info_disclosure_low"
        )

    # Display recommendations grouped by risk level
    if vulnerabilities:
        st.markdown("## " + texts.get("recommended_tests", "Recommended Tests"))
        
        # Group vulnerabilities by risk level
        risk_levels = ["Critical", "High", "Medium", "Low"]
        for risk_level in risk_levels:
            risk_vulns = [v for v in vulnerabilities if v["risk"] == risk_level]
            if risk_vulns:
                if risk_level == "Critical":
                    risk_icon = "🚨"
                elif risk_level == "High":
                    risk_icon = "⚠️"
                elif risk_level == "Medium":
                    risk_icon = "⚡"
                else:
                    risk_icon = "ℹ️"
                    
                st.markdown(f"### {risk_icon} {risk_level} Risk Level")
                for vuln in risk_vulns:
                    with st.expander(f"{vuln['type']}", expanded=True):
                        st.markdown(f"**Description:** {vuln['description']}")
                        st.markdown(f"**Recommendation:** {vuln['recommendation']}")
                        
                        # Create button with unique key
                        if st.button(f"Run Test", key=vuln['test_key']):
                            st.session_state['selected_test'] = vuln['type'].split()[0]
                            st.experimental_rerun()
                st.markdown("---")
    
    return vulnerabilities

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
        # Perform the scan
            scan_results = scan_website(target_url)
        
            # Check if there was an error
            if "error" in scan_results:
                st.error(f"Scan Error: {scan_results['message']}")
            else:
        # Store in history
        st.session_state.scan_history.append({
                    "timestamp": datetime.now(),
                    "target": target_url,
                    "mode": scan_mode,
                    "technologies": len(scan_results.get("technologies", [])),
                    "vulnerabilities": len(scan_results.get("vulnerabilities", [])),
        })
        
        # Display Results
                st.header(texts['scan_results'])
                
                # Summary metrics
        col1, col2 = st.columns(2)
                with col1:
                    st.metric(texts['tech_detected'], len(scan_results.get("technologies", [])))
                with col2:
                    st.metric("Vulnerabilities", len(scan_results.get("vulnerabilities", [])))
                
                # Display Vulnerabilities first if any exist
                vulnerabilities = scan_results.get("vulnerabilities", [])
                if vulnerabilities:
                    with st.expander("🚨 Vulnerabilities", expanded=True):
                        for vuln in vulnerabilities:
                            st.markdown(f"""
                            ### ⚠️ {vuln['type']} - {vuln['severity']} Risk
                            **Description:** {vuln['description']}  
                            **Recommendation:** {vuln['recommendation']}
                            ---
                            """)
                else:
                    st.success("No vulnerabilities detected!")
                
                # Display Test Recommendations
                st.subheader("🎯 Recommended Tests")
                analyze_vulnerabilities(scan_results)
                
                # Display Technologies
                technologies = scan_results.get("technologies", [])
                if technologies:
                    with st.expander("🔍 Detected Technologies", expanded=True):
                        for tech in technologies:
                            st.markdown(f"""
                            ### {tech['name']} ({tech['category']})
                            **Version:** `{tech['version']}`  
                            **Confidence:** {tech['confidence']}%  
                            **Period:** {tech['period']}
                            ---
                            """)
                
                # Display Server Information
                server_info = scan_results.get("server_info", {})
                if server_info:
                    with st.expander("🖥️ Server Information"):
                        for key, value in server_info.items():
                            st.markdown(f"**{key.title()}:** {value}")
                
                # Display SSL Information
                ssl_info = scan_results.get("ssl_info", {})
                if ssl_info:
                    with st.expander("🔒 SSL/TLS Certificate Details"):
                        for key, value in ssl_info.items():
                            if key != "Vulnerabilities":  # Skip vulnerabilities as they're shown above
                                st.markdown(f"**{key}:** {value}")
                
                # Display Headers
                headers = scan_results.get("headers", {})
                if headers:
                    with st.expander("📋 HTTP Headers"):
                        for header, value in headers.items():
                            st.markdown(f"**{header}:** {value}")
                
                # Technology Distribution
                if technologies:
                    tech_by_category = {}
                    for tech in technologies:
                        category = tech["category"]
                        tech_by_category[category] = tech_by_category.get(category, 0) + 1
                    
                    if tech_by_category:
                        fig = px.pie(
                            values=list(tech_by_category.values()),
                            names=list(tech_by_category.keys()),
                            title=texts['tech_distribution']
                        )
                        st.plotly_chart(fig, use_container_width=True)
        
        except Exception as e:
            st.error(f"Error during scan: {str(e)}")

# Scan History
st.header(texts['scan_history'])
if st.session_state.scan_history:
    history_df = pd.DataFrame(st.session_state.scan_history)
    st.dataframe(history_df, use_container_width=True)
    
    # History visualization
    if len(history_df) > 0:
        fig = px.line(
            history_df,
            x="timestamp",
            y=["technologies", "vulnerabilities"],
            title=texts['scan_history']
        )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info(texts['no_history']) 