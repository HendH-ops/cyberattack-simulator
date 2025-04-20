import requests
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple
import time

# Common sensitive files and directories to check
SENSITIVE_PATHS = [
    # Configuration files
    '.env',
    'config.php',
    'config.json',
    'config.yml',
    'config.yaml',
    'settings.php',
    'wp-config.php',
    
    # Backup files
    'backup.zip',
    'backup.tar.gz',
    'backup.sql',
    
    # Log files
    'error.log',
    'access.log',
    
    # Common directories
    'admin/',
    'config/',
    'backup/',
    'logs/',
]

# Common API endpoints that might expose sensitive information
API_ENDPOINTS = [
    '/api/v1/config',
    '/api/v1/settings'
]

def check_path(url: str, path: str) -> Tuple[bool, int]:
    """Check if a specific path exists and returns status code"""
    try:
        full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        response = requests.get(full_url, timeout=5, verify=False)
        
        # Consider the path as existing if we get any response
        # We'll interpret the status code in the UI
        return True, response.status_code
    except requests.RequestException as e:
        # If we can't connect at all, consider the path as not existing
        return False, 0

def scan_credentials(url: str) -> Dict[str, List[Dict[str, str]]]:
    """Scan for sensitive files and directories"""
    results = {
        'sensitive_files': [],
        'api_endpoints': []
    }
    
    # Check sensitive files and directories
    for path in SENSITIVE_PATHS:
        exists, status_code = check_path(url, path)
        if exists:
            results['sensitive_files'].append({
                'path': path,
                'status_code': status_code,
                'url': f"{url.rstrip('/')}/{path.lstrip('/')}"
            })
    
    # Check API endpoints
    for endpoint in API_ENDPOINTS:
        exists, status_code = check_path(url, endpoint)
        if exists:
            results['api_endpoints'].append({
                'endpoint': endpoint,
                'status_code': status_code,
                'url': f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
            })
    
    return results

def generate_report(url: str, results: Dict[str, List[Dict[str, str]]]) -> str:
    """Generate a report of the scan results"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)
    
    report_file = report_dir / f"credentials_scan_{timestamp}.txt"
    
    with open(report_file, 'w') as f:
        f.write(f"Credentials Scan Report\n")
        f.write(f"=====================\n\n")
        f.write(f"Target: {url}\n")
        f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Write sensitive files section
        f.write("Sensitive Files Found:\n")
        f.write("====================\n")
        if results['sensitive_files']:
            for file in results['sensitive_files']:
                f.write(f"Path: {file['path']}\n")
                f.write(f"Status Code: {file['status_code']}\n")
                f.write(f"URL: {file['url']}\n")
                f.write("-" * 50 + "\n")
        else:
            f.write("No sensitive files found.\n")
        
        # Write API endpoints section
        f.write("\nAPI Endpoints Found:\n")
        f.write("==================\n")
        if results['api_endpoints']:
            for endpoint in results['api_endpoints']:
                f.write(f"Endpoint: {endpoint['endpoint']}\n")
                f.write(f"Status Code: {endpoint['status_code']}\n")
                f.write(f"URL: {endpoint['url']}\n")
                f.write("-" * 50 + "\n")
        else:
            f.write("No sensitive API endpoints found.\n")
    
    return str(report_file)

def main():
    """Command-line interface for credentials scanning"""
    parser = argparse.ArgumentParser(description='Credentials Scanning Tool')
    parser.add_argument('--target', required=True, help='Target URL to scan')
    
    args = parser.parse_args()
    
    print(f"\nStarting credentials scan on: {args.target}")
    print("=" * 50)
    
    try:
        start_time = time.time()
        results = scan_credentials(args.target)
        
        # Print results
        if results['sensitive_files']:
            print("\nSensitive files found:")
            for file in results['sensitive_files']:
                print(f"- {file['path']} (Status: {file['status_code']})")
        
        if results['api_endpoints']:
            print("\nSensitive API endpoints found:")
            for endpoint in results['api_endpoints']:
                print(f"- {endpoint['endpoint']} (Status: {endpoint['status_code']})")
        
        # Generate report
        report_file = generate_report(args.target, results)
        print(f"\nScan completed in {time.time() - start_time:.2f} seconds")
        print(f"Report generated: {report_file}")
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error during scan: {str(e)}")

if __name__ == "__main__":
    main() 