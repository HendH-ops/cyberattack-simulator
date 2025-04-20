import socket
import threading
import queue
import time
from datetime import datetime
from pathlib import Path
import argparse
import dns.resolver
import requests
from typing import Dict, List, Tuple, Optional

# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

def resolve_domain(target: str) -> Optional[str]:
    """Resolve domain name to IP address"""
    try:
        if not target:
            return None
        # Check if input is already an IP
        try:
            socket.inet_aton(target)
            return target
        except socket.error:
            pass
        
        # Try to resolve domain
        answers = dns.resolver.resolve(target, 'A')
        return answers[0].address
    except Exception as e:
        print(f"Error resolving domain: {str(e)}")
        return None

def scan_port(ip: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, Optional[str]]:
    """Scan a single port and attempt service detection"""
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Try to connect
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            service = identify_service(sock, port)
            sock.close()
            return port, True, service
        
        sock.close()
        return port, False, None
        
    except Exception as e:
        return port, False, None

def identify_service(sock: socket.socket, port: int) -> Optional[str]:
    """Try to identify the service running on an open port"""
    try:
        # Known service
        if port in COMMON_PORTS:
            service_name = COMMON_PORTS[port]
            
            # Additional checks for HTTP/HTTPS
            if service_name in ["HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt"]:
                protocol = "https" if service_name.startswith("HTTPS") else "http"
                try:
                    response = requests.get(f"{protocol}://localhost:{port}", timeout=2, verify=False)
                    if 'server' in response.headers:
                        return f"{service_name} ({response.headers['server']})"
                except:
                    pass
            
            return service_name
        
        # Try banner grabbing
        try:
            sock.settimeout(2)
            banner = sock.recv(1024).decode().strip()
            if banner:
                return f"Unknown ({banner})"
        except:
            pass
        
        return "Unknown"
        
    except Exception as e:
        return "Unknown"

def scan_ports(target: str, start_port: int = 1, end_port: int = 1024, 
               timeout: float = 1.0, threads: int = 50) -> Dict[int, Tuple[bool, Optional[str]]]:
    """
    Scan a range of ports using multiple threads
    Returns a dictionary of port: (is_open, service_name)
    """
    ip = resolve_domain(target)
    if not ip:
        return {}
    
    # Initialize variables
    port_queue = queue.Queue()
    results = {}
    threads_list = []
    
    def worker():
        while True:
            try:
                port = port_queue.get_nowait()
            except queue.Empty:
                break
            
            port, is_open, service = scan_port(ip, port, timeout)
            if is_open:
                results[port] = (True, service)
            port_queue.task_done()
    
    # Fill queue with ports
    for port in range(start_port, end_port + 1):
        port_queue.put(port)
    
    # Start threads
    for _ in range(min(threads, end_port - start_port + 1)):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads_list.append(t)
    
    # Wait for all threads to complete
    for t in threads_list:
        t.join()
    
    return results

def generate_report(target: str, results: Dict[int, Tuple[bool, Optional[str]]]) -> str:
    """Generate a report of the scan results"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)
    
    report_file = report_dir / f"port_scan_{timestamp}.txt"
    
    with open(report_file, 'w') as f:
        f.write(f"Port Scan Report\n")
        f.write(f"===============\n\n")
        f.write(f"Target: {target}\n")
        f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"IP Address: {resolve_domain(target)}\n\n")
        
        f.write("Open Ports:\n")
        f.write("==========\n")
        if results:
            for port in sorted(results.keys()):
                _, service = results[port]
                f.write(f"Port {port}: {service}\n")
        else:
            f.write("No open ports found in the scanned range.\n")
        
        f.write("\nScan Summary:\n")
        f.write("============\n")
        f.write(f"Total ports scanned: {len(results)}\n")
        f.write(f"Open ports found: {len([p for p in results.keys() if results[p][0]])}\n")
    
    return report_file

def main():
    """Command-line interface for port scanning"""
    parser = argparse.ArgumentParser(description='Port Scanning Tool')
    parser.add_argument('--target', required=True, help='Target IP or domain name')
    parser.add_argument('--start-port', type=int, default=1, help='Start port number (default: 1)')
    parser.add_argument('--end-port', type=int, default=1024, help='End port number (default: 1024)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout in seconds (default: 1.0)')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50)')
    
    args = parser.parse_args()
    
    print(f"\nStarting port scan on: {args.target}")
    print(f"Port range: {args.start_port}-{args.end_port}")
    print("=" * 50)
    
    try:
        # Resolve IP
        ip = resolve_domain(args.target)
        if not ip:
            print("Could not resolve target host")
            return
        
        print(f"Resolved IP: {ip}")
        print(f"Scanning ports...")
        
        # Start scanning
        start_time = time.time()
        results = scan_ports(args.target, args.start_port, args.end_port, 
                           args.timeout, args.threads)
        
        # Print results
        if results:
            print("\nOpen ports:")
            print("-----------")
            for port in sorted(results.keys()):
                _, service = results[port]
                print(f"Port {port}: {service}")
        else:
            print("\nNo open ports found in the specified range.")
        
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