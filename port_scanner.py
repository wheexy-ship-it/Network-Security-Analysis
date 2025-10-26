#!/usr/bin/env python3
“””
Network Port Scanner
A simple yet effective port scanner for network reconnaissance
WARNING: Only use on networks you have permission to scan!
Author: [Your Name]
“””

import socket
import argparse
from datetime import datetime
import threading
from queue import Queue

# Common service ports and their descriptions

COMMON_PORTS = {
21: ‘FTP’,
22: ‘SSH’,
23: ‘Telnet’,
25: ‘SMTP’,
53: ‘DNS’,
80: ‘HTTP’,
110: ‘POP3’,
143: ‘IMAP’,
443: ‘HTTPS’,
445: ‘SMB’,
3306: ‘MySQL’,
3389: ‘RDP’,
5432: ‘PostgreSQL’,
8080: ‘HTTP-Proxy’,
8443: ‘HTTPS-Alt’
}

class PortScanner:
def *init*(self, target, ports, threads=100, timeout=1):
“”“Initialize the port scanner.”””
self.target = target
self.ports = ports
self.threads = threads
self.timeout = timeout
self.open_ports = []
self.queue = Queue()
self.print_lock = threading.Lock()


def resolve_target(self):
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(self.target)
        print(f"[+] Target: {self.target}")
        print(f"[+] IP Address: {ip}")
        return ip
    except socket.gaierror:
        print(f"[-] Could not resolve hostname: {self.target}")
        return None

def scan_port(self, port):
    """Scan a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        result = sock.connect_ex((self.target, port))
        
        if result == 0:
            service = COMMON_PORTS.get(port, 'Unknown')
            
            # Try to grab banner
            banner = self.grab_banner(sock, port)
            
            with self.print_lock:
                print(f"[+] Port {port:5d} OPEN    - {service:15s} {banner}")
                self.open_ports.append({
                    'port': port,
                    'service': service,
                    'banner': banner
                })
        
        sock.close()
    except socket.error:
        pass
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        exit(0)

def grab_banner(self, sock, port):
    """Attempt to grab service banner."""
    try:
        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        return banner.split('\n')[0][:50] if banner else ''
    except:
        return ''

def threader(self):
    """Worker thread function."""
    while True:
        port = self.queue.get()
        self.scan_port(port)
        self.queue.task_done()

def scan(self):
    """Execute the port scan."""
    ip = self.resolve_target()
    if not ip:
        return
    
    print(f"[+] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[+] Scanning {len(self.ports)} ports with {self.threads} threads")
    print("-" * 80)
    
    # Start worker threads
    for _ in range(self.threads):
        t = threading.Thread(target=self.threader, daemon=True)
        t.start()
    
    # Fill the queue with ports to scan
    for port in self.ports:
        self.queue.put(port)
    
    # Wait for all scans to complete
    self.queue.join()
    
    print("-" * 80)
    print(f"\n[+] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    self.generate_report()

def generate_report(self):
    """Generate scan report."""
    print(f"\n{'='*80}")
    print(f"SCAN SUMMARY")
    print(f"{'='*80}")
    print(f"Target: {self.target}")
    print(f"Total Ports Scanned: {len(self.ports)}")
    print(f"Open Ports Found: {len(self.open_ports)}")
    
    if self.open_ports:
        print(f"\n{'='*80}")
        print("OPEN PORTS DETAILS")
        print(f"{'='*80}")
        print(f"{'Port':<10} {'Service':<20} {'Banner'}")
        print("-" * 80)
        
        for port_info in sorted(self.open_ports, key=lambda x: x['port']):
            print(f"{port_info['port']:<10} {port_info['service']:<20} {port_info['banner']}")
        
        # Security recommendations
        self.security_assessment()
    else:
        print("\n[*] No open ports found")

def security_assessment(self):
    """Provide basic security assessment."""
    print(f"\n{'='*80}")
    print("SECURITY ASSESSMENT")
    print(f"{'='*80}")
    
    vulnerable_services = []
    
    for port_info in self.open_ports:
        port = port_info['port']
        service = port_info['service']
        
        # Check for potentially risky services
        if port == 21:
            vulnerable_services.append("⚠  FTP (Port 21) - Consider using SFTP instead")
        elif port == 23:
            vulnerable_services.append("🔴 Telnet (Port 23) - CRITICAL: Unencrypted, use SSH instead")
        elif port == 445:
            vulnerable_services.append("⚠  SMB (Port 445) - Ensure proper authentication and patches")
        elif port == 3389:
            vulnerable_services.append("⚠  RDP (Port 3389) - Ensure strong passwords and consider VPN")
        elif port == 8080:
            vulnerable_services.append("ℹ  HTTP-Proxy (Port 8080) - Verify if this should be exposed")
    
    if vulnerable_services:
        print("\n[!] Potential Security Concerns:")
        for concern in vulnerable_services:
            print(f"    {concern}")
    else:
        print("\n[+] No immediate security concerns identified")
    
    print("\n[*] Recommendations:")
    print("    • Close unnecessary ports")
    print("    • Use firewalls to restrict access")
    print("    • Keep services updated and patched")
    print("    • Use strong authentication")
    print("    • Monitor logs for suspicious activity")


def parse_ports(port_string):
“”“Parse port specification into list of ports.”””
ports = []


try:
    # Handle comma-separated ports: 80,443,8080
    if ',' in port_string:
        ports = [int(p.strip()) for p in port_string.split(',')]
    
    # Handle port ranges: 1-1000
    elif '-' in port_string:
        start, end = map(int, port_string.split('-'))
        ports = list(range(start, end + 1))
    
    # Handle single port: 80
    else:
        ports = [int(port_string)]
    
    return ports
except ValueError:
    print(f"[-] Invalid port specification: {port_string}")
    return []


def main():
parser = argparse.ArgumentParser(
description=‘Network Port Scanner - Scan network ports for security assessment’,
formatter_class=argparse.RawDescriptionHelpFormatter,
epilog=”””
Examples:
Scan common ports:
python port_scanner.py 192.168.1.1

Scan specific ports:
python port_scanner.py example.com -p 80,443,8080

Scan port range:
python port_scanner.py 192.168.1.1 -p 1-1000

Fast scan with more threads:
python port_scanner.py 192.168.1.1 -t 200

⚠  WARNING: Only scan networks you have permission to test!
Unauthorized port scanning may be illegal.

Author: [Your Name]
“””
)


parser.add_argument('target', help='Target hostname or IP address')
parser.add_argument('-p', '--ports', default='common',
                   help='Ports to scan: "common", "all", "1-1000", or "80,443,8080"')
parser.add_argument('-t', '--threads', type=int, default=100,
                   help='Number of threads to use (default: 100)')
parser.add_argument('--timeout', type=float, default=1.0,
                   help='Connection timeout in seconds (default: 1.0)')

args = parser.parse_args()

# Determine which ports to scan
if args.ports.lower() == 'common':
    ports = list(COMMON_PORTS.keys())
elif args.ports.lower() == 'all':
    ports = list(range(1, 65536))
    print("[!] Warning: Scanning all 65535 ports will take a while!")
else:
    ports = parse_ports(args.ports)
    if not ports:
        return

print("""
╔═══════════════════════════════════════════╗
║     Network Port Scanner v1.0             ║
║     Security Assessment Tool              ║
╚═══════════════════════════════════════════╝

⚠  Use responsibly and only on authorized networks
""")

scanner = PortScanner(args.target, ports, args.threads, args.timeout)

try:
    scanner.scan()
except KeyboardInterrupt:
    print("\n\n[-] Scan interrupted by user")
    print(f"[*] Ports scanned so far: {len(scanner.open_ports)} open ports found")


if *name* == “*main*”:
main()