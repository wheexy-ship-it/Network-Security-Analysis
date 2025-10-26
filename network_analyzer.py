#!/usr/bin/env python3
“””
Network Traffic Analyzer
A tool for analyzing network packets and detecting suspicious activities.
Author: [Your Name]
Date: October 2025
“””

import argparse
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, HTTP
from collections import defaultdict, Counter
import json
from datetime import datetime

class NetworkAnalyzer:
def *init*(self, pcap_file):
“”“Initialize the analyzer with a pcap file.”””
self.pcap_file = pcap_file
self.packets = None
self.stats = {
‘total_packets’: 0,
‘protocols’: defaultdict(int),
‘source_ips’: Counter(),
‘dest_ips’: Counter(),
‘source_ports’: Counter(),
‘dest_ports’: Counter(),
‘suspicious_activities’: []
}


def load_packets(self):
    """Load packets from pcap file."""
    try:
        print(f"[+] Loading packets from {self.pcap_file}...")
        self.packets = rdpcap(self.pcap_file)
        self.stats['total_packets'] = len(self.packets)
        print(f"[+] Loaded {self.stats['total_packets']} packets successfully")
        return True
    except Exception as e:
        print(f"[-] Error loading pcap file: {e}")
        return False

def analyze_protocols(self):
    """Analyze protocol distribution in the traffic."""
    print("\n[+] Analyzing protocol distribution...")
    
    for packet in self.packets:
        if IP in packet:
            # Identify transport layer protocol
            if TCP in packet:
                self.stats['protocols']['TCP'] += 1
                self.analyze_tcp_packet(packet)
            elif UDP in packet:
                self.stats['protocols']['UDP'] += 1
                self.analyze_udp_packet(packet)
            elif ICMP in packet:
                self.stats['protocols']['ICMP'] += 1
            else:
                self.stats['protocols']['Other'] += 1
            
            # Track IP addresses
            self.stats['source_ips'][packet[IP].src] += 1
            self.stats['dest_ips'][packet[IP].dst] += 1

def analyze_tcp_packet(self, packet):
    """Analyze TCP specific information."""
    tcp_layer = packet[TCP]
    self.stats['source_ports'][tcp_layer.sport] += 1
    self.stats['dest_ports'][tcp_layer.dport] += 1
    
    # Check for common suspicious patterns
    # SYN scan detection (SYN flag set, no ACK)
    if tcp_layer.flags == 'S':
        self.detect_port_scan(packet[IP].src, tcp_layer.dport)
    
    # Check for suspicious ports
    if tcp_layer.dport in [4444, 5555, 6666, 31337]:  # Common backdoor ports
        self.stats['suspicious_activities'].append({
            'type': 'Suspicious Port',
            'src': packet[IP].src,
            'dst': packet[IP].dst,
            'port': tcp_layer.dport,
            'timestamp': datetime.now().isoformat()
        })

def analyze_udp_packet(self, packet):
    """Analyze UDP specific information."""
    udp_layer = packet[UDP]
    self.stats['source_ports'][udp_layer.sport] += 1
    self.stats['dest_ports'][udp_layer.dport] += 1

def detect_port_scan(self, src_ip, dest_port):
    """Detect potential port scanning activity."""
    # If a single IP contacts many different ports, it might be scanning
    port_threshold = 20  # Alert if more than 20 different ports contacted
    
    ports_contacted = sum(1 for activity in self.stats['suspicious_activities'] 
                         if activity.get('type') == 'Port Scan' and activity.get('src') == src_ip)
    
    if ports_contacted > port_threshold:
        return  # Already flagged this IP
    
    # Count unique destination ports from this source
    unique_ports = set()
    for packet in self.packets:
        if IP in packet and packet[IP].src == src_ip and TCP in packet:
            unique_ports.add(packet[TCP].dport)
    
    if len(unique_ports) > port_threshold:
        self.stats['suspicious_activities'].append({
            'type': 'Port Scan',
            'src': src_ip,
            'ports_contacted': len(unique_ports),
            'timestamp': datetime.now().isoformat()
        })

def detect_anomalies(self):
    """Detect various network anomalies."""
    print("\n[+] Detecting anomalies...")
    
    # Detect unusual traffic volume from single source
    for ip, count in self.stats['source_ips'].most_common(5):
        percentage = (count / self.stats['total_packets']) * 100
        if percentage > 30:  # If single IP generates >30% of traffic
            self.stats['suspicious_activities'].append({
                'type': 'High Traffic Volume',
                'src': ip,
                'packet_count': count,
                'percentage': f"{percentage:.2f}%",
                'timestamp': datetime.now().isoformat()
            })
    
    # Detect ICMP flood (potential DoS)
    icmp_count = self.stats['protocols'].get('ICMP', 0)
    if icmp_count > (self.stats['total_packets'] * 0.5):
        self.stats['suspicious_activities'].append({
            'type': 'Possible ICMP Flood',
            'icmp_packets': icmp_count,
            'percentage': f"{(icmp_count/self.stats['total_packets'])*100:.2f}%",
            'timestamp': datetime.now().isoformat()
        })

def generate_report(self, output_format='text'):
    """Generate analysis report."""
    print("\n" + "="*60)
    print("NETWORK TRAFFIC ANALYSIS REPORT")
    print("="*60)
    
    print(f"\n[*] Total Packets Analyzed: {self.stats['total_packets']}")
    
    print("\n[*] Protocol Distribution:")
    for protocol, count in self.stats['protocols'].items():
        percentage = (count / self.stats['total_packets']) * 100
        print(f"    {protocol}: {count} ({percentage:.2f}%)")
    
    print("\n[*] Top 5 Source IPs:")
    for ip, count in self.stats['source_ips'].most_common(5):
        print(f"    {ip}: {count} packets")
    
    print("\n[*] Top 5 Destination IPs:")
    for ip, count in self.stats['dest_ips'].most_common(5):
        print(f"    {ip}: {count} packets")
    
    print("\n[*] Top 10 Destination Ports:")
    for port, count in self.stats['dest_ports'].most_common(10):
        print(f"    Port {port}: {count} connections")
    
    if self.stats['suspicious_activities']:
        print("\n[!] SUSPICIOUS ACTIVITIES DETECTED:")
        print("="*60)
        for i, activity in enumerate(self.stats['suspicious_activities'], 1):
            print(f"\n  Alert #{i}:")
            for key, value in activity.items():
                print(f"    {key}: {value}")
    else:
        print("\n[+] No suspicious activities detected")
    
    print("\n" + "="*60)
    
    # Export to JSON if requested
    if output_format == 'json':
        self.export_json()

def export_json(self):
    """Export results to JSON file."""
    output_file = f"network_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    # Convert Counter objects to regular dicts for JSON serialization
    export_data = {
        'total_packets': self.stats['total_packets'],
        'protocols': dict(self.stats['protocols']),
        'top_source_ips': dict(self.stats['source_ips'].most_common(10)),
        'top_dest_ips': dict(self.stats['dest_ips'].most_common(10)),
        'top_dest_ports': dict(self.stats['dest_ports'].most_common(20)),
        'suspicious_activities': self.stats['suspicious_activities'],
        'analysis_timestamp': datetime.now().isoformat()
    }
    
    with open(output_file, 'w') as f:
        json.dump(export_data, f, indent=4)
    
    print(f"\n[+] Results exported to {output_file}")

def run_analysis(self, output_format='text'):
    """Run complete analysis pipeline."""
    if not self.load_packets():
        return
    
    self.analyze_protocols()
    self.detect_anomalies()
    self.generate_report(output_format)


def main():
parser = argparse.ArgumentParser(
description=‘Network Traffic Analyzer - Analyze pcap files for security insights’,
formatter_class=argparse.RawDescriptionHelpFormatter,
epilog=”””
Examples:
python network_analyzer.py capture.pcap
python network_analyzer.py capture.pcap –format json
python network_analyzer.py traffic.pcap -f json

Author: [Your Name]
GitHub: https://github.com/yourusername
“””
)


parser.add_argument('pcap_file', help='Path to the pcap file to analyze')
parser.add_argument('-f', '--format', choices=['text', 'json'], 
                   default='text', help='Output format (default: text)')

args = parser.parse_args()

print("""
╔═══════════════════════════════════════════╗
║   Network Traffic Analyzer v1.0          ║
║   Security Analysis Tool                  ║
╚═══════════════════════════════════════════╝
""")

analyzer = NetworkAnalyzer(args.pcap_file)
analyzer.run_analysis(args.format)


if *name* == “*main*”:
main()