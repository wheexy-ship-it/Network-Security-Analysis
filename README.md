# 🌐 Network Security Analysis Tools

A collection of Python-based network security tools for traffic analysis, port scanning, and threat detection. Built as part of my cybersecurity learning journey.

## 📋 Table of Contents

- [Overview](#overview)
- [Tools Included](#tools-included)
- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Examples](#examples)
- [Learning Objectives](#learning-objectives)
- [Disclaimer](#disclaimer)

## 🎯 Overview

This repository contains network security tools developed while learning cybersecurity fundamentals. The tools are designed to analyze network traffic, identify security threats, and perform authorized security assessments.

*Skills Demonstrated:*

- Network protocol analysis (TCP/IP, UDP, ICMP)
- Packet capture analysis with Scapy
- Threat detection and anomaly identification
- Multi-threaded programming
- Security reporting and documentation

## 🛠 Tools Included

### 1. Network Traffic Analyzer (network_analyzer.py)

Advanced packet analysis tool that examines PCAP files to identify:

- Protocol distribution and traffic patterns
- Suspicious network activities
- Potential port scans
- Traffic anomalies and DoS indicators
- High-volume traffic sources

*Key Features:*

- ✅ Protocol breakdown (TCP, UDP, ICMP)
- ✅ Source/Destination IP tracking
- ✅ Port usage analysis
- ✅ Automated threat detection
- ✅ JSON export for further analysis
- ✅ Detailed security reports

### 2. Port Scanner (port_scanner.py)

Multi-threaded port scanning tool for network reconnaissance and security auditing.

*Key Features:*

- ✅ Fast multi-threaded scanning
- ✅ Service detection and banner grabbing
- ✅ Common port identification
- ✅ Custom port ranges and lists
- ✅ Security assessment and recommendations
- ✅ Configurable timeout and thread count

## 📦 Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Setup

1. *Clone the repository:*

bash
git clone https://github.com/yourusername/Network-Security-Analysis.git
cd Network-Security-Analysis


1. *Create a virtual environment (recommended):*

bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


1. *Install dependencies:*

bash
pip install -r requirements.txt


### Requirements

Create a requirements.txt file with:


scapy>=2.5.0


## 🚀 Usage

### Network Traffic Analyzer

*Basic usage:*

bash
python network_analyzer.py capture.pcap


*Export to JSON:*

bash
python network_analyzer.py capture.pcap --format json


*Help:*

bash
python network_analyzer.py --help


### Port Scanner

*Scan common ports:*

bash
python port_scanner.py 192.168.1.1


*Scan specific ports:*

bash
python port_scanner.py example.com -p 80,443,8080


*Scan port range:*

bash
python port_scanner.py 192.168.1.1 -p 1-1000


*Fast scan with custom threads:*

bash
python port_scanner.py 192.168.1.1 -p common -t 200


*Scan all ports (slow):*

bash
python port_scanner.py 192.168.1.1 -p all


## ✨ Features

### Network Traffic Analyzer Features

|Feature                  |Description                                              |
|-------------------------|---------------------------------------------------------|
|*Protocol Analysis*    |Identifies and counts TCP, UDP, ICMP, and other protocols|
|*IP Tracking*          |Tracks source and destination IP addresses               |
|*Port Analysis*        |Monitors port usage patterns                             |
|*Port Scan Detection*  |Identifies potential port scanning attempts              |
|*DoS Detection*        |Detects ICMP floods and traffic anomalies                |
|*High Volume Detection*|Flags IPs generating excessive traffic                   |
|*JSON Export*          |Exports results for integration with other tools         |
|*Detailed Reports*     |Comprehensive security analysis reports                  |

### Port Scanner Features

|Feature                |Description                               |
|-----------------------|------------------------------------------|
|*Multi-threading*    |Fast scanning using concurrent threads    |
|*Service Detection*  |Identifies common services on open ports  |
|*Banner Grabbing*    |Attempts to retrieve service banners      |
|*Custom Port Ranges* |Scan specific ports, ranges, or all ports |
|*Security Assessment*|Provides recommendations based on findings|
|*Configurable*       |Adjustable timeouts and thread counts     |

## 📚 Examples

### Example 1: Analyzing Network Traffic

bash
# Analyze a packet capture file
python network_analyzer.py suspicious_traffic.pcap

# Output includes:
# - Total packet count
# - Protocol distribution
# - Top source/destination IPs
# - Most accessed ports
# - Suspicious activity alerts


*Sample Output:*


============================================================
NETWORK TRAFFIC ANALYSIS REPORT
============================================================

[*] Total Packets Analyzed: 5432

[*] Protocol Distribution:
    TCP: 4231 (77.89%)
    UDP: 987 (18.17%)
    ICMP: 214 (3.94%)

[*] Top 5 Source IPs:
    192.168.1.100: 2341 packets
    10.0.0.50: 876 packets
    ...

[!] SUSPICIOUS ACTIVITIES DETECTED:
============================================================
  Alert #1:
    type: Port Scan
    src: 192.168.1.100
    ports_contacted: 247


### Example 2: Port Scanning

bash
# Scan common ports on a target
python port_scanner.py 192.168.1.1

# Scan specific web ports
python port_scanner.py example.com -p 80,443,8080,8443


*Sample Output:*


[+] Port   80  OPEN    - HTTP            Server: Apache/2.4.41
[+] Port  443  OPEN    - HTTPS           
[+] Port   22  OPEN    - SSH             SSH-2.0-OpenSSH_8.2p1

============================================================
SECURITY ASSESSMENT
============================================================
[!] Potential Security Concerns:
    ⚠  HTTP-Proxy (Port 8080) - Verify if this should be exposed


## 🎓 Learning Objectives

This project demonstrates understanding of:

1. *Network Protocols:*
- TCP/IP stack fundamentals
- Protocol analysis and identification
- Port and service relationships
1. *Security Concepts:*
- Threat detection methodologies
- Network reconnaissance techniques
- Traffic analysis best practices
- Security assessment procedures
1. *Python Programming:*
- Working with networking libraries (Scapy, socket)
- Multi-threaded programming
- Data structures and algorithms
- File I/O and data serialization
1. *Practical Skills:*
- PCAP file analysis
- Automated security scanning
- Report generation
- Security tool development

## 🔒 Security Considerations

### When Using These Tools:

1. *Authorization Required:*
- Only scan networks you own or have explicit permission to test
- Unauthorized scanning may be illegal in your jurisdiction
1. *Ethical Use:*
- These tools are for educational and authorized security testing only
- Never use for malicious purposes or unauthorized access
1. *Best Practices:*
- Always obtain written permission before scanning
- Document your testing activities
- Report findings responsibly
- Respect privacy and data protection laws

## ⚠ Disclaimer


LEGAL DISCLAIMER:

These tools are provided for educational purposes and authorized 
security testing only. Users are responsible for complying with all 
applicable laws and regulations. Unauthorized access to computer 
systems is illegal.

The author assumes no liability for misuse or damage caused by these tools.
Always obtain proper authorization before conducting security assessments.


## 🚧 Future Enhancements

- [ ] Add DNS query analysis
- [ ] Implement HTTP/HTTPS traffic inspection
- [ ] Add machine learning for anomaly detection
- [ ] Create web-based dashboard for visualization
- [ ] Add support for real-time traffic capture
- [ ] Implement additional protocol analyzers (FTP, SMTP, etc.)
- [ ] Add integration with threat intelligence feeds
- [ ] Create automated reporting system

## 📖 Resources

*Learning Materials:*

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

*Related Tools:*

- Wireshark - Network protocol analyzer
- tcpdump - Command-line packet analyzer
- Nmap - Network exploration and security auditing

## 👨‍💻 Author

*[Your Name]*

- GitHub: [@wheezy-ship-it]
- LinkedIn: [Solomon Wisdom Chiagozie](https://www.linkedin.com/in/solomon-wisdom-chiagozie-79731b34a?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=ios_app)
- Email: solomonwisdom944@gmail.com

## 📄 License

This project is licensed under the MIT License - see the <LICENSE> file for details.

## 🙏 Acknowledgments

- Built as part of the Google Cybersecurity Professional Certificate
- Inspired by tools like Wireshark, Nmap, and tcpdump
- Thanks to the cybersecurity community for continuous learning resources

-----

⭐ If you find this project helpful, please consider giving it a star!

*Last Updated:* October 2025