#!/usr/bin/env python3
"""
Deep Packet Inspection (DPI) Firewall
Language: Python 3
Platform: Linux (requires root privileges)
Dependencies: scapy, netfilterqueue
"""

import socket
import struct
import threading
import time
import re
import json
from datetime import datetime
from collections import defaultdict
import sys

try:
    from scapy.all import *
    from netfilterqueue import NetfilterQueue
except ImportError:
    print("Required libraries not found. Install with:")
    print("pip install scapy netfilterqueue")
    sys.exit(1)

class DPIFirewall:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_domains = set()
        self.suspicious_patterns = [
            rb'SELECT.*FROM.*WHERE',  # SQL Injection
            rb'<script.*?>.*?</script>',  # XSS
            rb'\.\./',  # Directory traversal
            rb'cmd\.exe',  # Command execution
            rb'powershell',  # PowerShell commands
            rb'wget|curl.*http',  # Download attempts
        ]
        
        # Traffic monitoring
        self.connection_count = defaultdict(int)
        self.packet_count = defaultdict(int)
        self.last_reset = time.time()
        
        # Rate limiting (packets per second)
        self.rate_limit = 100
        
        # Logging
        self.log_file = "firewall.log"
        
        # Protocol analyzers
        self.protocol_handlers = {
            'HTTP': self.analyze_http,
            'HTTPS': self.analyze_https,
            'DNS': self.analyze_dns,
            'FTP': self.analyze_ftp,
            'SMTP': self.analyze_smtp,
        }
        
        print("DPI Firewall initialized")
        self.log_event("SYSTEM", "Firewall started")

    def log_event(self, event_type, message):
        """Log events to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {event_type}: {message}"
        
        print(log_entry)
        with open(self.log_file, 'a') as f:
            f.write(log_entry + "\n")

    def reset_counters(self):
        """Reset rate limiting counters"""
        current_time = time.time()
        if current_time - self.last_reset > 1:  # Reset every second
            self.connection_count.clear()
            self.packet_count.clear()
            self.last_reset = current_time

    def is_rate_limited(self, src_ip):
        """Check if IP is rate limited"""
        self.reset_counters()
        self.packet_count[src_ip] += 1
        return self.packet_count[src_ip] > self.rate_limit

    def analyze_http(self, packet_data):
        """Analyze HTTP traffic"""
        try:
            # Look for HTTP methods
            http_methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD']
            for method in http_methods:
                if method in packet_data:
                    # Extract HTTP request
                    request_start = packet_data.find(method)
                    request_end = packet_data.find(b'\r\n\r\n', request_start)
                    if request_end != -1:
                        http_request = packet_data[request_start:request_end]
                        
                        # Check for suspicious patterns
                        for pattern in self.suspicious_patterns:
                            if re.search(pattern, http_request, re.IGNORECASE):
                                return f"Suspicious HTTP pattern detected: {pattern}"
                        
                        # Check for blocked domains
                        host_match = re.search(rb'Host: ([^\r\n]+)', http_request)
                        if host_match:
                            host = host_match.group(1).decode('utf-8', errors='ignore')
                            if any(domain in host for domain in self.blocked_domains):
                                return f"Blocked domain access: {host}"
                    break
        except Exception as e:
            pass
        return None

    def analyze_https(self, packet_data):
        """Analyze HTTPS/TLS traffic"""
        try:
            # TLS handshake analysis
            if packet_data.startswith(b'\x16\x03'):  # TLS handshake
                # Extract SNI (Server Name Indication)
                sni_start = packet_data.find(b'\x00\x00')
                if sni_start != -1:
                    # Basic SNI extraction (simplified)
                    potential_domain = packet_data[sni_start:sni_start+100]
                    for domain in self.blocked_domains:
                        if domain.encode() in potential_domain:
                            return f"Blocked HTTPS domain: {domain}"
        except Exception as e:
            pass
        return None

    def analyze_dns(self, packet_data):
        """Analyze DNS queries"""
        try:
            # DNS query analysis
            if len(packet_data) > 12:  # Minimum DNS header size
                # Check for suspicious domain queries
                for domain in self.blocked_domains:
                    if domain.encode() in packet_data:
                        return f"Blocked DNS query: {domain}"
        except Exception as e:
            pass
        return None

    def analyze_ftp(self, packet_data):
        """Analyze FTP traffic"""
        try:
            ftp_commands = [b'USER', b'PASS', b'RETR', b'STOR', b'DELE']
            for cmd in ftp_commands:
                if cmd in packet_data:
                    return "FTP activity detected"
        except Exception as e:
            pass
        return None

    def analyze_smtp(self, packet_data):
        """Analyze SMTP traffic"""
        try:
            smtp_commands = [b'HELO', b'EHLO', b'MAIL FROM', b'RCPT TO', b'DATA']
            for cmd in smtp_commands:
                if cmd in packet_data:
                    return "SMTP activity detected"
        except Exception as e:
            pass
        return None

    def deep_packet_inspection(self, packet_data, protocol, src_ip, dst_ip, src_port, dst_port):
        """Perform deep packet inspection"""
        
        # Protocol-specific analysis
        if protocol in self.protocol_handlers:
            result = self.protocol_handlers[protocol](packet_data)
            if result:
                return result
        
        # Generic pattern matching
        for pattern in self.suspicious_patterns:
            if re.search(pattern, packet_data, re.IGNORECASE):
                return f"Suspicious pattern detected: {pattern.decode('utf-8', errors='ignore')}"
        
        # Check for binary executable signatures
        exe_signatures = [
            b'MZ',  # Windows executable
            b'\x7fELF',  # Linux executable
            b'\xfe\xed\xfa',  # macOS executable
        ]
        
        for sig in exe_signatures:
            if packet_data.startswith(sig):
                return "Executable file transfer detected"
        
        return None

    def process_packet(self, packet):
        """Main packet processing function"""
        try:
            pkt = IP(packet.get_payload())
            src_ip = pkt.src
            dst_ip = pkt.dst
            
            # Check if IP is blocked
            if src_ip in self.blocked_ips or dst_ip in self.blocked_ips:
                self.log_event("BLOCKED", f"Blocked IP: {src_ip} -> {dst_ip}")
                packet.drop()
                return
            
            # Rate limiting
            if self.is_rate_limited(src_ip):
                self.log_event("RATE_LIMIT", f"Rate limited: {src_ip}")
                packet.drop()
                return
            
            # Analyze based on protocol
            protocol = None
            src_port = dst_port = 0
            
            if pkt.proto == 6:  # TCP
                tcp_pkt = pkt[TCP]
                src_port = tcp_pkt.sport
                dst_port = tcp_pkt.dport
                
                # Determine protocol based on port
                if dst_port == 80 or src_port == 80:
                    protocol = 'HTTP'
                elif dst_port == 443 or src_port == 443:
                    protocol = 'HTTPS'
                elif dst_port == 21 or src_port == 21:
                    protocol = 'FTP'
                elif dst_port == 25 or src_port == 25:
                    protocol = 'SMTP'
                
                # Get payload data
                if hasattr(tcp_pkt, 'payload'):
                    payload = bytes(tcp_pkt.payload)
                    
                    # Perform deep packet inspection
                    if len(payload) > 0:
                        dpi_result = self.deep_packet_inspection(
                            payload, protocol, src_ip, dst_ip, src_port, dst_port
                        )
                        
                        if dpi_result:
                            self.log_event("DPI_BLOCK", 
                                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} - {dpi_result}")
                            packet.drop()
                            return
            
            elif pkt.proto == 17:  # UDP
                udp_pkt = pkt[UDP]
                src_port = udp_pkt.sport
                dst_port = udp_pkt.dport
                
                if dst_port == 53 or src_port == 53:  # DNS
                    protocol = 'DNS'
                    if hasattr(udp_pkt, 'payload'):
                        payload = bytes(udp_pkt.payload)
                        dpi_result = self.deep_packet_inspection(
                            payload, protocol, src_ip, dst_ip, src_port, dst_port
                        )
                        
                        if dpi_result:
                            self.log_event("DPI_BLOCK", 
                                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} - {dpi_result}")
                            packet.drop()
                            return
            
            # Log allowed traffic (optional - can be disabled for performance)
            # self.log_event("ALLOWED", f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            # Accept packet
            packet.accept()
            
        except Exception as e:
            self.log_event("ERROR", f"Packet processing error: {e}")
            packet.accept()  # Accept on error to avoid breaking connections

    def add_blocked_ip(self, ip):
        """Add IP to blocked list"""
        self.blocked_ips.add(ip)
        self.log_event("CONFIG", f"Added blocked IP: {ip}")

    def add_blocked_domain(self, domain):
        """Add domain to blocked list"""
        self.blocked_domains.add(domain)
        self.log_event("CONFIG", f"Added blocked domain: {domain}")

    def start(self):
        """Start the firewall"""
        print("Starting DPI Firewall...")
        print("Make sure to run: sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")
        print("And: sudo iptables -I INPUT -j NFQUEUE --queue-num 0")
        print("Press Ctrl+C to stop")
        
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, self.process_packet)
        
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            print("\nStopping firewall...")
            self.log_event("SYSTEM", "Firewall stopped")
        finally:
            nfqueue.unbind()

def main():
    """Main function"""
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)
    
    # Create firewall instance
    firewall = DPIFirewall()
    
    # Example configuration
    firewall.add_blocked_ip("192.168.1.100")  # Block specific IP
    firewall.add_blocked_domain("malicious-site.com")  # Block domain
    firewall.add_blocked_domain("ads.google.com")  # Block ads
    
    # Start firewall
    firewall.start()

if __name__ == "__main__":
    main()
