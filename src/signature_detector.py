#!/usr/bin/env python3
"""
Signature-based Detection for Network IDS
"""

import re
from scapy.all import IP, TCP, UDP, Raw

class SignatureDetector:
    """Signature-based threat detection using pattern matching"""
    
    def __init__(self):
        self.signatures = self._load_signatures()
        self.match_count = 0
    
    def _load_signatures(self):
        """Load detection signatures/rules"""
        signatures = {
            'port_scan': {
                'name': 'Port Scanning Detection',
                'description': 'Detects potential port scanning activity',
                'condition': self._detect_port_scan,
                'severity': 'MEDIUM'
            },
            'syn_flood': {
                'name': 'SYN Flood Attack',
                'description': 'Detects TCP SYN flood attacks',
                'condition': self._detect_syn_flood,
                'severity': 'HIGH'
            },
            'suspicious_payload': {
                'name': 'Suspicious Payload Content',
                'description': 'Detects malicious payload patterns',
                'condition': self._detect_suspicious_payload,
                'severity': 'HIGH'
            },
            'brute_force': {
                'name': 'Brute Force Attack',
                'description': 'Detects brute force login attempts',
                'condition': self._detect_brute_force,
                'severity': 'HIGH'
            },
            'malware_communication': {
                'name': 'Malware Communication',
                'description': 'Detects communication with known malware ports',
                'condition': self._detect_malware_communication,
                'severity': 'CRITICAL'
            },
            'dns_tunneling': {
                'name': 'DNS Tunneling',
                'description': 'Detects potential DNS tunneling activity',
                'condition': self._detect_dns_tunneling,
                'severity': 'MEDIUM'
            },
            'data_exfiltration': {
                'name': 'Data Exfiltration',
                'description': 'Detects large outbound data transfers',
                'condition': self._detect_data_exfiltration,
                'severity': 'HIGH'
            }
        }
        
        return signatures
    
    def check_signatures(self, packet, features):
        """
        Check packet against all signatures
        Returns list of matched signature names
        """
        matches = []
        
        for sig_name, signature in self.signatures.items():
            try:
                if signature['condition'](packet, features):
                    matches.append({
                        'name': signature['name'],
                        'description': signature['description'],
                        'severity': signature['severity'],
                        'signature_id': sig_name
                    })
                    self.match_count += 1
            except Exception as e:
                # Don't let signature errors crash the system
                print(f"Error in signature {sig_name}: {e}")
        
        return matches
    
    def _detect_port_scan(self, packet, features):
        """Detect port scanning patterns"""
        # Check for rapid connections to different ports
        dst_port = features.get('dst_port', 0)
        tcp_flags = features.get('tcp_flags', 0)
        
        # SYN packets to uncommon ports
        if tcp_flags == 2 and dst_port > 1024:  # SYN flag only
            return True
        
        # Connection attempts to well-known vulnerable ports
        vulnerable_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995]
        if dst_port in vulnerable_ports and tcp_flags == 2:
            return True
        
        return False
    
    def _detect_syn_flood(self, packet, features):
        """Detect SYN flood attacks"""
        tcp_flags = features.get('tcp_flags', 0)
        packet_rate = features.get('packet_rate', 0)
        
        # High rate of SYN packets
        if tcp_flags == 2 and packet_rate > 50:  # SYN flag with high rate
            return True
        
        return False
    
    def _detect_suspicious_payload(self, packet, features):
        """Detect suspicious payload content"""
        if not packet.haslayer(Raw):
            return False
        
        payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
        
        # Common attack patterns
        suspicious_patterns = [
            r'/bin/sh',
            r'cmd\.exe',
            r'powershell',
            r'wget\s+http',
            r'curl\s+http',
            r'nc\s+-l',
            r'rm\s+-rf',
            r'union\s+select',
            r'<script>',
            r'javascript:',
            r'eval\(',
            r'base64_decode',
            r'exec\(',
            r'system\(',
            r'passthru\(',
            r'shell_exec\('
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        
        return False
    
    def _detect_brute_force(self, packet, features):
        """Detect brute force attacks"""
        dst_port = features.get('dst_port', 0)
        flow_packet_count = features.get('flow_packet_count', 0)
        
        # Common ports for brute force attacks
        auth_ports = [21, 22, 23, 25, 110, 143, 993, 995, 3389]
        
        if dst_port in auth_ports and flow_packet_count > 10:
            return True
        
        # Check for repeated authentication attempts
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
            auth_keywords = ['user', 'pass', 'login', 'auth', 'username', 'password']
            if any(keyword in payload for keyword in auth_keywords):
                return True
        
        return False
    
    def _detect_malware_communication(self, packet, features):
        """Detect communication with known malware ports"""
        dst_port = features.get('dst_port', 0)
        src_port = features.get('src_port', 0)
        
        # Known malware ports
        malware_ports = [
            1337, 31337, 12345, 54321, 9999, 8080, 6667, 6666,
            4444, 5555, 7777, 8888, 1234, 2222, 3333, 4445,
            5556, 6789, 9876, 1024, 1025, 1026, 1027, 1028
        ]
        
        if dst_port in malware_ports or src_port in malware_ports:
            return True
        
        return False
    
    def _detect_dns_tunneling(self, packet, features):
        """Detect DNS tunneling attempts"""
        dst_port = features.get('dst_port', 0)
        src_port = features.get('src_port', 0)
        payload_size = features.get('payload_size', 0)
        
        # DNS traffic on port 53 with unusually large payloads
        if (dst_port == 53 or src_port == 53) and payload_size > 512:
            return True
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
            # Look for base64-like patterns in DNS queries
            if len(payload) > 100 and any(c in payload for c in '0123456789abcdef'):
                return True
        
        return False
    
    def _detect_data_exfiltration(self, packet, features):
        """Detect potential data exfiltration"""
        bytes_per_second = features.get('bytes_per_second', 0)
        flow_total_bytes = features.get('flow_total_bytes', 0)
        dst_port = features.get('dst_port', 0)
        
        # Large outbound data transfers
        if bytes_per_second > 10000 and flow_total_bytes > 100000:
            return True
        
        # Unusual ports with large data transfers
        if dst_port > 1024 and flow_total_bytes > 50000:
            return True
        
        return False
    
    def add_custom_signature(self, name, description, condition_func, severity='MEDIUM'):
        """Add a custom signature rule"""
        self.signatures[name] = {
            'name': name,
            'description': description,
            'condition': condition_func,
            'severity': severity
        }
    
    def get_signature_stats(self):
        """Get signature matching statistics"""
        return {
            'total_signatures': len(self.signatures),
            'total_matches': self.match_count,
            'signatures': {name: sig['name'] for name, sig in self.signatures.items()}
        }