#!/usr/bin/env python3
"""
Packet Analyzer - Feature extraction from network packets
"""

import struct
import socket
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, ARP, Raw

class PacketAnalyzer:
    """Extract features from network packets for ML analysis"""
    
    def __init__(self):
        self.feature_names = [
            'packet_size', 'header_length', 'payload_size', 'tcp_flags',
            'src_port', 'dst_port', 'protocol_type', 'inter_arrival_time',
            'packet_rate', 'flow_duration', 'bytes_per_second'
        ]
        self.previous_packet_time = None
        self.flow_cache = {}
    
    def extract_features(self, packet):
        """
        Extract features from a single packet
        Returns dictionary of features
        """
        try:
            features = {}
            current_time = datetime.now().timestamp()
            
            # Basic packet information
            features['packet_size'] = len(packet)
            features['timestamp'] = current_time
            
            # IP layer analysis
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                features['src_ip'] = ip_layer.src
                features['dst_ip'] = ip_layer.dst
                features['header_length'] = ip_layer.ihl * 4
                features['ttl'] = ip_layer.ttl
                features['protocol_type'] = self._get_protocol_number(packet)
                
                # Payload size
                features['payload_size'] = len(packet[IP].payload) if packet[IP].payload else 0
            
            # Transport layer analysis
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                features['src_port'] = tcp_layer.sport
                features['dst_port'] = tcp_layer.dport
                features['tcp_flags'] = int(tcp_layer.flags)
                features['window_size'] = tcp_layer.window
                features['urgent_pointer'] = tcp_layer.urgptr
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                features['src_port'] = udp_layer.sport
                features['dst_port'] = udp_layer.dport
                features['tcp_flags'] = 0
                features['window_size'] = 0
                features['urgent_pointer'] = 0
                
            else:
                # Non-TCP/UDP packets
                features['src_port'] = 0
                features['dst_port'] = 0
                features['tcp_flags'] = 0
                features['window_size'] = 0
                features['urgent_pointer'] = 0
            
            # Time-based features
            if self.previous_packet_time:
                features['inter_arrival_time'] = current_time - self.previous_packet_time
            else:
                features['inter_arrival_time'] = 0
            
            self.previous_packet_time = current_time
            
            # Flow-based features
            flow_key = self._get_flow_key(features)
            features.update(self._calculate_flow_features(flow_key, features))
            
            # Derived features
            features['bytes_per_second'] = self._calculate_bps(features)
            features['is_fragmented'] = self._is_fragmented(packet)
            features['has_payload'] = 1 if features['payload_size'] > 0 else 0
            
            # Suspicious indicators
            features['suspicious_port'] = self._check_suspicious_port(features.get('dst_port', 0))
            features['private_to_private'] = self._is_private_to_private(features)
            
            return features
            
        except Exception as e:
            # Log error but don't crash
            print(f"Error extracting features: {e}")
            return None
    
    def _get_protocol_number(self, packet):
        """Get protocol number from packet"""
        if packet.haslayer(TCP):
            return 6  # TCP
        elif packet.haslayer(UDP):
            return 17  # UDP
        elif packet.haslayer(ICMP):
            return 1  # ICMP
        else:
            return 0  # Other
    
    def _get_flow_key(self, features):
        """Generate flow key for tracking connections"""
        src_ip = features.get('src_ip', '0.0.0.0')
        dst_ip = features.get('dst_ip', '0.0.0.0')
        src_port = features.get('src_port', 0)
        dst_port = features.get('dst_port', 0)
        protocol = features.get('protocol_type', 0)
        
        # Create bidirectional flow key
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}:{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}:{protocol}"
    
    def _calculate_flow_features(self, flow_key, features):
        """Calculate flow-based features"""
        current_time = features['timestamp']
        packet_size = features['packet_size']
        
        if flow_key not in self.flow_cache:
            self.flow_cache[flow_key] = {
                'start_time': current_time,
                'last_seen': current_time,
                'packet_count': 0,
                'total_bytes': 0
            }
        
        flow = self.flow_cache[flow_key]
        flow['last_seen'] = current_time
        flow['packet_count'] += 1
        flow['total_bytes'] += packet_size
        
        # Calculate features
        flow_duration = current_time - flow['start_time']
        packet_rate = flow['packet_count'] / max(flow_duration, 1)
        
        return {
            'flow_duration': flow_duration,
            'packet_rate': packet_rate,
            'flow_packet_count': flow['packet_count'],
            'flow_total_bytes': flow['total_bytes']
        }
    
    def _calculate_bps(self, features):
        """Calculate bytes per second"""
        duration = features.get('flow_duration', 1)
        total_bytes = features.get('flow_total_bytes', features['packet_size'])
        return total_bytes / max(duration, 1)
    
    def _is_fragmented(self, packet):
        """Check if packet is fragmented"""
        if packet.haslayer(IP):
            flags = packet[IP].flags
            frag_offset = packet[IP].frag
            return 1 if (flags & 1) or frag_offset > 0 else 0
        return 0
    
    def _check_suspicious_port(self, port):
        """Check if port is commonly associated with malware"""
        suspicious_ports = {
            31337, 12345, 54321, 1337, 6667, 6666, 4444, 5555, 9999
        }
        return 1 if port in suspicious_ports else 0
    
    def _is_private_to_private(self, features):
        """Check if communication is between private IPs"""
        src_ip = features.get('src_ip', '')
        dst_ip = features.get('dst_ip', '')
        
        def is_private_ip(ip):
            """Check if IP is in private range"""
            try:
                octets = [int(x) for x in ip.split('.')]
                # 10.0.0.0/8
                if octets[0] == 10:
                    return True
                # 172.16.0.0/12
                if octets[0] == 172 and 16 <= octets[1] <= 31:
                    return True
                # 192.168.0.0/16
                if octets[0] == 192 and octets[1] == 168:
                    return True
            except:
                pass
            return False
        
        return 1 if is_private_ip(src_ip) and is_private_ip(dst_ip) else 0
    
    def get_feature_vector(self, features):
        """Convert features dictionary to numeric vector for ML"""
        vector = []
        
        # Define the order of features for ML
        ml_features = [
            'packet_size', 'header_length', 'payload_size', 'tcp_flags',
            'src_port', 'dst_port', 'protocol_type', 'inter_arrival_time',
            'packet_rate', 'flow_duration', 'bytes_per_second', 'window_size',
            'is_fragmented', 'has_payload', 'suspicious_port', 'private_to_private'
        ]
        
        for feature in ml_features:
            vector.append(features.get(feature, 0))
        
        return vector