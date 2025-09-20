#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS) - Main Engine
Real-time network monitoring with ML-based threat detection
Author: Your Name
Date: September 2025
"""

import os
import sys
import time
import json
import logging
import argparse
import threading
from datetime import datetime
from pathlib import Path

# Third-party imports
import pandas as pd
import numpy as np
from scapy.all import sniff, get_if_list
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# Local imports
from packet_analyzer import PacketAnalyzer
from ml_detector import MLDetector
from signature_detector import SignatureDetector
from alert_manager import AlertManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ids_main.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetworkIDS:
    """
    Main Network Intrusion Detection System Class
    Coordinates packet capture, analysis, and threat detection
    """
    
    def __init__(self, config_file='config.json'):
        """Initialize the Network IDS with configuration"""
        self.config = self._load_config(config_file)
        self.is_running = False
        self.packet_count = 0
        self.threat_count = 0
        
        # Initialize components
        self.packet_analyzer = PacketAnalyzer()
        self.ml_detector = MLDetector()
        self.signature_detector = SignatureDetector()
        self.alert_manager = AlertManager(self.config)
        
        # Create necessary directories
        self._create_directories()
        
        logger.info("Network IDS initialized successfully")
    
    def _load_config(self, config_file):
        """Load configuration from JSON file"""
        default_config = {
            "interface": "eth0",
            "detection_threshold": 0.8,
            "log_level": "INFO",
            "alert_email": None,
            "max_packets": 0,  # 0 = unlimited
            "capture_filter": "",
            "model_path": "data/models/ids_model.pkl"
        }
        
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                default_config.update(config)
            else:
                logger.warning(f"Config file {config_file} not found, using defaults")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
        
        return default_config
    
    def _create_directories(self):
        """Create necessary directories"""
        dirs = ['logs', 'data/models', 'data/pcaps', 'reports']
        for dir_path in dirs:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    def packet_handler(self, packet):
        """
        Handle each captured packet
        Called by Scapy for every packet
        """
        try:
            self.packet_count += 1
            
            # Analyze packet
            features = self.packet_analyzer.extract_features(packet)
            if not features:
                return
            
            # ML-based detection
            is_anomaly, ml_confidence = self.ml_detector.detect_anomaly(features)
            
            # Signature-based detection
            signature_matches = self.signature_detector.check_signatures(packet, features)
            
            # Generate alerts if threats detected
            if is_anomaly or signature_matches:
                self.threat_count += 1
                self._generate_alert(packet, features, is_anomaly, ml_confidence, signature_matches)
            
            # Log progress
            if self.packet_count % 1000 == 0:
                logger.info(f"Processed {self.packet_count} packets, detected {self.threat_count} threats")
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _generate_alert(self, packet, features, is_anomaly, ml_confidence, signature_matches):
        """Generate security alert"""
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'packet_info': {
                'src_ip': features.get('src_ip', 'unknown'),
                'dst_ip': features.get('dst_ip', 'unknown'),
                'protocol': features.get('protocol', 'unknown'),
                'src_port': features.get('src_port', 0),
                'dst_port': features.get('dst_port', 0)
            },
            'detection_methods': {
                'ml_anomaly': is_anomaly,
                'ml_confidence': ml_confidence,
                'signature_matches': signature_matches
            },
            'severity': self._calculate_severity(is_anomaly, ml_confidence, signature_matches),
            'features': features
        }
        
        # Send alert through alert manager
        self.alert_manager.process_alert(alert_data)
        
        # Log the alert
        severity = alert_data['severity']
        src_ip = alert_data['packet_info']['src_ip']
        dst_ip = alert_data['packet_info']['dst_ip']
        
        logger.warning(f"🚨 THREAT DETECTED [{severity}]: {src_ip} → {dst_ip}")
        
        if signature_matches:
            logger.warning(f"   Signature matches: {signature_matches}")
        if is_anomaly:
            logger.warning(f"   ML anomaly detected (confidence: {ml_confidence:.2f})")
    
    def _calculate_severity(self, is_anomaly, ml_confidence, signature_matches):
        """Calculate threat severity"""
        severity_score = 0
        
        if is_anomaly:
            severity_score += ml_confidence * 50
        
        if signature_matches:
            severity_score += len(signature_matches) * 30
        
        if severity_score >= 80:
            return "CRITICAL"
        elif severity_score >= 60:
            return "HIGH"
        elif severity_score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def start_monitoring(self, interface=None, duration=0):
        """
        Start network monitoring
        Args:
            interface: Network interface to monitor
            duration: Monitoring duration in seconds (0 = infinite)
        """
        if self.is_running:
            logger.warning("IDS is already running")
            return
        
        interface = interface or self.config['interface']
        
        # Validate interface
        available_interfaces = get_if_list()
        if interface not in available_interfaces:
            logger.error(f"Interface {interface} not available. Available: {available_interfaces}")
            return
        
        logger.info(f"Starting Network IDS monitoring on {interface}")
        logger.info(f"Detection threshold: {self.config['detection_threshold']}")
        
        self.is_running = True
        
        try:
            # Start packet capture
            if duration > 0:
                logger.info(f"Monitoring for {duration} seconds...")
                sniff(
                    iface=interface,
                    prn=self.packet_handler,
                    timeout=duration,
                    filter=self.config.get('capture_filter', ''),
                    store=False
                )
            else:
                logger.info("Starting continuous monitoring (Ctrl+C to stop)...")
                sniff(
                    iface=interface,
                    prn=self.packet_handler,
                    filter=self.config.get('capture_filter', ''),
                    store=False
                )
        
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Error during monitoring: {e}")
        
        finally:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        if not self.is_running:
            return
        
        logger.info("Stopping Network IDS...")
        self.is_running = False
        
        # Generate final report
        self._generate_final_report()
    
    def _generate_final_report(self):
        """Generate final monitoring report"""
        report = {
            'monitoring_summary': {
                'total_packets': self.packet_count,
                'threats_detected': self.threat_count,
                'detection_rate': (self.threat_count / max(self.packet_count, 1)) * 100,
                'session_duration': 'N/A'  # Could calculate based on start time
            },
            'alert_summary': self.alert_manager.get_summary(),
            'timestamp': datetime.now().isoformat()
        }
        
        # Save report
        report_file = f"reports/ids_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"📊 MONITORING SUMMARY:")
        logger.info(f"   Total packets processed: {self.packet_count:,}")
        logger.info(f"   Threats detected: {self.threat_count:,}")
        logger.info(f"   Detection rate: {report['monitoring_summary']['detection_rate']:.2f}%")
        logger.info(f"   Report saved: {report_file}")
    
    def train_model(self, training_data_file):
        """Train the ML model on normal traffic data"""
        logger.info(f"Training ML model with data from {training_data_file}")
        
        try:
            # Load training data
            if training_data_file.endswith('.csv'):
                df = pd.read_csv(training_data_file)
            elif training_data_file.endswith('.json'):
                df = pd.read_json(training_data_file)
            else:
                logger.error("Training data must be CSV or JSON format")
                return False
            
            # Train the model
            success = self.ml_detector.train_model(df)
            
            if success:
                logger.info("ML model training completed successfully")
                return True
            else:
                logger.error("ML model training failed")
                return False
        
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return False
    
    def get_status(self):
        """Get current IDS status"""
        return {
            'running': self.is_running,
            'packets_processed': self.packet_count,
            'threats_detected': self.threat_count,
            'configuration': self.config
        }

def main():
    """Main function with CLI interface"""
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    parser.add_argument('--interface', '-i', help='Network interface to monitor')
    parser.add_argument('--duration', '-d', type=int, default=0,
                       help='Monitoring duration in seconds (0 = infinite)')
    parser.add_argument('--config', '-c', default='config.json',
                       help='Configuration file path')
    parser.add_argument('--train', '-t', help='Train model with data file')
    parser.add_argument('--list-interfaces', '-l', action='store_true',
                       help='List available network interfaces')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # List interfaces and exit
    if args.list_interfaces:
        print("Available network interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        return
    
    # Initialize IDS
    ids = NetworkIDS(args.config)
    
    # Train model if requested
    if args.train:
        success = ids.train_model(args.train)
        if not success:
            sys.exit(1)
        return
    
    # Check for root privileges on Unix systems
    if os.name == 'posix' and os.geteuid() != 0:
        print("⚠️  Warning: Root privileges required for packet capture")
        print("   Run with: sudo python ids_main.py")
    
    # Start monitoring
    try:
        ids.start_monitoring(args.interface, args.duration)
    except KeyboardInterrupt:
        print("\nShutting down IDS...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()