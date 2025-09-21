#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS) with Machine Learning
Author: Cybersecurity Portfolio Project  
Date: September 2025
Description: Real-time network monitoring and intrusion detection using ML algorithms
"""

import numpy as np
import pandas as pd
import logging
import socket
import struct
import time
import pickle
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import threading
import json
from collections import defaultdict
import sqlite3
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nids.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetworkPacketAnalyzer:
    """Analyzes network packets and extracts features for ML model"""

    def __init__(self):
        self.packet_count = 0
        self.connection_stats = defaultdict(lambda: {
            'packet_count': 0,
            'total_bytes': 0,
            'timestamps': [],
            'flags': []
        })

    def extract_features(self, packet_info, timestamp):
        """Extract ML features from packet information"""
        if not packet_info:
            return None

        connection_key = f"{packet_info['src_ip']}:{packet_info['dst_ip']}"
        stats = self.connection_stats[connection_key]

        # Update connection statistics
        stats['packet_count'] += 1
        stats['total_bytes'] += packet_info['packet_size']
        stats['timestamps'].append(timestamp)

        # Calculate features
        features = {
            'packet_size': packet_info['packet_size'],
            'ttl': packet_info['ttl'],
            'protocol': packet_info['protocol'],
            'packet_count': stats['packet_count'],
            'total_bytes': stats['total_bytes'],
            'avg_packet_size': stats['total_bytes'] / stats['packet_count'],
            'connection_duration': 0,
            'packets_per_second': 0
        }

        # Calculate time-based features
        if len(stats['timestamps']) > 1:
            duration = stats['timestamps'][-1] - stats['timestamps'][0]
            features['connection_duration'] = duration
            if duration > 0:
                features['packets_per_second'] = len(stats['timestamps']) / duration

        return features

class MLDetectionEngine:
    """Machine Learning engine for threat detection"""

    def __init__(self):
        self.normal_traffic_model = IsolationForest(contamination=0.1, random_state=42)
        self.attack_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False

    def generate_training_data(self):
        """Generate synthetic training data for demonstration"""
        logger.info("Generating training data...")

        # Normal traffic patterns
        normal_data = []
        for _ in range(1000):
            normal_data.append({
                'packet_size': np.random.normal(800, 200),
                'ttl': np.random.choice([64, 128, 255]),
                'protocol': np.random.choice([6, 17]),  # TCP, UDP
                'packet_count': np.random.poisson(10),
                'total_bytes': np.random.normal(8000, 2000),
                'avg_packet_size': np.random.normal(800, 100),
                'connection_duration': np.random.exponential(30),
                'packets_per_second': np.random.normal(5, 2),
                'label': 0  # Normal
            })

        # Attack patterns
        attack_data = []
        for _ in range(200):
            attack_type = np.random.choice(['dos', 'port_scan', 'data_exfil'])

            if attack_type == 'dos':
                attack_data.append({
                    'packet_size': np.random.normal(64, 10),
                    'ttl': np.random.choice([64, 128]),
                    'protocol': 6,
                    'packet_count': np.random.poisson(1000),
                    'total_bytes': np.random.normal(64000, 5000),
                    'avg_packet_size': 64,
                    'connection_duration': np.random.exponential(5),
                    'packets_per_second': np.random.normal(200, 50),
                    'label': 1  # Attack
                })
            elif attack_type == 'port_scan':
                attack_data.append({
                    'packet_size': np.random.normal(40, 5),
                    'ttl': 64,
                    'protocol': 6,
                    'packet_count': 1,
                    'total_bytes': 40,
                    'avg_packet_size': 40,
                    'connection_duration': 0.1,
                    'packets_per_second': 10,
                    'label': 1  # Attack
                })
            else:  # data_exfil
                attack_data.append({
                    'packet_size': np.random.normal(1500, 100),
                    'ttl': 128,
                    'protocol': 6,
                    'packet_count': np.random.poisson(500),
                    'total_bytes': np.random.normal(750000, 50000),
                    'avg_packet_size': 1500,
                    'connection_duration': np.random.exponential(60),
                    'packets_per_second': np.random.normal(8, 2),
                    'label': 1  # Attack
                })

        all_data = normal_data + attack_data
        return pd.DataFrame(all_data)

    def train_models(self):
        """Train ML models with generated data"""
        logger.info("Training ML models...")

        # Generate training data
        df = self.generate_training_data()

        # Prepare features
        feature_columns = ['packet_size', 'ttl', 'protocol', 'packet_count', 
                          'total_bytes', 'avg_packet_size', 'connection_duration', 
                          'packets_per_second']

        X = df[feature_columns].fillna(0)
        y = df['label']

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Train models
        self.normal_traffic_model.fit(X_train_scaled[y_train == 0])
        self.attack_classifier.fit(X_train_scaled, y_train)

        # Evaluate
        y_pred = self.attack_classifier.predict(X_test_scaled)
        logger.info("Model Performance:")
        logger.info("Classification Report: " + str(classification_report(y_test, y_pred)))

        self.is_trained = True
        logger.info("ML models training completed!")

class NetworkIntrusionDetectionSystem:
    """Main NIDS class"""

    def __init__(self):
        self.packet_analyzer = NetworkPacketAnalyzer()
        self.ml_engine = MLDetectionEngine()
        self.running = False
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'start_time': None
        }

    def initialize(self):
        """Initialize the NIDS system"""
        logger.info("Initializing NIDS...")
        self.ml_engine.train_models()
        logger.info("NIDS initialization completed!")

    def start(self):
        """Start the NIDS system"""
        logger.info("Starting NIDS system...")
        self.running = True
        self.stats['start_time'] = datetime.now()
        logger.info("NIDS system started successfully!")

def main():
    """Main function"""
    print("Network Intrusion Detection System")
    print("=" * 40)

    # Initialize NIDS
    nids = NetworkIntrusionDetectionSystem()
    nids.initialize()
    nids.start()

if __name__ == "__main__":
    main()
