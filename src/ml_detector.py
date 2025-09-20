#!/usr/bin/env python3
"""
ML-based Anomaly Detector for Network IDS
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib

class MLDetector:
    """Machine Learning based anomaly detection"""
    
    def __init__(self, model_path='data/models/ids_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.feature_names = [
            'packet_size', 'header_length', 'payload_size', 'tcp_flags',
            'src_port', 'dst_port', 'protocol_type', 'inter_arrival_time',
            'packet_rate', 'flow_duration', 'bytes_per_second', 'window_size',
            'is_fragmented', 'has_payload', 'suspicious_port', 'private_to_private'
        ]
        self.is_trained = False
        
        # Load existing model if available
        self._load_model()
        
        # If no model exists, create a default one with synthetic data
        if not self.is_trained:
            self._create_default_model()
    
    def _create_default_model(self):
        """Create a default model with synthetic normal traffic patterns"""
        print("Creating default model with synthetic training data...")
        
        # Generate synthetic normal traffic data
        np.random.seed(42)
        n_samples = 1000
        
        # Normal traffic patterns
        normal_data = []
        for _ in range(n_samples):
            sample = [
                np.random.normal(800, 200),    # packet_size
                np.random.normal(20, 5),       # header_length  
                np.random.normal(500, 150),    # payload_size
                np.random.choice([2, 16, 24]), # tcp_flags (common values)
                np.random.randint(1024, 65535), # src_port
                np.random.choice([80, 443, 22, 21, 25]), # dst_port (common)
                np.random.choice([6, 17]),      # protocol_type (TCP/UDP)
                np.random.exponential(0.01),    # inter_arrival_time
                np.random.normal(100, 30),      # packet_rate
                np.random.exponential(1),       # flow_duration
                np.random.normal(1000, 300),    # bytes_per_second
                np.random.normal(8192, 2000),   # window_size
                0,                              # is_fragmented (mostly not)
                1,                              # has_payload (mostly yes)
                0,                              # suspicious_port (mostly not)
                np.random.choice([0, 1], p=[0.7, 0.3]) # private_to_private
            ]
            normal_data.append(sample)
        
        df = pd.DataFrame(normal_data, columns=self.feature_names)
        self.train_model(df)
    
    def train_model(self, training_data):
        """
        Train the isolation forest model
        Args:
            training_data: DataFrame with normal traffic data
        """
        try:
            print(f"Training ML model with {len(training_data)} samples...")
            
            # Prepare features
            X = training_data[self.feature_names].fillna(0)
            
            # Initialize and fit scaler
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.model = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42,
                n_estimators=100
            )
            self.model.fit(X_scaled)
            
            self.is_trained = True
            
            # Save the trained model
            self._save_model()
            
            print("ML model training completed successfully")
            return True
            
        except Exception as e:
            print(f"Error training model: {e}")
            return False
    
    def detect_anomaly(self, features):
        """
        Detect if given features represent anomalous traffic
        Args:
            features: Dictionary of packet features
        Returns:
            (is_anomaly: bool, confidence: float)
        """
        if not self.is_trained:
            return False, 0.0
        
        try:
            # Convert features to vector
            feature_vector = self._features_to_vector(features)
            
            # Scale features
            feature_scaled = self.scaler.transform([feature_vector])
            
            # Predict anomaly
            anomaly_score = self.model.decision_function(feature_scaled)[0]
            is_anomaly = self.model.predict(feature_scaled)[0] == -1
            
            # Convert score to confidence (0-1 range)
            # Isolation Forest scores are typically between -1 and 1
            confidence = max(0, min(1, (1 - anomaly_score) / 2))
            
            return is_anomaly, confidence
            
        except Exception as e:
            print(f"Error in anomaly detection: {e}")
            return False, 0.0
    
    def _features_to_vector(self, features):
        """Convert features dictionary to vector"""
        vector = []
        for feature_name in self.feature_names:
            value = features.get(feature_name, 0)
            # Handle any non-numeric values
            if isinstance(value, (int, float)):
                vector.append(float(value))
            else:
                vector.append(0.0)
        return vector
    
    def _save_model(self):
        """Save trained model and scaler"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'is_trained': self.is_trained
            }
            
            with open(self.model_path, 'wb') as f:
                pickle.dump(model_data, f)
            
            print(f"Model saved to {self.model_path}")
            
        except Exception as e:
            print(f"Error saving model: {e}")
    
    def _load_model(self):
        """Load pre-trained model"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    model_data = pickle.load(f)
                
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.feature_names = model_data.get('feature_names', self.feature_names)
                self.is_trained = model_data.get('is_trained', True)
                
                print(f"Model loaded from {self.model_path}")
                
        except Exception as e:
            print(f"Could not load model from {self.model_path}: {e}")
    
    def retrain_with_feedback(self, feedback_data):
        """
        Retrain model with user feedback
        Args:
            feedback_data: List of (features, is_normal) tuples
        """
        if not feedback_data:
            return False
        
        try:
            # Convert feedback to DataFrame
            normal_samples = []
            for features, is_normal in feedback_data:
                if is_normal:
                    vector = self._features_to_vector(features)
                    normal_samples.append(vector)
            
            if normal_samples:
                df = pd.DataFrame(normal_samples, columns=self.feature_names)
                return self.train_model(df)
            
            return False
            
        except Exception as e:
            print(f"Error retraining with feedback: {e}")
            return False