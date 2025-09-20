#!/usr/bin/env python3
"""
Fixed Network IDS Dashboard - All-in-One Python File
No external HTML/CSS files required - Everything embedded
"""

from flask import Flask, render_template_string, jsonify
import json
import threading
import time
from datetime import datetime, timedelta
import numpy as np
import random

app = Flask(__name__)

# Complete HTML template with inline CSS - NO EXTERNAL FILES NEEDED
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ Network IDS Dashboard</title>
    <meta http-equiv="refresh" content="30">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        .header { 
            background: rgba(255, 255, 255, 0.95); 
            border-radius: 10px; 
            padding: 20px; 
            margin-bottom: 20px; 
            text-align: center; 
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); 
        }
        
        .header h1 { color: #2c3e50; margin-bottom: 10px; font-size: 2.5em; }
        
        .status { 
            background: #27ae60; 
            color: white; 
            padding: 8px 20px; 
            border-radius: 25px; 
            font-size: 16px; 
            font-weight: bold;
            display: inline-block;
        }
        
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        
        .stat-card { 
            background: rgba(255, 255, 255, 0.95); 
            border-radius: 10px; 
            padding: 25px; 
            text-align: center; 
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); 
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover { transform: translateY(-5px); }
        
        .stat-number { 
            font-size: 2.5em; 
            font-weight: bold; 
            margin-bottom: 10px; 
            color: #e74c3c; 
        }
        
        .stat-label { 
            font-size: 1.1em; 
            color: #7f8c8d; 
            font-weight: 500; 
        }
        
        .alerts-section { 
            background: rgba(255, 255, 255, 0.95); 
            border-radius: 10px; 
            padding: 25px; 
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); 
            margin-bottom: 20px;
        }
        
        .alerts-header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 20px; 
        }
        
        .alerts-header h3 { 
            color: #2c3e50; 
            font-size: 1.5em; 
        }
        
        .refresh-btn {
            background: #3498db;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s ease;
        }
        
        .refresh-btn:hover { background: #2980b9; }
        
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 10px; 
        }
        
        th, td { 
            padding: 15px 12px; 
            text-align: left; 
            border-bottom: 1px solid #ecf0f1; 
        }
        
        th { 
            background: #34495e; 
            color: white; 
            font-weight: 600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        tr:hover { background-color: #f8f9fa; }
        
        .severity-high { 
            color: #e74c3c; 
            font-weight: bold; 
            background: #fadbd8;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
        }
        
        .severity-medium { 
            color: #f39c12; 
            font-weight: bold; 
            background: #fdeaa7;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
        }
        
        .severity-low { 
            color: #27ae60; 
            font-weight: bold; 
            background: #d5f4e6;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
        }
        
        .footer { 
            text-align: center; 
            color: rgba(255, 255, 255, 0.8); 
            margin-top: 30px; 
            font-size: 14px;
        }
        
        .system-info {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .system-info h4 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        
        .info-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .info-label { font-weight: 600; color: #7f8c8d; }
        .info-value { color: #2c3e50; }
        
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: 1fr; }
            .container { padding: 10px; }
            .header h1 { font-size: 2em; }
            table { font-size: 14px; }
            th, td { padding: 10px 8px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Network Intrusion Detection System</h1>
            <span class="status">● ACTIVE MONITORING</span>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{{ stats.packets_processed }}</div>
                <div class="stat-label">Packets Processed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.threats_detected }}</div>
                <div class="stat-label">Threats Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.alerts_generated }}</div>
                <div class="stat-label">Alerts Generated</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.uptime_hours }}</div>
                <div class="stat-label">Hours Online</div>
            </div>
        </div>
        
        <div class="system-info">
            <h4>📊 System Information</h4>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">Detection Engine:</span>
                    <span class="info-value">Active</span>
                </div>
                <div class="info-item">
                    <span class="info-label">ML Model:</span>
                    <span class="info-value">Isolation Forest v2.1</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Monitoring Interface:</span>
                    <span class="info-value">eth0</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Update Rate:</span>
                    <span class="info-value">30 seconds</span>
                </div>
            </div>
        </div>
        
        <div class="alerts-section">
            <div class="alerts-header">
                <h3>🚨 Recent Security Alerts</h3>
                <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Severity</th>
                        <th>Source IP</th>
                        <th>Threat Type</th>
                        <th>Description</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for alert in recent_alerts %}
                    <tr>
                        <td>{{ alert.timestamp }}</td>
                        <td><span class="severity-{{ alert.severity.lower() }}">{{ alert.severity }}</span></td>
                        <td><strong>{{ alert.source_ip }}</strong></td>
                        <td>{{ alert.threat_type }}</td>
                        <td>{{ alert.description }}</td>
                        <td>
                            {% if alert.severity == 'HIGH' %}
                                <span style="color: #e74c3c;">🔒 Blocked</span>
                            {% else %}
                                <span style="color: #f39c12;">⚠️ Monitoring</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>🔒 Network IDS Dashboard | Educational Purpose Only | Auto-refresh every 30 seconds</p>
            <p>Current Time: {{ current_time }} | System Uptime: {{ stats.uptime_hours }} hours</p>
        </div>
    </div>
</body>
</html>
"""

class NetworkIDSSimulator:
    """Simulated Network IDS for demonstration"""
    
    def __init__(self):
        self.stats = {
            'packets_processed': 15430,
            'threats_detected': 7,
            'alerts_generated': 12,
            'start_time': datetime.now() - timedelta(hours=2, minutes=30)
        }
        
        # Generate realistic sample alerts
        self.recent_alerts = self._generate_sample_alerts()
        
        # Start background simulation
        self._start_monitoring_simulation()
    
    def _generate_sample_alerts(self):
        """Generate realistic sample alerts"""
        threat_types = [
            'Port Scan', 'Brute Force SSH', 'DDoS Attack', 'Malware C2', 
            'Data Exfiltration', 'SQL Injection', 'Suspicious File Transfer'
        ]
        
        severities = ['HIGH', 'MEDIUM', 'LOW']
        severity_weights = [0.2, 0.5, 0.3]  # More medium/low alerts
        
        descriptions = {
            'Port Scan': 'Multiple port connection attempts detected',
            'Brute Force SSH': 'Repeated failed SSH login attempts',
            'DDoS Attack': 'High volume traffic from multiple sources',
            'Malware C2': 'Communication with known C2 server',
            'Data Exfiltration': 'Large data transfer to external IP',
            'SQL Injection': 'Malicious SQL query detected',
            'Suspicious File Transfer': 'Unusual file upload activity'
        }
        
        sample_alerts = []
        for i in range(15):
            threat_type = random.choice(threat_types)
            severity = np.random.choice(severities, p=severity_weights)
            
            alert = {
                'timestamp': (datetime.now() - timedelta(minutes=random.randint(1, 180))).strftime('%H:%M:%S'),
                'severity': severity,
                'source_ip': f"192.168.{random.randint(1,10)}.{random.randint(1, 254)}",
                'threat_type': threat_type,
                'description': descriptions.get(threat_type, 'Security threat detected')
            }
            sample_alerts.append(alert)
        
        # Sort by timestamp (most recent first)
        return sorted(sample_alerts, key=lambda x: x['timestamp'], reverse=True)
    
    def _start_monitoring_simulation(self):
        """Start background simulation of IDS activity"""
        def update_stats():
            while True:
                # Simulate realistic processing activity
                self.stats['packets_processed'] += random.randint(50, 200)
                
                # Occasionally detect new threats
                if random.random() < 0.2:  # 20% chance every 15 seconds
                    self.stats['threats_detected'] += 1
                    self.stats['alerts_generated'] += 1
                    
                    # Add new alert to the beginning of the list
                    threat_types = ['Port Scan', 'Suspicious Login', 'Malware Activity']
                    severities = ['HIGH', 'MEDIUM', 'LOW']
                    
                    new_alert = {
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'severity': random.choice(severities),
                        'source_ip': f"192.168.{random.randint(1,10)}.{random.randint(1, 254)}",
                        'threat_type': random.choice(threat_types),
                        'description': 'Real-time threat detected by ML engine'
                    }
                    
                    # Keep only last 15 alerts
                    self.recent_alerts.insert(0, new_alert)
                    self.recent_alerts = self.recent_alerts[:15]
                
                time.sleep(15)  # Update every 15 seconds
        
        thread = threading.Thread(target=update_stats, daemon=True)
        thread.start()
    
    def get_dashboard_data(self):
        """Get current dashboard data"""
        uptime = datetime.now() - self.stats['start_time']
        uptime_hours = round(uptime.total_seconds() / 3600, 1)
        
        return {
            'stats': {
                'packets_processed': f"{self.stats['packets_processed']:,}",
                'threats_detected': self.stats['threats_detected'],
                'alerts_generated': self.stats['alerts_generated'],
                'uptime_hours': uptime_hours
            },
            'recent_alerts': self.recent_alerts,
            'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

# Initialize IDS Simulator
ids_simulator = NetworkIDSSimulator()

@app.route('/')
def dashboard():
    """Main dashboard route - NO EXTERNAL FILES NEEDED!"""
    data = ids_simulator.get_dashboard_data()
    return render_template_string(DASHBOARD_TEMPLATE, **data)

@app.route('/api/stats')
def api_stats():
    """API endpoint for real-time stats"""
    return jsonify(ids_simulator.get_dashboard_data())

@app.route('/api/refresh')
def api_refresh():
    """Force refresh data"""
    # Add a new simulated alert
    new_alert = {
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'severity': random.choice(['HIGH', 'MEDIUM', 'LOW']),
        'source_ip': f"10.0.{random.randint(1,5)}.{random.randint(1, 254)}",
        'threat_type': random.choice(['Port Scan', 'Brute Force', 'Malware']),
        'description': 'Manual refresh - new threat detected'
    }
    
    ids_simulator.recent_alerts.insert(0, new_alert)
    ids_simulator.recent_alerts = ids_simulator.recent_alerts[:15]
    ids_simulator.stats['alerts_generated'] += 1
    
    return jsonify({'status': 'refreshed', 'new_alerts': 1})

if __name__ == '__main__':
    print("🚀 Starting Network IDS Dashboard...")
    print("="*50)
    print("📊 Dashboard URL: http://localhost:5000")
    print("🔄 Auto-refresh: Every 30 seconds") 
    print("🛡️ Status: Monitoring Active")
    print("⚠️  Note: This is a simulation for educational purposes")
    print("="*50)
    
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n✅ IDS Dashboard stopped successfully")
    except Exception as e:
        print(f"\n❌ Error starting dashboard: {e}")