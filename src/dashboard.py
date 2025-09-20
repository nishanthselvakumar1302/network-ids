#!/usr/bin/env python3
"""
Web Dashboard for Network IDS
"""

from flask import Flask, render_template, jsonify, request
import json
import os
from datetime import datetime, timedelta

app = Flask(__name__)

class IDSDashboard:
    """Dashboard for visualizing IDS data"""
    
    def __init__(self):
        self.alerts = []
        self.stats = {
            'total_packets': 0,
            'total_threats': 0,
            'uptime': datetime.now()
        }
    
    def load_recent_alerts(self, days=7):
        """Load recent alerts from files"""
        alerts = []
        
        for i in range(days):
            date = datetime.now() - timedelta(days=i)
            filename = f"logs/alerts_{date.strftime('%Y%m%d')}.json"
            
            if os.path.exists(filename):
                try:
                    with open(filename, 'r') as f:
                        daily_alerts = json.load(f)
                        alerts.extend(daily_alerts)
                except:
                    pass
        
        return sorted(alerts, key=lambda x: x.get('timestamp', ''), reverse=True)
    
    def get_dashboard_data(self):
        """Get data for dashboard"""
        alerts = self.load_recent_alerts()
        
        # Calculate statistics
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for alert in alerts:
            severity = alert.get('severity', 'LOW')
            severity_counts[severity] += 1
        
        # Top source IPs
        ip_counts = {}
        for alert in alerts:
            src_ip = alert.get('packet_info', {}).get('src_ip', 'unknown')
            ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
        
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Timeline data (last 24 hours)
        timeline_data = []
        for hour in range(24):
            hour_start = datetime.now() - timedelta(hours=hour)
            hour_alerts = [a for a in alerts if 
                          datetime.fromisoformat(a.get('timestamp', '').replace('Z', '+00:00')).hour == hour_start.hour]
            timeline_data.append({
                'hour': hour_start.strftime('%H:00'),
                'count': len(hour_alerts)
            })
        
        return {
            'total_alerts': len(alerts),
            'severity_counts': severity_counts,
            'top_source_ips': top_ips,
            'recent_alerts': alerts[:20],
            'timeline_data': list(reversed(timeline_data))
        }

dashboard = IDSDashboard()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/dashboard-data')
def get_dashboard_data():
    """API endpoint for dashboard data"""
    return jsonify(dashboard.get_dashboard_data())

@app.route('/api/alerts')
def get_alerts():
    """API endpoint for alerts"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    severity = request.args.get('severity', None)
    
    alerts = dashboard.load_recent_alerts()
    
    # Filter by severity if specified
    if severity:
        alerts = [a for a in alerts if a.get('severity') == severity]
    
    # Pagination
    start = (page - 1) * per_page
    end = start + per_page
    
    return jsonify({
        'alerts': alerts[start:end],
        'total': len(alerts),
        'page': page,
        'per_page': per_page
    })

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    print("🌐 Starting IDS Dashboard...")
    print("📊 Dashboard will be available at: http://localhost:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)