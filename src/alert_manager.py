#!/usr/bin/env python3
"""
Alert Manager for Network IDS
"""

import json
import smtplib
import logging
from datetime import datetime
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

class AlertManager:
    """Manage security alerts and notifications"""
    
    def __init__(self, config):
        self.config = config
        self.alerts = []
        self.alert_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        # Setup logging
        self.logger = logging.getLogger('AlertManager')
    
    def process_alert(self, alert_data):
        """Process and handle a security alert"""
        # Add timestamp and ID
        alert_data['alert_id'] = f"IDS_{int(datetime.now().timestamp())}"
        alert_data['processed_at'] = datetime.now().isoformat()
        
        # Store alert
        self.alerts.append(alert_data)
        
        # Update counters
        severity = alert_data.get('severity', 'LOW')
        self.alert_counts[severity] = self.alert_counts.get(severity, 0) + 1
        
        # Log alert
        self._log_alert(alert_data)
        
        # Send notifications if configured
        self._send_notifications(alert_data)
        
        # Write to file
        self._write_alert_to_file(alert_data)
    
    def _log_alert(self, alert_data):
        """Log the alert"""
        severity = alert_data['severity']
        src_ip = alert_data['packet_info']['src_ip']
        dst_ip = alert_data['packet_info']['dst_ip']
        protocol = alert_data['packet_info']['protocol']
        
        log_message = f"[{severity}] {src_ip} → {dst_ip} ({protocol})"
        
        if severity == 'CRITICAL':
            self.logger.critical(log_message)
        elif severity == 'HIGH':
            self.logger.error(log_message)
        elif severity == 'MEDIUM':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def _send_notifications(self, alert_data):
        """Send alert notifications"""
        severity = alert_data['severity']
        
        # Only send notifications for high severity alerts
        if severity in ['CRITICAL', 'HIGH'] and self.config.get('alert_email'):
            self._send_email_alert(alert_data)
    
    def _send_email_alert(self, alert_data):
        """Send email alert notification"""
        try:
            # Email configuration (you would set these in config)
            smtp_server = self.config.get('smtp_server', 'localhost')
            smtp_port = self.config.get('smtp_port', 587)
            email_user = self.config.get('email_user', '')
            email_password = self.config.get('email_password', '')
            alert_email = self.config.get('alert_email')
            
            if not all([smtp_server, alert_email]):
                return
            
            # Create message
            msg = MimeMultipart()
            msg['From'] = email_user
            msg['To'] = alert_email
            msg['Subject'] = f"[IDS ALERT] {alert_data['severity']} - Security Threat Detected"
            
            # Email body
            body = self._format_alert_email(alert_data)
            msg.attach(MimeText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if email_user and email_password:
                    server.starttls()
                    server.login(email_user, email_password)
                
                server.sendmail(email_user, alert_email, msg.as_string())
            
            self.logger.info(f"Email alert sent for {alert_data['alert_id']}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    def _format_alert_email(self, alert_data):
        """Format alert data for email"""
        template = f"""
NETWORK INTRUSION DETECTION SYSTEM ALERT

Alert ID: {alert_data['alert_id']}
Timestamp: {alert_data['timestamp']}
Severity: {alert_data['severity']}

PACKET INFORMATION:
- Source IP: {alert_data['packet_info']['src_ip']}
- Destination IP: {alert_data['packet_info']['dst_ip']}
- Protocol: {alert_data['packet_info']['protocol']}
- Source Port: {alert_data['packet_info']['src_port']}
- Destination Port: {alert_data['packet_info']['dst_port']}

DETECTION METHODS:
"""
        
        detection = alert_data['detection_methods']
        if detection['ml_anomaly']:
            template += f"- ML Anomaly Detected (confidence: {detection['ml_confidence']:.2f})\n"
        
        if detection['signature_matches']:
            template += "- Signature Matches:\n"
            for match in detection['signature_matches']:
                template += f"  * {match['name']}: {match['description']}\n"
        
        template += f"""
RECOMMENDED ACTION:
- Investigate the source IP address
- Review network logs for similar activity
- Consider blocking the source if confirmed malicious

This is an automated alert from your Network IDS system.
"""
        
        return template
    
    def _write_alert_to_file(self, alert_data):
        """Write alert to JSON file"""
        try:
            filename = f"logs/alerts_{datetime.now().strftime('%Y%m%d')}.json"
            
            # Read existing alerts
            try:
                with open(filename, 'r') as f:
                    alerts = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                alerts = []
            
            # Add new alert
            alerts.append(alert_data)
            
            # Write back to file
            with open(filename, 'w') as f:
                json.dump(alerts, f, indent=2, default=str)
                
        except Exception as e:
            self.logger.error(f"Failed to write alert to file: {e}")
    
    def get_recent_alerts(self, count=10):
        """Get recent alerts"""
        return self.alerts[-count:] if self.alerts else []
    
    def get_alerts_by_severity(self, severity):
        """Get alerts filtered by severity"""
        return [alert for alert in self.alerts if alert.get('severity') == severity]
    
    def get_summary(self):
        """Get alert summary statistics"""
        return {
            'total_alerts': len(self.alerts),
            'by_severity': self.alert_counts.copy(),
            'recent_alert': self.alerts[-1] if self.alerts else None
        }
    
    def export_alerts(self, filename=None):
        """Export all alerts to JSON file"""
        if filename is None:
            filename = f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.alerts, f, indent=2, default=str)
            
            self.logger.info(f"Alerts exported to {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"Failed to export alerts: {e}")
            return None