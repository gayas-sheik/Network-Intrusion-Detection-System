"""
Simple Browser Activity Monitor - Works with Flask app
Detects browser tab opening and generates alerts
"""

import time
import threading
import psutil
import socket
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque

class SimpleBrowserMonitor:
    def __init__(self):
        self.running = False
        self.monitor_thread = None
        self.my_ip = self._get_my_ip()
        
        # Tracking variables
        self.current_connections = set()
        self.tab_count = 0
        self.last_tab_count = 0
        self.connection_start_times = {}
        self.traffic_stats = {
            'packets_per_second': deque(maxlen=60),
            'bytes_per_second': deque(maxlen=60),
            'connection_count': deque(maxlen=60)
        }
        
        # Detection thresholds
        self.thresholds = {
            'tab_spike': 3,  # 3 new tabs in 30 seconds
            'traffic_spike': 2.5,  # 2.5x normal traffic
            'persistent_connection': 180,  # 3 minutes
            'flood_detection': 15  # 15 connections in 10 seconds
        }
        
        self.baseline_traffic = []
        self.last_alert_time = {}
        
    def _get_my_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            my_ip = s.getsockname()[0]
            s.close()
            return my_ip
        except:
            return "127.0.0.1"
    
    def start_monitoring(self):
        """Start browser monitoring"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            print("🔍 Simple browser monitoring started - detecting actual browser activity")
    
    def stop_monitoring(self):
        """Stop browser monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()
        print("⏹️ Simple browser monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        last_check = time.time()
        connection_count_window = deque(maxlen=10)  # Last 10 seconds
        
        while self.running:
            try:
                current_time = time.time()
                
                # Get current browser connections
                connections = self._get_browser_connections()
                
                # Calculate new connections
                new_connections = connections - self.current_connections
                closed_connections = self.current_connections - connections
                
                # Update connection tracking
                self.current_connections = connections
                
                # Track new connections (tab opening)
                if new_connections:
                    for conn in new_connections:
                        self.connection_start_times[conn] = current_time
                        print(f"🔗 New browser connection: {conn}")
                
                # Remove closed connections
                if closed_connections:
                    for conn in closed_connections:
                        if conn in self.connection_start_times:
                            duration = current_time - self.connection_start_times[conn]
                            if duration > self.thresholds['persistent_connection']:
                                print(f"⏱️ Persistent connection closed: {conn} ({duration:.1f}s)")
                                self._create_alert(
                                    'persistent_connection',
                                    'low',
                                    self.my_ip,
                                    'browser',
                                    f"Persistent connection closed after {duration:.1f} seconds"
                                )
                            del self.connection_start_times[conn]
                
                # Update tab count
                self.tab_count = len(connections)
                
                # Detect tab spike
                if self.tab_count - self.last_tab_count >= self.thresholds['tab_spike']:
                    print(f"🚀 Tab spike detected: {self.tab_count - self.last_tab_count} new tabs")
                    self._create_alert(
                        'tab_spike',
                        'medium',
                        self.my_ip,
                        'browser',
                        f"Browser tab spike detected: {self.tab_count - self.last_tab_count} new tabs opened"
                    )
                
                # Update traffic statistics
                self._update_traffic_stats(len(new_connections), len(closed_connections))
                
                # Check for flood attack
                connection_count_window.append(len(new_connections))
                if len(connection_count_window) >= 10 and sum(connection_count_window) >= self.thresholds['flood_detection']:
                    print(f"🌊 Flood attack detected: {sum(connection_count_window)} connections in 10 seconds")
                    self._create_alert(
                        'flood_attack',
                        'high',
                        self.my_ip,
                        'browser',
                        f"Flood attack detected: {sum(connection_count_window)} connections in 10 seconds"
                    )
                    connection_count_window.clear()
                
                # Detect traffic spikes
                self._detect_traffic_spike()
                
                self.last_tab_count = self.tab_count
                self.last_check = current_time
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                print(f"Error in browser monitoring: {e}")
                time.sleep(5)
    
    def _get_browser_connections(self):
        """Get current browser connections"""
        connections = set()
        
        try:
            # Get all network connections
            net_connections = psutil.net_connections(kind='inet')
            
            for conn in net_connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Check if it's a browser connection (common browser ports)
                    remote_port = conn.raddr.port
                    local_ip = conn.laddr.ip
                    
                    # Browser ports and common web ports
                    browser_ports = {80, 443, 8080, 3000, 5000, 8000, 8443, 9000, 3001, 4000, 6000, 7000, 8888, 9001}
                    
                    if (local_ip == self.my_ip and remote_port in browser_ports):
                        connection_key = f"{local_ip}:{conn.laddr.port}->{conn.raddr.ip}:{remote_port}"
                        connections.add(connection_key)
        
        except Exception as e:
            print(f"Error getting connections: {e}")
        
        return connections
    
    def _update_traffic_stats(self, new_connections, closed_connections):
        """Update traffic statistics"""
        current_time = time.time()
        
        # Update packet statistics
        total_activity = new_connections + closed_connections
        self.traffic_stats['packets_per_second'].append(total_activity)
        self.traffic_stats['bytes_per_second'].append(total_activity * 1024)  # Estimate
        self.traffic_stats['connection_count'].append(self.tab_count)
        
        # Build baseline
        if len(self.baseline_traffic) < 100:
            self.baseline_traffic.append(total_activity)
    
    def _detect_traffic_spike(self):
        """Detect traffic spikes using statistical analysis"""
        if len(self.baseline_traffic) >= 30 and len(self.traffic_stats['packets_per_second']) > 0:
            current_traffic = self.traffic_stats['packets_per_second'][-1]
            
            if current_traffic > 0:
                mean_traffic = sum(self.baseline_traffic) / len(self.baseline_traffic)
                
                if mean_traffic > 0:
                    spike_ratio = current_traffic / mean_traffic
                    
                    if spike_ratio >= self.thresholds['traffic_spike']:
                        print(f"📈 Traffic spike detected: {spike_ratio:.1f}x normal traffic")
                        self._create_alert(
                            'traffic_spike',
                            'high',
                            self.my_ip,
                            'browser',
                            f"Traffic spike detected: {spike_ratio:.1f}x normal traffic"
                        )
    
    def _create_alert(self, alert_type, severity, source_ip, target_ip, description):
        """Create intrusion alert"""
        try:
            # Import here to avoid circular import
            from app import app, db, IntrusionAlert
            from app import SecurityUtils
            
            # Prevent duplicate alerts (same type within 2 minutes)
            current_time = datetime.utcnow()
            alert_key = f"{alert_type}_{source_ip}"
            
            if alert_key in self.last_alert_time:
                if (current_time - self.last_alert_time[alert_key]).seconds < 120:
                    return  # Skip duplicate alert
            
            self.last_alert_time[alert_key] = current_time
            
            # Create alert data
            alert_data = {
                'type': alert_type,
                'severity': severity,
                'source_ip': source_ip,
                'target_ip': target_ip,
                'description': description,
                'timestamp': current_time.isoformat(),
                'detection_method': 'simple_browser_monitor',
                'tab_count': self.tab_count
            }
            
            # Serialize and hash
            alert_json = json.dumps(alert_data, sort_keys=True).encode('utf-8')
            alert_hash = SecurityUtils.hash_data(alert_json)
            
            # Encrypt alert details
            aes_key = SecurityUtils.generate_aes_key()
            encrypted_details = SecurityUtils.encrypt_data(alert_json, aes_key)
            encrypted_key = SecurityUtils.encode_base64(aes_key)
            
            # Create digital signature
            from app import nids_engine
            signature = SecurityUtils.sign_data(alert_json, nids_engine.private_key)
            
            # Store alert in database
            alert = IntrusionAlert(
                alert_type=alert_type,
                severity=severity,
                source_ip=source_ip,
                target_ip=target_ip,
                description=description[:255],
                encrypted_details=SecurityUtils.encode_base64(encrypted_details),
                digital_signature=signature,
                alert_hash=alert_hash
            )
            
            with app.app_context():
                db.session.add(alert)
                db.session.commit()
            
            print(f"🚨 BROWSER {alert_type.upper()} Alert: {description}")
            
        except Exception as e:
            print(f"Error creating browser alert: {e}")
    
    def get_statistics(self):
        """Get current monitoring statistics"""
        return {
            'total_packets': sum(self.traffic_stats['packets_per_second']),
            'bytes_transferred': sum(self.traffic_stats['bytes_per_second']),
            'current_pps': self.traffic_stats['packets_per_second'][-1] if self.traffic_stats['packets_per_second'] else 0,
            'current_bps': self.traffic_stats['bytes_per_second'][-1] if self.traffic_stats['bytes_per_second'] else 0,
            'active_sources': 1,  # Your device
            'browser_tabs': self.tab_count,
            'persistent_connections': len([k for k, v in self.connection_start_times.items() if time.time() - v > self.thresholds['persistent_connection']]),
            'baseline_samples': len(self.baseline_traffic),
            'monitoring_type': 'simple_browser',
            'total_connections': len(self.current_connections)
        }

# Global simple browser monitor instance
simple_browser_monitor = SimpleBrowserMonitor()
