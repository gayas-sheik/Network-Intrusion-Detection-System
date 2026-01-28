"""
Real Network Traffic Monitor for NIDS
Monitors actual device traffic including browser tabs, connections, and traffic patterns
"""

import time
import threading
import psutil
import socket
import subprocess
import platform
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from app import app, db, TrafficLog, IntrusionAlert, nids_engine

class RealNetworkMonitor:
    def __init__(self):
        self.running = False
        self.monitor_thread = None
        self.my_ip = self._get_my_ip()
        self.stats = {
            'total_packets': 0,
            'bytes_transferred': 0,
            'packets_per_second': deque(maxlen=60),  # Last 60 seconds
            'bytes_per_second': deque(maxlen=60),
            'connection_count': defaultdict(int),
            'port_access': defaultdict(set),
            'ip_traffic': defaultdict(list),
            'browser_tabs': 0,
            'persistent_connections': defaultdict(int),
            'connection_durations': defaultdict(list),
            'last_reset_time': time.time()
        }
        self.attack_patterns = {
            'tab_spike_threshold': 5,  # More than 5 tabs in 30 seconds
            'persistent_connection_threshold': 300,  # 5 minutes
            'traffic_spike_multiplier': 3.0,  # 3x normal traffic
            'anomaly_std_threshold': 2.0,  # standard deviations
            'connection_threshold': 20,  # connections per minute
            'browser_ports': [80, 443, 8080, 3000, 5000, 8000, 8443, 9000],
            'suspicious_ports': [22, 23, 25, 53, 110, 143, 993, 995, 1433, 3306, 3389, 5432, 6379, 27017]
        }
        self.baseline_traffic = []
        self.browser_processes = set()
        
    def _get_my_ip(self):
        """Get the local IP address"""
        try:
            # Try to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            my_ip = s.getsockname()[0]
            s.close()
            return my_ip
        except:
            return "127.0.0.1"  # Fallback to localhost
    
    def start_monitoring(self):
        """Start real network traffic monitoring"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            print("🔍 Real network monitoring started - monitoring your device traffic")
    
    def stop_monitoring(self):
        """Stop network traffic monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()
        print("⏹️ Real network monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop for real traffic analysis"""
        last_time = time.time()
        baseline_samples = 0
        
        while self.running:
            try:
                current_time = time.time()
                time_diff = current_time - last_time
                
                # Monitor real network connections
                self._monitor_real_connections()
                
                # Monitor browser activity
                self._monitor_browser_activity()
                
                # Analyze traffic patterns every 3 seconds
                if time_diff >= 3.0:
                    self._analyze_real_traffic_patterns()
                    last_time = current_time
                
                # Build baseline for anomaly detection
                if baseline_samples < 100:
                    self._build_baseline()
                    baseline_samples += 1
                
                time.sleep(1) # Monitor every second
                
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(2)
    
    def _monitor_real_connections(self):
        """Monitor real network connections on the device"""
        try:
            # Get active network connections
            connections = psutil.net_connections(kind='inet')
            
            current_time = time.time()
            active_connections = []
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':  # Only count established connections
                    local_address = conn.laddr.ip
                    remote_address = conn.raddr.ip
                    local_port = conn.laddr.port
                    remote_port = conn.raddr.port
                    
                    # Focus on connections involving our IP
                    if local_address == self.my_ip or remote_address == self.my_ip:
                        connection_key = f"{local_address}:{local_port} -> {remote_address}:{remote_port}"
                        
                        # Track connection duration
                        if connection_key not in self.stats['connection_durations']:
                            self.stats['connection_durations'][connection_key] = current_time
                        
                        duration = current_time - self.stats['connection_durations'][connection_key]
                        self.stats['connection_durations'][connection_key] = current_time
                        
                        # Count persistent connections
                        if duration > self.attack_patterns['persistent_connection_threshold']:
                            self.stats['persistent_connections'][local_address] += 1
                        
                        # Update statistics
                        self.stats['total_packets'] += 1
                        self.stats['bytes_transferred'] += conn.status
                        self.stats['packets_per_second'].append(1)
                        self.stats['bytes_per_second'].append(conn.status)
                        self.stats['connection_count'][local_address] += 1
                        self.stats['port_access'][local_address].add(remote_port)
                        
                        # Track IP traffic
                        traffic_data = {
                            'source_ip': local_address,
                            'dest_ip': remote_address,
                            'source_port': local_port,
                            'dest_port': remote_port,
                            'protocol': 'TCP',
                            'size': conn.status,
                            'timestamp': current_time,
                            'type': 'real_connection'
                        }
                        self.stats['ip_traffic'][local_address].append(traffic_data)
                        
                        active_connections.append(connection_key)
            
            # Clean old connection data
            self._cleanup_old_connections(current_time)
            
        except Exception as e:
            print(f"Error monitoring connections: {e}")
    
    def _monitor_browser_activity(self):
        """Monitor browser-specific activity"""
        try:
            # Detect browser processes
            self._detect_browser_processes()
            
            # Count browser tabs (estimated from connections)
            browser_connections = 0
            for conn_key in self.stats['connection_durations']:
                if any(port in self.attack_patterns['browser_ports'] for port in [int(p) for p in conn_key.split(':')[1:3] if p.isdigit()]):
                    browser_connections += 1
            
            # Detect tab spikes
            if browser_connections > self.stats['browser_tabs']:
                tab_spike = browser_connections - self.stats['browser_tabs']
                if tab_spike > self.attack_patterns['tab_spike_threshold']:
                    self._create_alert(
                        'tab_spike',
                        'medium',
                        self.my_ip,
                        'browser',
                        f"Browser tab spike detected: {browser_connections} tabs opened simultaneously"
                    )
            
            self.stats['browser_tabs'] = browser_connections
            
        except Exception as e:
            print(f"Error monitoring browser activity: {e}")
    
    def _detect_browser_processes(self):
        """Detect browser processes running on the system"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                if proc.info and any(browser in proc.info['name'].lower() for browser in ['chrome', 'firefox', 'safari', 'edge', 'opera']):
                    self.browser_processes.add(proc.info['pid'])
        except:
            pass
    
    def _analyze_real_traffic_patterns(self):
        """Analyze real traffic patterns for anomalies"""
        current_time = datetime.utcnow()
        
        # Check for various real-world attack patterns
        self._detect_real_tab_spikes(current_time)
        self._detect_real_persistent_connections(current_time)
        self._detect_real_traffic_anomalies(current_time)
        self._detect_real_connection_anomalies(current_time)
        self._detect_real_suspicious_activities(current_time)
    
    def _detect_real_tab_spikes(self, current_time):
        """Detect real browser tab spikes"""
        if self.stats['browser_tabs'] > self.attack_patterns['tab_spike_threshold']:
            self._create_alert(
                'tab_spike',
                'medium',
                self.my_ip,
                'browser',
                f"Real browser tab spike: {self.stats['browser_tabs']} tabs detected"
            )
    
    def _detect_real_persistent_connections(self, current_time):
        """Detect persistent connections"""
        for source_ip, count in self.stats['persistent_connections'].items():
            if count > 0:
                self._create_alert(
                    'persistent_connection',
                    'low',
                    source_ip,
                    'browser',
                    f"Persistent connections detected: {count} long-lived connections"
                )
            # Reset counter after alert
            self.stats['persistent_connections'][source_ip] = 0
    
    def _detect_real_traffic_anomalies(self, current_time):
        """Detect traffic anomalies using statistical analysis"""
        if len(self.baseline_traffic) >= 30:
            current_pps = self.stats['packets_per_second'][-1] if self.stats['packets_per_second'] else 0
            
            if current_pps > 0:
                mean_pps = sum(self.baseline_traffic) / len(self.baseline_traffic)
                variance = sum((x - mean_pps) ** 2 for x in self.baseline_traffic) / len(self.baseline_traffic)
                std_dev = variance ** 0.5
                
                if std_dev > 0:
                    z_score = abs(current_pps - mean_pps) / std_dev
                    
                    if z_score > self.attack_patterns['anomaly_std_threshold']:
                        self._create_alert(
                            'traffic_anomaly',
                            'medium',
                            self.my_ip,
                            'browser',
                            f"Real traffic anomaly: {z_score:.2f} standard deviations from baseline"
                        )
    
    def _detect_real_connection_anomalies(self, current_time):
        """Detect connection-based anomalies"""
        for source_ip, count in self.stats['connection_count'].items():
            if count > self.attack_patterns['connection_threshold']:
                self._create_alert(
                    'connection_anomaly',
                    'medium',
                    source_ip,
                    'browser',
                    f"High connection rate: {count} connections/minute"
                )
                # Reset counter
                self.stats['connection_count'][source_ip] = 0
    
    def _detect_real_suspicious_activities(self, current_time):
        """Detect suspicious activities in real traffic"""
        # Check for access to sensitive ports
        for source_ip, ports in self.stats['port_access'].items():
            sensitive_ports = ports.intersection(set(self.attack_patterns['suspicious_ports']))
            if sensitive_ports:
                self._create_alert(
                    'suspicious_access',
                    'medium',
                    source_ip,
                    'browser',
                    f"Access to sensitive ports: {list(sensitive_ports)}"
                )
        
        # Check for unusual port patterns
        for source_ip, ports in self.stats['port_access'].items():
            if len(ports) > 15:  # Unusual number of different ports
                self._create_alert(
                    'port_scan',
                    'high',
                    source_ip,
                    'browser',
                    f"Unusual port access: {len(ports)} different ports"
                )
    
    def _build_baseline(self):
        """Build baseline traffic patterns"""
        if len(self.stats['packets_per_second']) > 0:
            self.baseline_traffic.append(self.stats['packets_per_second'][-1])
    
    def _cleanup_old_connections(self, current_time):
        """Clean up old connection data"""
        cutoff_time = current_time - 300  # 5 minutes
        for ip in list(self.stats['connection_durations'].keys()):
            self.stats['connection_durations'][ip] = [
                t for t in [self.stats['connection_durations'][ip]] 
                if t > cutoff_time
            ]
            if not self.stats['connection_durations'][ip]:
                del self.stats['connection_durations'][ip]
        
        # Reset counters periodically
        if current_time - self.stats['last_reset_time'] > 60:  # Reset every minute
            self.stats['connection_count'].clear()
            self.stats['last_reset_time'] = current_time
    
    def _create_alert(self, alert_type, severity, source_ip, target_ip, description):
        """Create intrusion alert for real traffic"""
        try:
            from app import SecurityUtils
            
            # Check if similar alert already exists recently
            recent_alert = IntrusionAlert.query.filter(
                IntrusionAlert.source_ip == source_ip,
                IntrusionAlert.alert_type == alert_type,
                IntrusionAlert.created_at > datetime.utcnow() - timedelta(minutes=2)
            ).first()
            
            if recent_alert:
                return  # Avoid duplicate alerts
            
            # Create alert data
            alert_data = {
                'type': alert_type,
                'severity': severity,
                'source_ip': source_ip,
                'target_ip': target_ip,
                'description': description,
                'timestamp': datetime.utcnow().isoformat(),
                'detection_method': 'real_monitoring'
            }
            
            # Serialize and hash alert data
            alert_json = json.dumps(alert_data, sort_keys=True).encode('utf-8')
            alert_hash = SecurityUtils.hash_data(alert_json)
            
            # Encrypt alert details
            aes_key = SecurityUtils.generate_aes_key()
            encrypted_details = SecurityUtils.encrypt_data(alert_json, aes_key)
            encrypted_key = SecurityUtils.encode_base64(aes_key)
            
            # Create digital signature
            signature = SecurityUtils.sign_data(alert_json, nids_engine.private_key)
            
            # Store alert in database
            alert = IntrusionAlert(
                alert_type=alert_type,
                severity=severity,
                source_ip=source_ip,
                target_ip=target_ip,
                description=description[:255],  # Truncate for database
                encrypted_details=SecurityUtils.encode_base64(encrypted_details),
                digital_signature=signature,
                alert_hash=alert_hash
            )
            
            db.session.add(alert)
            db.session.commit()
            
            print(f"🚨 REAL {alert_type.upper()} Alert: {description}")
            
        except Exception as e:
            print(f"Error creating real alert: {e}")
    
    def _create_traffic_log(self, traffic):
        """Create traffic log entry for real traffic"""
        try:
            from app import SecurityUtils
            
            # Generate AES key for encryption
            aes_key = SecurityUtils.generate_aes_key()
            
            # Prepare packet data
            packet_data = f"{traffic['source_ip']}:{traffic['source_port']} -> {traffic['dest_ip']}:{traffic['dest_port']} {traffic['protocol']} {traffic['size']} bytes".encode('utf-8')
            
            # Encrypt packet data
            encrypted_payload = SecurityUtils.encrypt_data(packet_data, aes_key)
            
            # Calculate hash
            packet_hash = SecurityUtils.hash_data(packet_data)
            
            # Store encrypted key
            encrypted_key = SecurityUtils.encode_base64(aes_key)
            
            # Create traffic log
            log = TrafficLog(
                source_ip=traffic['source_ip'],
                dest_ip=traffic['dest_ip'],
                source_port=traffic['source_port'],
                dest_port=traffic['dest_port'],
                protocol=traffic['protocol'],
                packet_size=traffic['size'],
                encrypted_payload=SecurityUtils.encode_base64(encrypted_payload),
                encryption_key=encrypted_key,
                packet_hash=packet_hash
            )
            
            db.session.add(log)
            db.session.commit()
            
        except Exception as e:
            print(f"Error creating real traffic log: {e}")
    
    def get_statistics(self):
        """Get current real monitoring statistics"""
        return {
            'total_packets': self.stats['total_packets'],
            'bytes_transferred': self.stats['bytes_transferred'],
            'current_pps': self.stats['packets_per_second'][-1] if self.stats['packets_per_second'] else 0,
            'current_bps': self.stats['bytes_per_second'][-1] if self.stats['bytes_per_second'] else 0,
            'active_sources': len(self.stats['ip_traffic']),
            'browser_tabs': self.stats['browser_tabs'],
            'persistent_connections': sum(self.stats['persistent_connections'].values()),
            'baseline_samples': len(self.baseline_traffic),
            'monitoring_type': 'real_device'
        }

# Global real monitor instance
real_network_monitor = RealNetworkMonitor()
