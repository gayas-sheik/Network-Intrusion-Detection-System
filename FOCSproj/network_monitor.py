"""
Real Network Traffic Monitor for NIDS
Simulates and monitors network traffic with comprehensive attack detection
"""

import time
import threading
import random
import socket
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
from app import app, db, TrafficLog, IntrusionAlert, nids_engine

class NetworkMonitor:
    def __init__(self):
        self.running = False
        self.monitor_thread = None
        self.stats = {
            'total_packets': 0,
            'bytes_transferred': 0,
            'packets_per_second': deque(maxlen=60),  # Last 60 seconds
            'bytes_per_second': deque(maxlen=60),
            'connection_count': defaultdict(int),
            'port_access': defaultdict(set),
            'ip_traffic': defaultdict(list)
        }
        self.attack_patterns = {
            'port_scan_threshold': 20,  # ports accessed in 60 seconds
            'flood_pps_threshold': 100,  # packets per second
            'flood_bandwidth_threshold': 1048576,  # 1MB per second
            'anomaly_std_threshold': 2.5,  # standard deviations
            'connection_threshold': 50,  # connections per minute
            'suspicious_ports': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379]
        }
        
    def start_monitoring(self):
        """Start network traffic monitoring"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            print("🔍 Network monitoring started with comprehensive attack detection")
    
    def stop_monitoring(self):
        """Stop network traffic monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()
        print("⏹️ Network monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop with real-time analysis"""
        last_time = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                time_diff = current_time - last_time
                
                # Generate realistic network traffic
                self._generate_realistic_traffic()
                
                # Perform real-time analysis every 2 seconds
                if time_diff >= 2.0:
                    self._analyze_traffic_patterns()
                    last_time = current_time
                
                time.sleep(0.5)  # High-frequency monitoring
                
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(2)
    
    def _generate_realistic_traffic(self):
        """Generate realistic network traffic with various patterns"""
        with app.app_context():
            # Base traffic patterns
            traffic_patterns = [
                # Normal web traffic
                {'source_ip': '192.168.1.10', 'dest_ip': '192.168.1.1', 'source_port': 45000, 'dest_port': 80, 'protocol': 'TCP', 'size': 1024, 'type': 'normal'},
                {'source_ip': '192.168.1.15', 'dest_ip': '8.8.8.8', 'source_port': 53000, 'dest_port': 53, 'protocol': 'UDP', 'size': 512, 'type': 'normal'},
                {'source_ip': '10.0.0.5', 'dest_ip': '192.168.1.10', 'source_port': 80, 'dest_port': 8080, 'protocol': 'TCP', 'size': 2048, 'type': 'normal'},
                
                # Database traffic
                {'source_ip': '192.168.1.20', 'dest_ip': '192.168.1.100', 'source_port': 33000, 'dest_port': 3306, 'protocol': 'TCP', 'size': 4096, 'type': 'database'},
                {'source_ip': '192.168.1.21', 'dest_ip': '192.168.1.100', 'source_port': 54000, 'dest_port': 5432, 'protocol': 'TCP', 'size': 2048, 'type': 'database'},
                
                # Email traffic
                {'source_ip': '192.168.1.30', 'dest_ip': '192.168.1.1', 'source_port': 45000, 'dest_port': 25, 'protocol': 'TCP', 'size': 1536, 'type': 'email'},
                {'source_ip': '192.168.1.31', 'dest_ip': '192.168.1.1', 'source_port': 46000, 'dest_port': 587, 'protocol': 'TCP', 'size': 1024, 'type': 'email'},
            ]
            
            # Occasionally generate attack traffic (15% chance)
            if random.random() < 0.15:
                traffic = self._generate_attack_traffic()
            else:
                traffic = random.choice(traffic_patterns)
            
            # Create traffic log
            self._create_traffic_log(traffic)
            
            # Update statistics
            self._update_statistics(traffic)
            
            # Analyze with NIDS engine
            nids_engine.analyze_packet(traffic)
    
    def _generate_attack_traffic(self):
        """Generate various types of attack traffic"""
        attack_types = [
            # Port Scan Attack
            self._generate_port_scan_attack(),
            
            # Flooding Attack
            self._generate_flooding_attack(),
            
            # Traffic Spike Anomaly
            self._generate_traffic_spike(),
            
            # Suspicious Port Access
            self._generate_suspicious_port_access(),
            
            # Brute Force Attack
            self._generate_brute_force_attack(),
            
            # Data Exfiltration
            self._generate_data_exfiltration(),
        ]
        
        return random.choice(attack_types)
    
    def _generate_port_scan_attack(self):
        """Generate port scanning attack traffic"""
        scanner_ip = f"192.168.1.{random.randint(200, 250)}"
        target_ip = "192.168.1.100"
        
        # Scan multiple ports quickly
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432]
        port = random.choice(ports)
        
        return {
            'source_ip': scanner_ip,
            'dest_ip': target_ip,
            'source_port': random.randint(1000, 65000),
            'dest_port': port,
            'protocol': 'TCP',
            'size': 64,
            'type': 'port_scan'
        }
    
    def _generate_flooding_attack(self):
        """Generate flooding attack traffic"""
        attacker_ip = f"10.0.0.{random.randint(100, 200)}"
        target_ip = "192.168.1.100"
        
        # High volume small packets
        return {
            'source_ip': attacker_ip,
            'dest_ip': target_ip,
            'source_port': random.randint(1000, 65000),
            'dest_port': 80,
            'protocol': 'TCP',
            'size': random.randint(64, 256),
            'type': 'flooding'
        }
    
    def _generate_traffic_spike(self):
        """Generate traffic spike anomaly"""
        source_ip = f"172.16.0.{random.randint(10, 50)}"
        target_ip = "192.168.1.100"
        
        # Unusually large packet
        return {
            'source_ip': source_ip,
            'dest_ip': target_ip,
            'source_port': random.randint(1000, 65000),
            'dest_port': random.choice([80, 443, 8080]),
            'protocol': 'TCP',
            'size': random.randint(8192, 16384),  # Large packets
            'type': 'traffic_spike'
        }
    
    def _generate_suspicious_port_access(self):
        """Generate suspicious port access"""
        source_ip = f"192.168.1.{random.randint(150, 199)}"
        target_ip = "192.168.1.100"
        
        # Access to sensitive ports
        suspicious_ports = [22, 1433, 3306, 3389, 5432, 6379, 27017]
        
        return {
            'source_ip': source_ip,
            'dest_ip': target_ip,
            'source_port': random.randint(1000, 65000),
            'dest_port': random.choice(suspicious_ports),
            'protocol': 'TCP',
            'size': 128,
            'type': 'suspicious_access'
        }
    
    def _generate_brute_force_attack(self):
        """Generate brute force attack traffic"""
        attacker_ip = f"10.0.0.{random.randint(50, 100)}"
        target_ip = "192.168.1.100"
        
        return {
            'source_ip': attacker_ip,
            'dest_ip': target_ip,
            'source_port': random.randint(1000, 65000),
            'dest_port': 22,  # SSH brute force
            'protocol': 'TCP',
            'size': 96,
            'type': 'brute_force'
        }
    
    def _generate_data_exfiltration(self):
        """Generate data exfiltration traffic"""
        insider_ip = "192.168.1.50"  # Insider threat
        external_ip = f"203.0.113.{random.randint(1, 255)}"
        
        return {
            'source_ip': insider_ip,
            'dest_ip': external_ip,
            'source_port': random.randint(1000, 65000),
            'dest_port': random.choice([443, 9999, 8080]),
            'protocol': 'TCP',
            'size': random.randint(4096, 8192),  # Large outbound transfers
            'type': 'data_exfiltration'
        }
    
    def _analyze_traffic_patterns(self):
        """Real-time traffic pattern analysis"""
        current_time = datetime.utcnow()
        
        # Check for various attack patterns
        self._detect_port_scans(current_time)
        self._detect_flooding(current_time)
        self._detect_traffic_anomalies(current_time)
        self._detect_connection_anomalies(current_time)
        self._detect_suspicious_activities(current_time)
    
    def _detect_port_scans(self, current_time):
        """Detect port scanning activities"""
        for source_ip, ports in self.stats['port_access'].items():
            if len(ports) > self.attack_patterns['port_scan_threshold']:
                # Create port scan alert
                self._create_alert(
                    'port_scan',
                    'high',
                    source_ip,
                    '192.168.1.100',
                    f"Port scan detected: {len(ports)} unique ports accessed"
                )
                # Clear the ports to avoid duplicate alerts
                self.stats['port_access'][source_ip].clear()
    
    def _detect_flooding(self, current_time):
        """Detect flooding attacks"""
        if len(self.stats['packets_per_second']) > 0:
            current_pps = self.stats['packets_per_second'][-1]
            current_bps = self.stats['bytes_per_second'][-1] if self.stats['bytes_per_second'] else 0
            
            # Check packet rate flooding
            if current_pps > self.attack_patterns['flood_pps_threshold']:
                flood_source = self._get_top_traffic_source()
                self._create_alert(
                    'flooding',
                    'critical',
                    flood_source,
                    '192.168.1.100',
                    f"Packet flooding detected: {current_pps} packets/sec"
                )
            
            # Check bandwidth flooding
            if current_bps > self.attack_patterns['flood_bandwidth_threshold']:
                flood_source = self._get_top_traffic_source()
                self._create_alert(
                    'flooding',
                    'high',
                    flood_source,
                    '192.168.1.100',
                    f"Bandwidth flooding detected: {current_bps/1024/1024:.2f} MB/sec"
                )
    
    def _detect_traffic_anomalies(self, current_time):
        """Detect traffic anomalies using statistical analysis"""
        if len(self.stats['packets_per_second']) >= 30:  # Need at least 30 samples
            pps_data = list(self.stats['packets_per_second'])
            
            # Calculate mean and standard deviation
            mean_pps = sum(pps_data) / len(pps_data)
            variance = sum((x - mean_pps) ** 2 for x in pps_data) / len(pps_data)
            std_dev = variance ** 0.5
            
            if std_dev > 0:
                current_pps = pps_data[-1]
                z_score = abs(current_pps - mean_pps) / std_dev
                
                if z_score > self.attack_patterns['anomaly_std_threshold']:
                    anomaly_source = self._get_top_traffic_source()
                    self._create_alert(
                        'anomaly',
                        'medium',
                        anomaly_source,
                        '192.168.1.100',
                        f"Traffic anomaly detected: {z_score:.2f} standard deviations from normal"
                    )
    
    def _detect_connection_anomalies(self, current_time):
        """Detect connection-based anomalies"""
        for source_ip, count in self.stats['connection_count'].items():
            if count > self.attack_patterns['connection_threshold']:
                self._create_alert(
                    'anomaly',
                    'medium',
                    source_ip,
                    '192.168.1.100',
                    f"High connection rate: {count} connections/minute"
                )
                # Reset counter
                self.stats['connection_count'][source_ip] = 0
    
    def _detect_suspicious_activities(self, current_time):
        """Detect suspicious activities and insider threats"""
        # Check for access to sensitive ports
        for source_ip, ports in self.stats['port_access'].items():
            sensitive_ports = ports.intersection(set(self.attack_patterns['suspicious_ports']))
            if sensitive_ports:
                self._create_alert(
                    'suspicious_access',
                    'medium',
                    source_ip,
                    '192.168.1.100',
                    f"Access to sensitive ports: {list(sensitive_ports)}"
                )
    
    def _get_top_traffic_source(self):
        """Get the IP generating most traffic"""
        if self.stats['ip_traffic']:
            return max(self.stats['ip_traffic'].keys(), 
                      key=lambda ip: len(self.stats['ip_traffic'][ip]))
        return "unknown"
    
    def _create_alert(self, alert_type, severity, source_ip, target_ip, description):
        """Create intrusion alert"""
        try:
            from app import SecurityUtils
            
            # Check if similar alert already exists recently
            recent_alert = IntrusionAlert.query.filter(
                IntrusionAlert.source_ip == source_ip,
                IntrusionAlert.alert_type == alert_type,
                IntrusionAlert.created_at > datetime.utcnow() - timedelta(minutes=5)
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
            
            print(f"🚨 {alert_type.upper()} Alert: {description}")
            
        except Exception as e:
            print(f"Error creating alert: {e}")
    
    def _update_statistics(self, traffic):
        """Update traffic statistics"""
        current_time = time.time()
        
        # Update basic stats
        self.stats['total_packets'] += 1
        self.stats['bytes_transferred'] += traffic['size']
        
        # Update per-second stats
        self.stats['packets_per_second'].append(1)
        self.stats['bytes_per_second'].append(traffic['size'])
        
        # Update connection tracking
        key = f"{traffic['source_ip']}:{traffic['dest_ip']}:{traffic['dest_port']}"
        self.stats['connection_count'][traffic['source_ip']] += 1
        
        # Update port access tracking
        self.stats['port_access'][traffic['source_ip']].add(traffic['dest_port'])
        
        # Update IP traffic tracking
        self.stats['ip_traffic'][traffic['source_ip']].append(traffic)
        
        # Clean old data (older than 1 minute)
        cutoff_time = current_time - 60
        for ip in list(self.stats['ip_traffic'].keys()):
            self.stats['ip_traffic'][ip] = [
                t for t in self.stats['ip_traffic'][ip] 
                if t.get('timestamp', current_time) > cutoff_time
            ]
            if not self.stats['ip_traffic'][ip]:
                del self.stats['ip_traffic'][ip]
    
    def _create_traffic_log(self, traffic):
        """Create traffic log entry"""
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
            print(f"Error creating traffic log: {e}")
    
    def get_statistics(self):
        """Get current monitoring statistics"""
        return {
            'total_packets': self.stats['total_packets'],
            'bytes_transferred': self.stats['bytes_transferred'],
            'current_pps': self.stats['packets_per_second'][-1] if self.stats['packets_per_second'] else 0,
            'current_bps': self.stats['bytes_per_second'][-1] if self.stats['bytes_per_second'] else 0,
            'active_sources': len(self.stats['ip_traffic']),
            'port_scans_detected': len([ip for ip, ports in self.stats['port_access'].items() if len(ports) > 10])
        }

# Global monitor instance
network_monitor = NetworkMonitor()
