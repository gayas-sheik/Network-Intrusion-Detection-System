"""
Network Intrusion Detection System (NIDS)
A comprehensive cybersecurity application demonstrating:
- NIST SP 800-63-2 compliant authentication
- Role-based access control (RBAC)
- AES-256 encryption for logs and alerts
- RSA digital signatures for alert integrity
- Network traffic monitoring and intrusion detection
- Multi-factor authentication with OTP
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import os
import hashlib
import secrets
import base64
import time
import pyotp
import bcrypt
import json
import logging
import random
from datetime import datetime, timedelta
from functools import wraps
import threading
import queue
import socket
import struct
import ipaddress
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)  # Generate secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nids_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'your-email@gmail.com')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Global variables for NIDS functionality
nids_running = False
traffic_queue = queue.Queue()
alert_queue = queue.Queue()

# Import simple browser monitor
try:
    from simple_browser_monitor import simple_browser_monitor
    print("✅ Simple browser monitor loaded successfully")
except ImportError as e:
    print(f"⚠️ Simple browser monitor not available: {e}")
    simple_browser_monitor = None

# Import browser monitor
try:
    from browser_monitor import browser_monitor
    print("✅ Browser monitor loaded successfully")
except ImportError as e:
    print(f"⚠️ Browser monitor not available: {e}")
    browser_monitor = None

# Import network monitor
try:
    from network_monitor import network_monitor
    print("✅ Simulated network monitor loaded successfully")
except ImportError as e:
    print(f"⚠️ Simulated network monitor not available: {e}")
    network_monitor = None

# Import real network monitor
try:
    from real_network_monitor import real_network_monitor
    print("✅ Real network monitor loaded successfully")
except ImportError as e:
    print(f"⚠️ Real network monitor not available: {e}")
    real_network_monitor = None

# Database Models
class User(UserMixin, db.Model):
    """User model with role-based access control"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')  # admin, analyst, viewer
    mfa_secret = db.Column(db.String(32), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        """Hash password with salt using SHA-256"""
        self.salt = secrets.token_hex(32)
        salted_password = password.encode('utf-8') + self.salt.encode('utf-8')
        self.password_hash = hashlib.sha256(salted_password).hexdigest()

    def check_password(self, password):
        """Verify password against stored hash"""
        salted_password = password.encode('utf-8') + self.salt.encode('utf-8')
        return hashlib.sha256(salted_password).hexdigest() == self.password_hash

    def generate_mfa_secret(self):
        """Generate MFA secret for OTP"""
        self.mfa_secret = pyotp.random_base32()
        return self.mfa_secret

    def verify_mfa(self, token):
        """Verify MFA token"""
        if not self.mfa_secret:
            return False
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(token, valid_window=1)
    
    def send_otp_email(self):
        """Send OTP via email"""
        try:
            totp = pyotp.TOTP(self.mfa_secret)
            current_otp = totp.now()
            
            msg = Message(
                'NIDS - One-Time Password (OTP)',
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[self.email]
            )
            
            msg.body = f"""
Hello {self.username},

Your One-Time Password (OTP) for NIDS login is:

{current_otp}

This code will expire in 30 seconds.

If you did not request this OTP, please secure your account immediately.

Security Notice:
- Never share this OTP with anyone
- This OTP is valid for only 30 seconds
- NIDS will never ask for your password via email

Best regards,
Network Intrusion Detection System
            """
            
            mail.send(msg)
            logger.info(f"OTP sent to {self.email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send OTP email: {e}")
            return False

class TrafficLog(db.Model):
    """Encrypted network traffic logs"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(45), nullable=False)
    dest_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer, nullable=False)
    dest_port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    packet_size = db.Column(db.Integer, nullable=False)
    encrypted_payload = db.Column(db.Text, nullable=False)  # Encrypted packet data
    encryption_key = db.Column(db.Text, nullable=False)  # Encrypted AES key
    packet_hash = db.Column(db.String(64), nullable=False)  # SHA-256 hash
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class IntrusionAlert(db.Model):
    """Digitally signed intrusion alerts"""
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50), nullable=False)  # flooding, port_scan, anomaly
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    source_ip = db.Column(db.String(45), nullable=False)
    target_ip = db.Column(db.String(45), nullable=False)
    description = db.Column(db.Text, nullable=False)
    encrypted_details = db.Column(db.Text, nullable=False)  # Encrypted alert details
    digital_signature = db.Column(db.Text, nullable=False)  # RSA signature
    alert_hash = db.Column(db.String(64), nullable=False)  # SHA-256 hash
    status = db.Column(db.String(20), default='active')  # active, resolved, false_positive
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # Relationship with user
    resolver = db.relationship('User', backref=db.backref('resolved_alerts', lazy=True))

class SystemConfig(db.Model):
    """System configuration settings"""
    id = db.Column(db.Integer, primary_key=True)
    config_key = db.Column(db.String(100), unique=True, nullable=False)
    config_value = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=True)
    is_encrypted = db.Column(db.Boolean, default=False)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship with user
    updater = db.relationship('User', backref=db.backref('config_updates', lazy=True))

class AccessControl(db.Model):
    """Access Control List (ACL) for fine-grained permissions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)  # traffic_logs, intrusion_alerts, system_config
    resource_id = db.Column(db.String(100), nullable=True)  # Specific resource ID or 'all'
    permission = db.Column(db.String(20), nullable=False)  # read, write, delete, admin
    granted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('permissions', lazy=True))
    grantor = db.relationship('User', foreign_keys=[granted_by])

class AuditLog(db.Model):
    """Comprehensive audit log for security events"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    details = db.Column(db.Text, nullable=True)

    # Relationship with user
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))

# Security utility functions
class SecurityUtils:
    """Security utility class for encryption, hashing, and digital signatures"""
    
    @staticmethod
    def generate_aes_key():
        """Generate secure AES-256 key"""
        return os.urandom(32)  # 256 bits
    
    @staticmethod
    def encrypt_data(data, key):
        """Encrypt data using AES-256-GCM"""
        iv = os.urandom(12)  # 96-bit IV for GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Return IV + encrypted data + tag
        return iv + encrypted_data + encryptor.tag
    
    @staticmethod
    def decrypt_data(encrypted_data, key):
        """Decrypt data using AES-256-GCM"""
        iv = encrypted_data[:12]  # First 12 bytes are IV
        tag = encrypted_data[-16:]  # Last 16 bytes are authentication tag
        ciphertext = encrypted_data[12:-16]  # Middle is encrypted data
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    @staticmethod
    def generate_rsa_keys():
        """Generate RSA key pair for digital signatures"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def sign_data(data, private_key):
        """Create digital signature using RSA private key"""
        signature = private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(data, signature, public_key):
        """Verify digital signature using RSA public key"""
        try:
            signature_bytes = base64.b64decode(signature)
            public_key.verify(
                signature_bytes,
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def hash_data(data):
        """Calculate SHA-256 hash of data"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def encode_base64(data):
        """Encode data to Base64"""
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def decode_base64(encoded_data):
        """Decode Base64 data"""
        return base64.b64decode(encoded_data.encode('utf-8'))

# Network Intrusion Detection Engine
class NIDSEngine:
    """Network Intrusion Detection System Engine"""
    
    def __init__(self):
        self.detection_rules = {
            'flooding': {
                'packet_threshold': 1000,  # packets per second
                'connection_threshold': 100,  # connections per second
                'bandwidth_threshold': 1048576,  # 1MB per second
            },
            'port_scan': {
                'port_threshold': 50,  # unique ports accessed
                'time_window': 60,  # seconds
                'connection_threshold': 10,  # connections per port
            },
            'anomaly': {
                'baseline_samples': 1000,
                'deviation_threshold': 3.0,  # standard deviations
            }
        }
        self.traffic_stats = {}
        self.port_scan_tracker = {}
        self.baseline_traffic = []
        
        # Generate RSA keys for alert signing
        self.private_key, self.public_key = SecurityUtils.generate_rsa_keys()
    
    def analyze_packet(self, packet_data):
        """Analyze network packet for intrusion detection"""
        try:
            # Extract packet information
            source_ip = packet_data.get('source_ip')
            dest_ip = packet_data.get('dest_ip')
            source_port = packet_data.get('source_port')
            dest_port = packet_data.get('dest_port')
            protocol = packet_data.get('protocol')
            packet_size = packet_data.get('size', 0)
            timestamp = packet_data.get('timestamp', datetime.utcnow())
            
            # Update traffic statistics
            self.update_traffic_stats(source_ip, packet_size, timestamp)
            
            # Check for flooding attacks
            flooding_alert = self.detect_flooding(source_ip, timestamp)
            if flooding_alert:
                self.create_alert('flooding', 'high', source_ip, dest_ip, flooding_alert)
            
            # Check for port scanning
            port_scan_alert = self.detect_port_scan(source_ip, dest_port, timestamp)
            if port_scan_alert:
                self.create_alert('port_scan', 'medium', source_ip, dest_ip, port_scan_alert)
            
            # Check for traffic anomalies
            anomaly_alert = self.detect_anomaly(source_ip, packet_size, timestamp)
            if anomaly_alert:
                self.create_alert('anomaly', 'medium', source_ip, dest_ip, anomaly_alert)
                
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
    
    def update_traffic_stats(self, source_ip, packet_size, timestamp):
        """Update traffic statistics for anomaly detection"""
        if source_ip not in self.traffic_stats:
            self.traffic_stats[source_ip] = {
                'packet_count': 0,
                'total_bytes': 0,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'packets_per_second': [],
            }
        
        stats = self.traffic_stats[source_ip]
        stats['packet_count'] += 1
        stats['total_bytes'] += packet_size
        stats['last_seen'] = timestamp
        
        # Calculate packets per second
        time_diff = (timestamp - stats['first_seen']).total_seconds()
        if time_diff > 0:
            pps = stats['packet_count'] / time_diff
            stats['packets_per_second'].append(pps)
            
            # Keep only recent samples
            if len(stats['packets_per_second']) > 100:
                stats['packets_per_second'] = stats['packets_per_second'][-100:]
    
    def detect_flooding(self, source_ip, timestamp):
        """Detect potential flooding attacks"""
        if source_ip not in self.traffic_stats:
            return None
        
        stats = self.traffic_stats[source_ip]
        rules = self.detection_rules['flooding']
        
        # Check packet rate
        if stats['packets_per_second']:
            current_pps = stats['packets_per_second'][-1]
            if current_pps > rules['packet_threshold']:
                return f"High packet rate detected: {current_pps:.2f} packets/sec"
        
        # Check bandwidth usage
        time_diff = (timestamp - stats['first_seen']).total_seconds()
        if time_diff > 0:
            bps = stats['total_bytes'] / time_diff
            if bps > rules['bandwidth_threshold']:
                return f"High bandwidth usage detected: {bps/1024/1024:.2f} MB/sec"
        
        return None
    
    def detect_port_scan(self, source_ip, dest_port, timestamp):
        """Detect potential port scanning activity"""
        if source_ip not in self.port_scan_tracker:
            self.port_scan_tracker[source_ip] = {
                'ports_accessed': set(),
                'first_seen': timestamp,
                'port_counts': {},
            }
        
        tracker = self.port_scan_tracker[source_ip]
        tracker['ports_accessed'].add(dest_port)
        
        if dest_port not in tracker['port_counts']:
            tracker['port_counts'][dest_port] = 0
        tracker['port_counts'][dest_port] += 1
        
        rules = self.detection_rules['port_scan']
        time_diff = (timestamp - tracker['first_seen']).total_seconds()
        
        # Check if too many ports accessed in time window
        if time_diff <= rules['time_window']:
            if len(tracker['ports_accessed']) > rules['port_threshold']:
                return f"Port scan detected: {len(tracker['ports_accessed'])} ports in {time_diff:.0f} seconds"
        
        return None
    
    def detect_anomaly(self, source_ip, packet_size, timestamp):
        """Detect traffic anomalies using statistical analysis"""
        # This is a simplified anomaly detection
        # In production, you'd use more sophisticated ML algorithms
        
        if source_ip not in self.traffic_stats:
            return None
        
        stats = self.traffic_stats[source_ip]
        if len(stats['packets_per_second']) < 10:
            return None  # Not enough data for analysis
        
        # Calculate mean and standard deviation
        pps_samples = stats['packets_per_second'][-50:]  # Last 50 samples
        if len(pps_samples) < 10:
            return None
        
        mean_pps = sum(pps_samples) / len(pps_samples)
        variance = sum((x - mean_pps) ** 2 for x in pps_samples) / len(pps_samples)
        std_dev = variance ** 0.5
        
        current_pps = pps_samples[-1]
        threshold = self.detection_rules['anomaly']['deviation_threshold']
        
        if std_dev > 0 and abs(current_pps - mean_pps) > threshold * std_dev:
            return f"Traffic anomaly detected: {current_pps:.2f} pps (baseline: {mean_pps:.2f} ± {std_dev:.2f})"
        
        return None
    
    def create_alert(self, alert_type, severity, source_ip, target_ip, description):
        """Create and sign intrusion alert"""
        try:
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
            signature = SecurityUtils.sign_data(alert_json, self.private_key)
            
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
            
            logger.info(f"Created {alert_type} alert for {source_ip}")
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")

# Global NIDS engine instance
nids_engine = NIDSEngine()

# Access Control decorators
def require_permission(permission, resource_type='traffic_logs'):
    """Decorator to check user permissions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            # Check role-based permissions
            if current_user.role == 'admin':
                return f(*args, **kwargs)
            
            # Check ACL for specific permissions
            has_permission = AccessControl.query.filter_by(
                user_id=current_user.id,
                resource_type=resource_type,
                permission=permission
            ).first()
            
            if not has_permission:
                log_audit_event(
                    user_id=current_user.id,
                    action='unauthorized_access_attempt',
                    resource=resource_type,
                    success=False,
                    details=f'Attempted to access {resource_type} with {permission} permission'
                )
                flash('Access denied: Insufficient permissions', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_audit_event(user_id, action, resource=None, success=True, details=None):
    """Log security events for audit trail"""
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        success=success,
        details=details
    )
    db.session.add(audit_log)
    db.session.commit()
    logger.info(f"Audit: {action} by user {user_id} - Success: {success}")

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with secure password handling"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'viewer')
        
        # Validate input
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('register.html')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        user.generate_mfa_secret()
        
        db.session.add(user)
        db.session.commit()
        
        # Log registration
        log_audit_event(
            user_id=user.id,
            action='user_registration',
            resource='user_account',
            details=f'New user registered: {username}'
        )
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

def display_otp_in_terminal(username, user):
    """Display OTP in terminal with clear formatting"""
    totp = pyotp.TOTP(user.mfa_secret)
    current_otp = totp.now()
    
    # Display OTP in terminal with clear formatting
    print("\n" + "="*60)
    print("🔐 NIDS ONE-TIME PASSWORD (OTP)")
    print("="*60)
    print(f"👤 User: {username}")
    print(f"📧 Email: {user.email}")
    print(f"🔑 OTP Code: {current_otp}")
    print(f"⏰ Valid for: 30 seconds")
    print(f"🕐 Generated at: {datetime.now().strftime('%H:%M:%S')}")
    print("="*60)
    print("📝 Copy this OTP and paste it in the login form")
    print("="*60 + "\n")
    
    return current_otp

@app.route('/send_otp', methods=['POST'])
def send_otp():
    """Send OTP to user's email"""
    username = request.form.get('username')
    
    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash('Username not found', 'error')
        return redirect(url_for('login'))
    
    # Always display OTP in terminal for demonstration
    current_otp = display_otp_in_terminal(username, user)
    
    # Try to send email (but OTP is already shown in terminal)
    email_sent = user.send_otp_email()
    
    if email_sent:
        flash(f'OTP sent to {user.email} and displayed in terminal', 'success')
    else:
        flash('OTP displayed in terminal (email failed)', 'info')
    
    session['otp_sent'] = True
    session['otp_username'] = username
    logger.info(f"OTP displayed in terminal for user {username}")
    
    # Preserve username in session to pre-fill the form
    session['preserved_username'] = username
    
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login with MFA support"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        mfa_token = request.form.get('mfa_token', '')
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            log_audit_event(
                user_id=user.id if user else None,
                action='login_attempt',
                resource='authentication',
                success=False,
                details='Invalid username or password'
            )
            flash('Invalid username or password', 'error')
            return render_template('login.html')
        
        if not user.is_active:
            log_audit_event(
                user_id=user.id,
                action='login_attempt',
                resource='authentication',
                success=False,
                details='Account deactivated'
            )
            flash('Account is deactivated', 'error')
            return render_template('login.html')
        
        # Verify MFA token
        if not user.verify_mfa(mfa_token):
            log_audit_event(
                user_id=user.id,
                action='login_attempt',
                resource='authentication',
                success=False,
                details='Invalid MFA token'
            )
            flash('Invalid MFA token', 'error')
            return render_template('login.html')
        
        # Successful login
        login_user(user)
        log_audit_event(
            user_id=user.id,
            action='login_success',
            resource='authentication',
            success=True,
            details=f'User {username} logged in successfully'
        )
        
        # Clear preserved username from session
        session.pop('preserved_username', None)
        
        next_page = request.args.get('next')
        return redirect(next_page or url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout and clear session"""
    log_audit_event(
        user_id=current_user.id,
        action='logout',
        resource='authentication',
        details=f'User {current_user.username} logged out'
    )
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with system overview"""
    # Get recent alerts
    recent_alerts = IntrusionAlert.query.order_by(IntrusionAlert.created_at.desc()).limit(10).all()
    
    # Get traffic statistics
    total_logs = TrafficLog.query.count()
    total_alerts = IntrusionAlert.query.count()
    active_alerts = IntrusionAlert.query.filter_by(status='active').count()
    
    return render_template('dashboard.html', 
                         recent_alerts=recent_alerts,
                         total_logs=total_logs,
                         total_alerts=total_alerts,
                         active_alerts=active_alerts)

@app.route('/traffic_logs')
@login_required
@require_permission('read', 'traffic_logs')
def traffic_logs():
    """View encrypted traffic logs"""
    page = request.args.get('page', 1, type=int)
    logs = TrafficLog.query.order_by(TrafficLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False)
    return render_template('traffic_logs.html', logs=logs)

@app.route('/alerts')
@login_required
@require_permission('read', 'intrusion_alerts')
def alerts():
    """View intrusion alerts"""
    page = request.args.get('page', 1, type=int)
    alerts = IntrusionAlert.query.order_by(IntrusionAlert.created_at.desc()).paginate(
        page=page, per_page=50, error_out=False)
    return render_template('alerts.html', alerts=alerts)

@app.route('/alert/<int:alert_id>')
@login_required
@require_permission('read', 'intrusion_alerts')
def view_alert(alert_id):
    """View detailed alert information"""
    alert = IntrusionAlert.query.get_or_404(alert_id)
    
    try:
        # Decrypt alert details
        encrypted_details = SecurityUtils.decode_base64(alert.encrypted_details)
        aes_key = SecurityUtils.decode_base64(alert.encryption_key)
        decrypted_details = SecurityUtils.decrypt_data(encrypted_details, aes_key)
        alert_data = json.loads(decrypted_details.decode('utf-8'))
        
        # Verify digital signature
        is_valid_signature = SecurityUtils.verify_signature(
            decrypted_details, 
            alert.digital_signature, 
            nids_engine.public_key
        )
        
        return render_template('alert_detail.html', 
                             alert=alert, 
                             alert_data=alert_data,
                             signature_valid=is_valid_signature)
        
    except Exception as e:
        logger.error(f"Error decrypting alert {alert_id}: {e}")
        flash('Error decrypting alert details', 'error')
        return redirect(url_for('alerts'))

@app.route('/resolve_alert/<int:alert_id>', methods=['POST'])
@login_required
@require_permission('write', 'intrusion_alerts')
def resolve_alert(alert_id):
    """Resolve an intrusion alert"""
    alert = IntrusionAlert.query.get_or_404(alert_id)
    
    alert.status = 'resolved'
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = current_user.id
    
    db.session.commit()
    
    log_audit_event(
        user_id=current_user.id,
        action='alert_resolved',
        resource='intrusion_alert',
        details=f'Alert {alert_id} resolved by {current_user.username}'
    )
    
    flash('Alert resolved successfully', 'success')
    return redirect(url_for('alerts'))

@app.route('/system_config')
@login_required
@require_permission('read', 'system_config')
def system_config():
    """View system configuration"""
    configs = SystemConfig.query.all()
    return render_template('system_config.html', configs=configs)

@app.route('/nids_control')
@login_required
@require_permission('admin', 'system_config')
def nids_control():
    """Control NIDS engine"""
    global nids_running, network_monitor, real_network_monitor, browser_monitor, simple_browser_monitor
    
    action = request.args.get('action')
    if action == 'start':
        nids_running = True
        
        # Start with simple browser monitor first (most reliable)
        if simple_browser_monitor:
            simple_browser_monitor.start_monitoring()
            flash('Browser monitoring started - detecting actual browser tab activity', 'success')
        elif browser_monitor:
            browser_monitor.start_monitoring()
            flash('Browser monitoring started - detecting actual browser tab activity', 'success')
        elif real_network_monitor:
            real_network_monitor.start_monitoring()
            flash('Real device monitoring started - monitoring your actual network traffic', 'success')
        elif network_monitor:
            network_monitor.start_monitoring()
            flash('Simulated monitoring started', 'info')
        else:
            flash('No monitor available', 'warning')
        
    elif action == 'stop':
        nids_running = False
        
        if simple_browser_monitor:
            simple_browser_monitor.stop_monitoring()
        elif browser_monitor:
            browser_monitor.stop_monitoring()
        elif real_network_monitor:
            real_network_monitor.stop_monitoring()
        elif network_monitor:
            network_monitor.stop_monitoring()
        
        flash('NIDS engine stopped', 'warning')
    
    # Get current statistics from active monitor
    stats = {}
    monitor_type = 'none'
    
    if simple_browser_monitor and simple_browser_monitor.running:
        stats = simple_browser_monitor.get_statistics()
        monitor_type = 'simple_browser'
    elif browser_monitor and browser_monitor.running:
        stats = browser_monitor.get_statistics()
        monitor_type = 'browser'
    elif real_network_monitor and real_network_monitor.running:
        stats = real_network_monitor.get_statistics()
        monitor_type = 'real_device'
    elif network_monitor and network_monitor.running:
        stats = network_monitor.get_statistics()
        monitor_type = 'simulated'
    elif simple_browser_monitor:
        stats = simple_browser_monitor.get_statistics()
        monitor_type = 'simple_browser'
    elif browser_monitor:
        stats = browser_monitor.get_statistics()
        monitor_type = 'browser'
    elif real_network_monitor:
        stats = real_network_monitor.get_statistics()
        monitor_type = 'real_device'
    elif network_monitor:
        stats = network_monitor.get_statistics()
        monitor_type = 'simulated'
    
    return render_template('nids_control.html', nids_running=nids_running, stats=stats, monitor_type=monitor_type)

def create_sample_alerts():
    """Create sample intrusion alerts for demonstration"""
    try:
        from app import SecurityUtils
        
        sample_alerts = [
            {
                'alert_type': 'port_scan',
                'severity': 'high',
                'source_ip': '192.168.1.50',
                'target_ip': '192.168.1.100',
                'description': 'Port scan detected: 25 unique ports accessed in 60 seconds'
            },
            {
                'alert_type': 'flooding',
                'severity': 'critical',
                'source_ip': '10.0.0.100',
                'target_ip': '192.168.1.100',
                'description': 'Packet flooding detected: 150 packets/sec'
            },
            {
                'alert_type': 'anomaly',
                'severity': 'medium',
                'source_ip': '172.16.0.25',
                'target_ip': '192.168.1.100',
                'description': 'Traffic anomaly detected: 3.2 standard deviations from normal'
            },
            {
                'alert_type': 'brute_force',
                'severity': 'medium',
                'source_ip': '10.0.0.75',
                'target_ip': '192.168.1.100',
                'description': 'SSH brute force attack detected: 50 failed login attempts'
            },
            {
                'alert_type': 'suspicious_access',
                'severity': 'medium',
                'source_ip': '192.168.1.50',
                'target_ip': '192.168.1.100',
                'description': 'Access to sensitive ports: [22, 3306, 3389]'
            }
        ]
        
        for alert_data in sample_alerts:
            # Create alert data
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
                alert_type=alert_data['alert_type'],
                severity=alert_data['severity'],
                source_ip=alert_data['source_ip'],
                target_ip=alert_data['target_ip'],
                description=alert_data['description'][:255],
                encrypted_details=SecurityUtils.encode_base64(encrypted_details),
                digital_signature=signature,
                alert_hash=alert_hash,
                created_at=datetime.utcnow() - timedelta(minutes=random.randint(1, 30))
            )
            
            db.session.add(alert)
        
        db.session.commit()
        print("✅ Sample intrusion alerts created for demonstration")
        
    except Exception as e:
        print(f"Error creating sample alerts: {e}")

# Initialize database and create default admin
with app.app_context():
    db.create_all()
    
    # Create default admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            role='admin'
        )
        admin.set_password('Admin123!@#')
        admin.generate_mfa_secret()
        db.session.add(admin)
        
        # Create sample analyst
        analyst = User(
            username='analyst',
            email='analyst@example.com',
            role='analyst'
        )
        analyst.set_password('Analyst123!@#')
        analyst.generate_mfa_secret()
        db.session.add(analyst)
        
        # Create sample viewer
        viewer = User(
            username='viewer',
            email='viewer@example.com',
            role='viewer'
        )
        viewer.set_password('Viewer123!@#')
        viewer.generate_mfa_secret()
        db.session.add(viewer)
        
        db.session.commit()
        
        print("Default users created:")
        print("Admin - Username: admin, Password: Admin123!@#")
        print("Analyst - Username: analyst, Password: Analyst123!@#")
        print("Viewer - Username: viewer, Password: Viewer123!@#")
        print("\nMFA secrets generated. Use pyotp.TOTP(secret).now() to get current OTP")
    
    # Create sample alerts for demonstration
    if IntrusionAlert.query.count() == 0:
        create_sample_alerts()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
