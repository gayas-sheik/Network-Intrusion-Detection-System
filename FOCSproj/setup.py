#!/usr/bin/env python3
"""
Network Intrusion Detection System - Setup Script
Automated setup for the cybersecurity demonstration application
"""

import os
import sys
import subprocess
import sqlite3
from datetime import datetime

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print("✅ Python version check passed")

def install_dependencies():
    """Install required Python packages"""
    print("📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        sys.exit(1)

def create_directories():
    """Create necessary directories"""
    directories = ['encrypted_logs', 'logs']
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"✅ Created directory: {directory}")
        else:
            print(f"📁 Directory already exists: {directory}")

def initialize_database():
    """Initialize the SQLite database"""
    print("🗄️ Initializing database...")
    try:
        # Import app to create database tables
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from app import app, db, User
        
        with app.app_context():
            db.create_all()
            print("✅ Database tables created")
            
            # Check if default users exist
            admin_exists = User.query.filter_by(username='admin').first()
            if not admin_exists:
                create_default_users()
            else:
                print("👥 Default users already exist")
                
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        sys.exit(1)

def create_default_users():
    """Create default demo users"""
    from app import db, User
    
    print("👥 Creating default demo users...")
    
    users = [
        {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'Admin123!@#',
            'role': 'admin'
        },
        {
            'username': 'analyst',
            'email': 'analyst@example.com',
            'password': 'Analyst123!@#',
            'role': 'analyst'
        },
        {
            'username': 'viewer',
            'email': 'viewer@example.com',
            'password': 'Viewer123!@#',
            'role': 'viewer'
        }
    ]
    
    for user_data in users:
        user = User(
            username=user_data['username'],
            email=user_data['email'],
            role=user_data['role']
        )
        user.set_password(user_data['password'])
        user.generate_mfa_secret()
        db.session.add(user)
        print(f"✅ Created user: {user_data['username']} ({user_data['role']})")
    
    db.session.commit()
    print("✅ Default users created successfully")

def generate_mfa_codes():
    """Generate current MFA codes for demo users"""
    print("\n🔐 MFA Codes for Demo Users:")
    print("=" * 50)
    
    try:
        from app import User, app
        
        with app.app_context():
            users = User.query.all()
            for user in users:
                import pyotp
                totp = pyotp.TOTP(user.mfa_secret)
                current_code = totp.now()
                print(f"👤 {user.username} ({user.role}): {current_code}")
                
    except Exception as e:
        print(f"❌ Error generating MFA codes: {e}")

def display_startup_info():
    """Display application startup information"""
    print("\n🚀 Setup Complete!")
    print("=" * 50)
    print("📋 Network Intrusion Detection System Information:")
    print(f"🌐 URL: http://localhost:5000")
    print(f"📁 Encrypted Logs Directory: {os.path.abspath('encrypted_logs')}")
    print(f"🗄️ Database: {os.path.abspath('nids_database.db')}")
    print("\n👤 Demo Credentials:")
    print("┌─────────────┬──────────────────┬──────────┐")
    print("│ Username    │ Password         │ Role     │")
    print("├─────────────┼──────────────────┼──────────┤")
    print("│ admin       │ Admin123!@#      │ Admin    │")
    print("│ analyst     │ Analyst123!@#    │ Analyst  │")
    print("│ viewer      │ Viewer123!@#     │ Viewer   │")
    print("└─────────────┴──────────────────┴──────────┘")
    print("\n🔐 MFA Setup:")
    print("• MFA is automatically enabled for all users")
    print("• Use the codes shown above to login")
    print("• New codes generated every 30 seconds")
    print("\n🎯 Security Features Demonstrated:")
    print("✅ NIST SP 800-63-2 Authentication")
    print("✅ Multi-Factor Authentication (MFA)")
    print("✅ AES-256 Encryption for logs and alerts")
    print("✅ RSA Digital Signatures for integrity")
    print("✅ Role-Based Access Control (RBAC)")
    print("✅ Network Boundary Monitoring")
    print("✅ Intrusion Detection Logic")
    print("✅ Comprehensive Audit Logging")
    print("✅ SHA-256 Password Hashing with Salt")
    print("✅ Base64 Encoding for secure transmission")
    print("\n📚 Documentation:")
    print("📖 See README.md for detailed information")
    print("📖 See ARCHITECTURE.md for system design")
    print("📖 See SECURITY_DOCUMENTATION.md for theoretical analysis")
    print("🎓 Ready for academic evaluation and viva")

def check_network_permissions():
    """Check if user has sufficient permissions for network monitoring"""
    print("\n🔍 Network Permission Check:")
    try:
        import socket
        import platform
        
        system = platform.system()
        if system == "Linux":
            # Try to create a raw socket (requires admin privileges on Linux)
            test_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            test_socket.close()
            print("✅ Raw socket access available (admin privileges)")
            return True
        elif system == "Windows":
            # Windows uses different socket types for packet capture
            print("ℹ️  Windows system detected")
            print("   For full network monitoring, run with administrator privileges")
            print("   Npcap or WinPcap required for raw socket access")
            print("   Demo mode will simulate network traffic for demonstration")
            return False
        else:
            print(f"ℹ️  {system} system detected")
            print("   Demo mode will simulate network traffic for demonstration")
            return False
            
    except (OSError, PermissionError):
        print("⚠️  Raw socket access not available (demo mode)")
        print("   For full network monitoring, run with administrator/root privileges")
        print("   Demo mode will simulate network traffic for demonstration")
        return False
    except Exception as e:
        print(f"ℹ️  Network permission check failed: {e}")
        print("   Demo mode will simulate network traffic for demonstration")
        return False

def run_application():
    """Optionally run the application"""
    print("\n" + "=" * 50)
    response = input("🚀 Would you like to start the NIDS application now? (y/n): ").lower().strip()
    
    if response in ['y', 'yes']:
        print("\n🌐 Starting Network Intrusion Detection System...")
        print("📍 Navigate to: http://localhost:5000")
        print("⏹️  Press Ctrl+C to stop the server")
        print("🔍 Use demo credentials to access the system")
        print("=" * 50)
        
        try:
            from app import app
            app.run(debug=False, host='0.0.0.0', port=5000)
        except KeyboardInterrupt:
            print("\n👋 NIDS application stopped by user")
        except Exception as e:
            print(f"❌ Error starting application: {e}")
    else:
        print("\n💡 To start the application later, run:")
        print("   python app.py")
        print("\n📚 Don't forget to check the documentation files!")

def main():
    """Main setup function"""
    print("🔐 Network Intrusion Detection System - Setup")
    print("=" * 50)
    print("🎓 Foundations of Cyber Security Lab Evaluation")
    print("📅 Setup started at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 50)
    
    # Run setup steps
    check_python_version()
    install_dependencies()
    create_directories()
    initialize_database()
    check_network_permissions()
    generate_mfa_codes()
    display_startup_info()
    run_application()

if __name__ == "__main__":
    main()
