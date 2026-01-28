#!/usr/bin/env python3
"""
Network Intrusion Detection System - Quick Start Script
Simple script to run the NIDS application
"""

import os
import sys

def check_requirements():
    """Check if required packages are installed"""
    try:
        import flask
        import flask_sqlalchemy
        import flask_login
        import flask_mail
        import cryptography
        import pyotp
        print("✅ All required packages are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing package: {e}")
        print("Please run: pip install -r requirements.txt")
        return False

def setup_email():
    """Check email configuration"""
    from dotenv import load_dotenv
    load_dotenv()
    
    if os.getenv('MAIL_USERNAME') == 'your-email@gmail.com':
        print("\n⚠️  Email configuration not set up")
        print("To enable OTP via email:")
        print("1. Copy .env.example to .env")
        print("2. Update .env with your email details")
        print("3. For Gmail: Enable 2FA and generate app password")
        print("4. Restart the application")
        return False
    else:
        print("✅ Email configuration found")
        return True

def main():
    print("🔐 Network Intrusion Detection System - Quick Start")
    print("=" * 50)
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Check email setup
    email_configured = setup_email()
    
    print("\n🚀 Starting NIDS Application...")
    print("📍 URL: http://localhost:5000")
    print("👤 Default Users:")
    print("   • admin / Admin123!@#")
    print("   • analyst / Analyst123!@#")
    print("   • viewer / Viewer123!@#")
    
    if email_configured:
        print("📧 OTP will be sent to user emails")
    else:
        print("📱 Use manual OTP (see setup.py for generation)")
    
    print("\n⏹️  Press Ctrl+C to stop the server")
    print("=" * 50)
    
    try:
        # Import and run the app
        from app import app
        app.run(debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n👋 NIDS application stopped")
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
