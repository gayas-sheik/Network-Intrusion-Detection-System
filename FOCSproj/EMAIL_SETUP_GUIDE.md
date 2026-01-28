# Email OTP Setup Guide

## 📧 Setting Up Email OTP for NIDS

This guide will help you configure the Network Intrusion Detection System to send One-Time Passwords (OTP) directly to user emails.

## 🔧 Step 1: Configure Gmail (Recommended)

### 1.1 Enable 2-Factor Authentication
1. Go to [Google Account Settings](https://myaccount.google.com/)
2. Click on "Security"
3. Enable "2-Step Verification"

### 1.2 Generate App Password
1. In Google Security settings, click on "App passwords"
2. Select "Mail" for the app
3. Select "Other (Custom name)" and enter "NIDS"
4. Click "Generate"
5. Copy the 16-character password (this is your app password)

### 1.3 Create .env File
1. Copy the example file:
   ```bash
   cp .env.example .env
   ```

2. Edit the `.env` file with your details:
   ```env
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USE_TLS=True
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-16-character-app-password
   MAIL_DEFAULT_SENDER=your-email@gmail.com
   ```

## 🔧 Step 2: Configure Outlook/Hotmail (Alternative)

### 2.1 Enable 2-Factor Authentication
1. Go to [Microsoft Account Security](https://account.microsoft.com/security)
2. Enable "Two-step verification"

### 2.2 Generate App Password
1. In security settings, go to "Advanced security options"
2. Under "App passwords", create a new password
3. Enter "NIDS" as the app name
4. Copy the generated password

### 2.3 Update .env File
```env
MAIL_SERVER=smtp-mail.outlook.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@outlook.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@outlook.com
```

## 🚀 Step 3: Run the Application

### Method 1: Quick Start (Recommended)
```bash
python run.py
```

### Method 2: Direct Run
```bash
python app.py
```

### Method 3: Full Setup
```bash
python setup.py
```

## 📱 Step 4: Test Email OTP

1. Navigate to: http://localhost:5000
2. Enter username (e.g., "admin")
3. Enter password (e.g., "Admin123!@#")
4. Click "Send OTP to Email" link
5. Check your email for the OTP
6. Enter the 6-digit OTP in the MFA field
7. Click "Access NIDS System"

## 🔄 Step 5: Update User Emails

The default users have example emails. Update them in the database:

```python
# Run this in Python console
from app import app, db, User
with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    admin.email = 'your-email@gmail.com'  # Update with your email
    db.session.commit()
```

## 🛠️ Troubleshooting

### Issue: "SMTP authentication failed"
**Solution**: 
- Verify your app password is correct
- Ensure 2-factor authentication is enabled
- Check that you're using an app password, not your regular password

### Issue: "Connection refused"
**Solution**:
- Check your firewall settings
- Verify SMTP server and port are correct
- Try with TLS disabled for testing (not recommended for production)

### Issue: "Email not received"
**Solution**:
- Check spam/junk folder
- Verify recipient email address
- Check email server logs

### Issue: "Invalid MFA token"
**Solution**:
- OTP expires after 30 seconds, get a new one
- Ensure you're entering the latest OTP
- Check that system time is correct

## 🔒 Security Best Practices

1. **Never commit .env file to version control**
2. **Use app-specific passwords, not your main password**
3. **Enable 2-factor authentication on your email account**
4. **Regularly rotate app passwords**
5. **Monitor email for suspicious activity**

## 📧 Email Template Preview

When users request an OTP, they'll receive an email like this:

```
Subject: NIDS - One-Time Password (OTP)

Hello admin,

Your One-Time Password (OTP) for NIDS login is:

123456

This code will expire in 30 seconds.

If you did not request this OTP, please secure your account immediately.

Security Notice:
- Never share this OTP with anyone
- This OTP is valid for only 30 seconds
- NIDS will never ask for your password via email

Best regards,
Network Intrusion Detection System
```

## 🎯 Testing Checklist

- [ ] Email configured in .env file
- [ ] 2-factor authentication enabled on email account
- [ ] App password generated
- [ ] Application starts without errors
- [ ] OTP email received successfully
- [ ] OTP works for login
- [ ] OTP expires after 30 seconds

## 📞 Support

If you encounter issues:

1. Check the application logs for error messages
2. Verify all configuration values are correct
3. Test email configuration with a simple Python script
4. Ensure firewall allows SMTP connections

For additional help, refer to the main README.md file.
