const nodemailer = require('nodemailer');

// Create reusable transporter
let transporter = null;

function createTransporter() {
  if (transporter) return transporter;
  
  const config = {
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.EMAIL_PORT) || 587,
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  };
  
  // Check if email is configured
  if (!config.auth.user || !config.auth.pass || config.auth.user === 'your-email@gmail.com') {
    console.warn('⚠️  Email not configured. Set EMAIL_USER and EMAIL_PASS in .env file.');
    return null;
  }
  
  transporter = nodemailer.createTransport(config);
  return transporter;
}

async function sendVerificationEmail(email, username, verificationCode, otpTtlMinutes = 10) {
  const trans = createTransporter();
  
  if (!trans) {
    console.warn('⚠️  Skipping email send - email not configured');
    return false;
  }
  
  const mailOptions = {
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
    to: email,
    subject: 'Verify Your Email - SQLi Demo Store',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; background-color: #0b1020; color: #e6eefc; padding: 20px; }
          .container { max-width: 600px; margin: 0 auto; background: #111a33; border-radius: 12px; padding: 30px; border: 1px solid #1b2a4d; }
          .header { text-align: center; margin-bottom: 30px; }
          .code-box { background: #1a2440; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; border: 2px solid #5b9aff; }
          .code { font-size: 32px; font-weight: bold; color: #5b9aff; letter-spacing: 8px; font-family: monospace; }
          .footer { text-align: center; color: #a8c1f5; font-size: 12px; margin-top: 30px; }
          a { color: #5b9aff; text-decoration: none; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1 style="color: #5b9aff;">🛡️ SQLi Demo Store</h1>
            <h2 style="color: #e6eefc;">Verify Your Email</h2>
          </div>
          
          <p>Hi <strong>${username}</strong>,</p>
          
          <p>Thank you for signing up! Please verify your email address by entering the following code:</p>
          
          <div class="code-box">
            <div style="color: #a8c1f5; margin-bottom: 10px;">Your Verification Code:</div>
            <div class="code">${verificationCode}</div>
          </div>
          
          <p>Go back to <a href="http://localhost:3000/signup">the signup page</a> and enter your username and code to verify.</p>
          <ul>
            <li><strong>Username:</strong> ${username}</li>
            <li><strong>Code:</strong> ${verificationCode}</li>
          </ul>
          
          <p>This code will expire in ${otpTtlMinutes} minutes.</p>
          
          <p>If you didn't create an account, please ignore this email.</p>
          
          <div class="footer">
            <p>This is an educational demo application for learning about SQL Injection.</p>
            <p>For educational purposes only - not for production use.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `
Hi ${username},

Thank you for signing up for SQLi Demo Store!

Your verification code is: ${verificationCode}

Go back to the signup page (http://localhost:3000/signup) and enter your username and code:
- Username: ${username}
- Code: ${verificationCode}

This code will expire in ${otpTtlMinutes} minutes.

If you didn't create an account, please ignore this email.

---
This is an educational demo application.
    `
  };
  
  try {
    await trans.sendMail(mailOptions);
    console.log(`✅ Verification email sent to ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Error sending email:', error.message);
    return false;
  }
}

async function sendLoginOTPEmail(email, username, otpCode, otpTtlMinutes) {
  const trans = createTransporter();

  if (!trans) {
    console.warn('⚠️  Skipping login OTP send - email not configured');
    return false;
  }

  const mailOptions = {
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
    to: email,
    subject: 'Your Login OTP - SQLi Demo Store',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; background-color: #0b1020; color: #e6eefc; padding: 20px; }
          .container { max-width: 600px; margin: 0 auto; background: #111a33; border-radius: 12px; padding: 30px; border: 1px solid #1b2a4d; }
          .header { text-align: center; margin-bottom: 30px; }
          .code-box { background: #1a2440; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; border: 2px solid #5b9aff; }
          .code { font-size: 32px; font-weight: bold; color: #5b9aff; letter-spacing: 8px; font-family: monospace; }
          .footer { text-align: center; color: #a8c1f5; font-size: 12px; margin-top: 30px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1 style="color: #5b9aff;">🛡️ SQLi Demo Store</h1>
            <h2 style="color: #e6eefc;">Login OTP Verification</h2>
          </div>

          <p>Hi <strong>${username}</strong>,</p>

          <p>Use this one-time password to complete your login:</p>

          <div class="code-box">
            <div style="color: #a8c1f5; margin-bottom: 10px;">Your OTP Code:</div>
            <div class="code">${otpCode}</div>
          </div>

          <p>This code expires in ${otpTtlMinutes} minutes.</p>
          <p>If this was not you, you can ignore this email.</p>

          <div class="footer">
            <p>This is an educational demo application for learning about SQL Injection.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `
Hi ${username},

Your login OTP is: ${otpCode}

This code expires in ${otpTtlMinutes} minutes.

If this was not you, please ignore this email.

---
This is an educational demo application.
    `
  };

  try {
    await trans.sendMail(mailOptions);
    console.log(`✅ Login OTP sent to ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Error sending login OTP email:', error.message);
    return false;
  }
}

module.exports = { sendVerificationEmail, sendLoginOTPEmail };
