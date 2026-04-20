require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const morgan = require('morgan');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { all, get, run, rawQuery, init, reset } = require('./src/db');
const { sendVerificationEmail, sendLoginOTPEmail } = require('./src/email');

const app = express();
const PORT = process.env.PORT || 3000;
let VULN_MODE = (process.env.VULN_MODE || 'on').toLowerCase() === 'on' ? 'on' : 'off';
const OTP_TTL_MINUTES = parseInt(process.env.OTP_TTL_MINUTES || '10', 10);
const LOGIN_OTP_REQUIRED = (process.env.LOGIN_OTP_REQUIRED || 'true').toLowerCase() === 'true';

// Simple in-memory guard to prevent concurrent DB resets from being started
// by multiple HTTP requests. This prevents race conditions where two
// reset processes run at the same time and violate FK constraints.
let resetInProgress = false;
// Flag that indicates whether DB initialization/seeding has completed.
// We start the HTTP server immediately and perform DB init in background
// so the wrapper/browser can connect quickly while seeding proceeds.
let dbReady = false;

// Phrase that admin must type to confirm destructive reset. Keep it obvious
// and configurable via environment for CI or other workflows.
const RESET_CONFIRM_PHRASE = process.env.RESET_CONFIRM_PHRASE || 'RESET DEMO';

// Store last executed SQL for demo purposes
let lastSQL = [];

// Helper to find product image with any extension
function getImagePath(imageName) {
  const extensions = ['.png', '.jpg', '.jpeg', '.webp', '.gif'];
  const basePath = path.join(__dirname, 'public', 'images', 'products');
  
  for (const ext of extensions) {
    const fullPath = path.join(basePath, imageName + ext);
    if (fs.existsSync(fullPath)) {
      return `/public/images/products/${imageName}${ext}`;
    }
  }
  
  // Return placeholder if no image found
  return '/public/images/products/placeholder.svg';
}

// View engine and static assets
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.use(
  session({
    // Use a provided SESSION_SECRET when possible. If not provided, generate
    // a secure random secret at runtime so the repository doesn't contain
    // a predictable default secret.
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 }
  })
);

if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET is not set. A random secret was generated for this process. For repeatable demo runs set SESSION_SECRET in your environment.');
}

// Helper to expose mode, session, cart, and SQL demo to views
app.use((req, res, next) => {
  res.locals.vulnMode = VULN_MODE;
  res.locals.user = req.session.user || null;
  res.locals.cart = req.session.cart || [];
  // Only expose last executed SQL queries to admin users for demo/learning.
  // Regular users should not see query text or params.
  res.locals.lastSQL = (req.session.user && req.session.user.role === 'admin') ? lastSQL : [];
  res.locals.getImagePath = getImagePath;
  // Expose whether a reset is running (either in-memory or via persistent lock)
  res.locals.resetInProgress = resetInProgress;
  // Expose confirmation phrase to views
  res.locals.resetConfirmPhrase = RESET_CONFIRM_PHRASE;
  next();
});

// Expose common UI helpers: flash message from query param and a per-session reset token
app.use((req, res, next) => {
  res.locals.msg = (req.query && req.query.msg) ? String(req.query.msg).trim() : null;
  // Ensure a per-session reset token exists (simple CSRF-like protection for the demo).
  try {
    if (!req.session.resetToken) {
      const crypto = require('crypto');
      req.session.resetToken = crypto.randomBytes(16).toString('hex');
    }
    res.locals.resetToken = req.session.resetToken;
  } catch (e) {
    res.locals.resetToken = null;
  }
  next();
});

function parseProduct(p) {
  if (!p) return p;
  return { ...p, price: parseFloat(p.price), stock: parseInt(p.stock) };
}

// Helper to log SQL for demo
function logSQL(sql, params = []) {
  const timestamp = new Date().toISOString();
  lastSQL.unshift({ sql, params, timestamp, mode: VULN_MODE });
  if (lastSQL.length > 10) lastSQL.pop(); // Keep last 10
}

// Parse SQLite timestamp ("YYYY-MM-DD HH:MM:SS" from CURRENT_TIMESTAMP)
// as UTC and return a Date. If the value already includes timezone
// information or ISO 'T', let Date handle it.
function parseSqliteTimestampAsUTC(ts) {
  if (!ts) return null;
  if (ts instanceof Date) return ts;
  if (typeof ts !== 'string') return new Date(ts);
  // If it looks like "YYYY-MM-DD HH:MM:SS" (no timezone), treat as UTC
  const simplePattern = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
  if (simplePattern.test(ts)) {
    // Convert to ISO-like UTC string so Date parses it as UTC
    return new Date(ts.replace(' ', 'T') + 'Z');
  }
  // Fallback: let Date try to parse (covers ISO strings etc.)
  return new Date(ts);
}

function formatToIST(ts) {
  const d = parseSqliteTimestampAsUTC(ts);
  if (!d || isNaN(d.getTime())) return '';
  // Use explicit components and 24-hour format (hour12: false) so output
  // is consistent like "DD/MM/YYYY, HH:MM:SS" without am/pm.
  return d.toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

// Minimal string escaper for vulnerable-mode INSERT/UPDATE to avoid syntax errors with quotes
// Note: This keeps the route "vulnerable" elsewhere (login/search/order lookup),
// but prevents breaking the SQL when admins use apostrophes in names/descriptions.
function escapeSqlString(val) {
  if (val === null || val === undefined) return '';
  return String(val).replace(/'/g, "''");
}

function generateOtpCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Hash password using bcrypt
async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

// Compare password with hash
async function comparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

function renderLogin(res, payload = {}) {
  return res.render('login', {
    error: null,
    success: null,
    otpRequired: false,
    pendingUsername: null,
    otpDebugCode: null,
    ...payload
  });
}

// Helper to write audit logs
async function logAudit(req, action, entity_type = null, entity_id = null, before_json = null, after_json = null) {
  try {
    const user_id = req.session && req.session.user ? req.session.user.id : null;
    const ip = req.ip || (req.headers && (req.headers['x-forwarded-for'] || req.connection && req.connection.remoteAddress)) || null;
    const ua = req.headers && req.headers['user-agent'] ? req.headers['user-agent'] : null;
    await run(
      'INSERT INTO audit_logs (user_id, action, entity_type, entity_id, before_json, after_json, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [user_id, action, entity_type, entity_id, before_json, after_json, ip, ua]
    );
  } catch (e) {
    console.warn('Failed to write audit log', e);
  }
}

// Home
app.get('/', async (req, res, next) => {
  try {
    // If DB hasn't finished initializing yet, return a quick "Starting" page
    // so the wrapper/browser sees a 200 response immediately instead of
    // waiting for the seeding work to finish.
    if (!dbReady) {
      return res.send(`<!doctype html><html><head><meta charset="utf-8"><title>SQLi Demo - Starting</title></head><body style="font-family:Arial,Helvetica,sans-serif;padding:24px;"><h2>SQLi Demo App</h2><p>Starting up and seeding demo data — please wait a few seconds and refresh this page.</p></body></html>`);
    }

    const sql = 'SELECT * FROM products LIMIT 6';
    logSQL(sql);
    const featuredProducts = (await all(sql)).map(parseProduct);
    res.render('index', { title: 'SQLi Demo Store', featuredProducts });
  } catch (err) {
    next(err);
  }
});

// Mode toggle
app.post('/toggle-mode', (req, res) => {
  VULN_MODE = VULN_MODE === 'on' ? 'off' : 'on';
  lastSQL = []; // Clear SQL log when switching modes
  res.redirect(req.get('Referer') || '/');
});

// Signup routes
app.get('/signup', (req, res) => {
  res.render('signup', { 
    error: null, 
    success: null, 
    verificationCode: null,
    emailSent: false,
    pendingVerification: false,
    userEmail: null,
    username: null,
    vulnerableMode: VULN_MODE === 'on'
  });
});

app.post('/signup', async (req, res, next) => {
  const { username, password, email, verificationCode } = req.body;
  
  try {
    // If verification code is provided, verify the user
    if (verificationCode) {
      const user = await get(
        'SELECT id, verification_code, verification_expires_at FROM users WHERE username = ? AND email = ?',
        [username, email]
      );
      
      if (!user) {
        return res.render('signup', {
          error: 'User not found. Please sign up first.',
          success: null,
          verificationCode: null,
          emailSent: false,
          pendingVerification: false,
          userEmail: null,
          username: null,
          vulnerableMode: VULN_MODE === 'on'
        });
      }
      
      if (user.verification_code !== verificationCode) {
        return res.render('signup', {
          error: 'Invalid verification code. Please try again.',
          success: null,
          verificationCode: null,
          emailSent: false,
          pendingVerification: true,
          userEmail: email,
          username: username,
          vulnerableMode: VULN_MODE === 'on'
        });
      }

      const verificationExpiry = parseSqliteTimestampAsUTC(user.verification_expires_at);
      if (!verificationExpiry || isNaN(verificationExpiry.getTime()) || verificationExpiry.getTime() < Date.now()) {
        return res.render('signup', {
          error: `Verification code expired. Please sign up again to receive a fresh code (valid for ${OTP_TTL_MINUTES} minutes).`,
          success: null,
          verificationCode: null,
          emailSent: false,
          pendingVerification: false,
          userEmail: null,
          username: null,
          vulnerableMode: VULN_MODE === 'on'
        });
      }
      
      // Verify the user
      await run('UPDATE users SET is_verified = 1, verification_code = NULL, verification_expires_at = NULL WHERE id = ?', [user.id]);
      
      return res.render('signup', {
        error: null,
        success: '✅ Email verified successfully! You can now login.',
        verificationCode: null,
        emailSent: false,
        pendingVerification: false,
        userEmail: null,
        username: null,
        vulnerableMode: VULN_MODE === 'on'
      });
    }
    
    // Otherwise, create new account
    // Allow reissuing verification for unverified accounts using same username/email.
    const existingUnverifiedByEmail = await get(
      'SELECT id, username FROM users WHERE email = ? AND is_verified = 0',
      [email]
    );
    if (existingUnverifiedByEmail) {
      if (existingUnverifiedByEmail.username !== username) {
        return res.render('signup', {
          error: 'This email already has a pending account with a different username. Please use the original username for verification.',
          success: null,
          verificationCode: null,
          emailSent: false,
          pendingVerification: false,
          userEmail: null,
          username: null,
          vulnerableMode: VULN_MODE === 'on'
        });
      }

      const reissuedCode = generateOtpCode();
      const reissueExpiry = new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000);
      const hashedPassword = await hashPassword(password);
      await run(
        'UPDATE users SET password = ?, password_bcrypt = ?, verification_code = ?, verification_expires_at = ? WHERE id = ?',
        [password, hashedPassword, reissuedCode, reissueExpiry, existingUnverifiedByEmail.id]
      );

      const emailSent = await sendVerificationEmail(email, username, reissuedCode, OTP_TTL_MINUTES);
      return res.render('signup', {
        error: null,
        success: emailSent
          ? `Verification code re-sent to ${email}. It expires in ${OTP_TTL_MINUTES} minutes.`
          : 'Verification code regenerated. Email sending is not configured.',
        verificationCode: emailSent ? null : reissuedCode,
        emailSent: emailSent,
        pendingVerification: true,
        userEmail: email,
        username: username,
        vulnerableMode: VULN_MODE === 'on'
      });
    }

    // Check if username already exists
    const existingUsername = await get('SELECT id FROM users WHERE username = ?', [username]);
    if (existingUsername) {
      return res.render('signup', {
        error: 'Username already exists',
        success: null,
        verificationCode: null,
        emailSent: false,
        pendingVerification: false,
        userEmail: null,
        username: null,
        vulnerableMode: VULN_MODE === 'on'
      });
    }

    // Check if email already exists
    const existingEmail = await get('SELECT id FROM users WHERE email = ?', [email]);
    if (existingEmail) {
      return res.render('signup', {
        error: 'Email already registered. Please use a different email or login.',
        success: null,
        verificationCode: null,
        emailSent: false,
        pendingVerification: false,
        userEmail: null,
        username: null,
        vulnerableMode: VULN_MODE === 'on'
      });
    }
    
    // Generate 6-digit verification code
    const newVerificationCode = generateOtpCode();
    const verificationExpiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000);
    
    // Hash password before storing
    const hashedPassword = await hashPassword(password);
    
    // Insert new user with both plaintext (for vulnerable mode) and bcrypt hash (for secure mode)
    await run(
      'INSERT INTO users (username, password, password_bcrypt, role, email, is_verified, verification_code, verification_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [username, password, hashedPassword, 'user', email, 0, newVerificationCode, verificationExpiresAt]
    );
    
    // Send verification email
    const emailSent = await sendVerificationEmail(email, username, newVerificationCode, OTP_TTL_MINUTES);
    
    res.render('signup', { 
      error: null, 
      success: emailSent 
        ? `Account created! We've sent a 6-digit verification code to ${email}. It expires in ${OTP_TTL_MINUTES} minutes.`
        : 'Account created! Email sending is not configured.',
      verificationCode: emailSent ? null : newVerificationCode,
      emailSent: emailSent,
      pendingVerification: true,
      userEmail: email,
      username: username,
      vulnerableMode: VULN_MODE === 'on'
    });
  } catch (err) {
    next(err);
  }
});


// Login routes
app.get('/login', (req, res) => {
  res.render('login', {
    error: null,
    success: null,
    otpRequired: false,
    pendingUsername: null,
    otpDebugCode: null
  });
});

app.post('/login', async (req, res, next) => {
  const { username, password } = req.body;
  try {
    let user;
    if (VULN_MODE === 'on') {
      // Intentionally vulnerable: string concatenation with unsanitized inputs on both username and password
      const sql = "SELECT id, username, role, email, is_verified, password, password_bcrypt FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
      logSQL(sql);
      const rows = await rawQuery(sql);
      user = rows[0] || null;
    } else {
      // Secure mode: parameterized query with bcrypt password verification
      const sql = 'SELECT id, username, role, email, is_verified, password_bcrypt FROM users WHERE username = ?';
      logSQL(sql, [username]);
      user = await get(sql, [username]);
      
      // Verify password with bcrypt if user exists
      if (user) {
        const passwordMatch = await comparePassword(password, user.password_bcrypt);
        if (!passwordMatch) {
          user = null; // Mark as invalid
        }
      }
    }

    if (user) {
      // Check if email is verified
      if (!user.is_verified) {
        return res.status(401).render('login', {
          error: 'Please verify your email before logging in. Check your email for the verification code or go back to the signup page.',
          success: null,
          otpRequired: false,
          pendingUsername: null,
          otpDebugCode: null
        });
      }

      if (LOGIN_OTP_REQUIRED) {
        const otpCode = generateOtpCode();
        const otpExpiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000);
        await run('UPDATE users SET login_otp_code = ?, login_otp_expires_at = ? WHERE id = ?', [otpCode, otpExpiresAt, user.id]);
        const otpSent = await sendLoginOTPEmail(user.email, user.username, otpCode, OTP_TTL_MINUTES);

        req.session.pendingLogin = {
          userId: user.id,
          username: user.username,
          email: user.email
        };

        await logAudit(req, 'LOGIN_OTP_SENT', 'user', user.id, null, JSON.stringify({ otpSent }));

        return renderLogin(res, {
          success: otpSent
            ? `A login OTP has been sent to ${user.email}. It expires in ${OTP_TTL_MINUTES} minutes.`
            : 'Email sending is not configured. Use the OTP shown below for demo purposes.',
          otpRequired: true,
          pendingUsername: user.username,
          otpDebugCode: otpSent ? null : otpCode
        });
      }
      
      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
        email: user.email,
        is_verified: user.is_verified
      };
      delete req.session.pendingLogin;
      if (!req.session.cart) req.session.cart = [];
      await logAudit(req, 'LOGIN_SUCCESS', 'user', user.id, null, null);
      return res.redirect('/products');
    }
    delete req.session.pendingLogin;
    await logAudit(req, 'LOGIN_FAIL', 'user', null, null, JSON.stringify({ username }));
    return res.status(401).render('login', {
      error: 'Invalid credentials',
      success: null,
      otpRequired: false,
      pendingUsername: null,
      otpDebugCode: null
    });
  } catch (err) {
    return next(err);
  }
});

app.post('/login/verify-otp', async (req, res, next) => {
  const { otpCode } = req.body;
  const pendingLogin = req.session.pendingLogin;

  if (!pendingLogin || !pendingLogin.userId) {
    return renderLogin(res, {
      error: 'Your login OTP session expired. Please login again.',
      otpRequired: false
    });
  }

  try {
    const user = await get(
      'SELECT id, username, role, email, is_verified, login_otp_code, login_otp_expires_at FROM users WHERE id = ?',
      [pendingLogin.userId]
    );

    if (!user || !user.is_verified) {
      delete req.session.pendingLogin;
      return renderLogin(res, {
        error: 'Unable to verify OTP. Please login again.',
        otpRequired: false
      });
    }

    const otpExpiry = parseSqliteTimestampAsUTC(user.login_otp_expires_at);
    if (!otpExpiry || isNaN(otpExpiry.getTime()) || otpExpiry.getTime() < Date.now()) {
      delete req.session.pendingLogin;
      await run('UPDATE users SET login_otp_code = NULL, login_otp_expires_at = NULL WHERE id = ?', [user.id]);
      return renderLogin(res, {
        error: `OTP expired. Please login again to get a new code (valid for ${OTP_TTL_MINUTES} minutes).`,
        otpRequired: false
      });
    }

    if (!otpCode || String(otpCode).trim() !== String(user.login_otp_code)) {
      return renderLogin(res, {
        error: 'Invalid OTP. Please try again.',
        otpRequired: true,
        pendingUsername: pendingLogin.username
      });
    }

    await run('UPDATE users SET login_otp_code = NULL, login_otp_expires_at = NULL WHERE id = ?', [user.id]);

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      email: user.email,
      is_verified: user.is_verified
    };
    delete req.session.pendingLogin;
    if (!req.session.cart) req.session.cart = [];
    await logAudit(req, 'LOGIN_SUCCESS', 'user', user.id, null, JSON.stringify({ viaOtp: true }));
    return res.redirect('/products');
  } catch (err) {
    return next(err);
  }
});

app.post('/login/resend-otp', async (req, res, next) => {
  const pendingLogin = req.session.pendingLogin;
  if (!pendingLogin || !pendingLogin.userId) {
    return renderLogin(res, {
      error: 'No active OTP flow found. Please login again.',
      otpRequired: false
    });
  }

  try {
    const user = await get('SELECT id, username, email, is_verified FROM users WHERE id = ?', [pendingLogin.userId]);
    if (!user || !user.is_verified) {
      delete req.session.pendingLogin;
      return renderLogin(res, {
        error: 'Unable to resend OTP. Please login again.',
        otpRequired: false
      });
    }

    const otpCode = generateOtpCode();
    const otpExpiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000);
    await run('UPDATE users SET login_otp_code = ?, login_otp_expires_at = ? WHERE id = ?', [otpCode, otpExpiresAt, user.id]);
    const otpSent = await sendLoginOTPEmail(user.email, user.username, otpCode, OTP_TTL_MINUTES);

    return renderLogin(res, {
      success: otpSent
        ? `A new OTP has been sent to ${user.email}. It expires in ${OTP_TTL_MINUTES} minutes.`
        : 'Email sending is not configured. Use the OTP shown below for demo purposes.',
      otpRequired: true,
      pendingUsername: user.username,
      otpDebugCode: otpSent ? null : otpCode
    });
  } catch (err) {
    return next(err);
  }
});

app.post('/logout', (req, res) => {
  delete req.session.pendingLogin;
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// Products list + search
app.get('/products', async (req, res, next) => {
  const q = (req.query.q || '').trim();
  const category = req.query.category || '';
  try {
    let products;
    if (!q && !category) {
      const sql = 'SELECT id, name, price, image_url, category, stock FROM products ORDER BY id';
      logSQL(sql);
      products = (await all(sql, [])).map(parseProduct);
    } else if (category && !q) {
      // Filter by category only
      if (VULN_MODE === 'on') {
        const sql = "SELECT id, name, price, image_url, category, stock FROM products WHERE category = '" + category + "' ORDER BY id";
        logSQL(sql);
        products = await rawQuery(sql);
      } else {
        const sql = 'SELECT id, name, price, image_url, category, stock FROM products WHERE category = ? ORDER BY id';
        logSQL(sql, [category]);
        products = await all(sql, [category]);
      }
    } else if (category && q) {
      // Filter by BOTH category and search term
      if (VULN_MODE === 'on') {
        // Vulnerable concatenation still respects category filter
        const sql = "SELECT id, name, price, image_url, category, stock FROM products WHERE category = '" + category + "' AND name LIKE '%" + q + "%' ORDER BY id";
        logSQL(sql);
        products = await rawQuery(sql);
      } else {
        const sql = 'SELECT id, name, price, image_url, category, stock FROM products WHERE category = ? AND name LIKE ? ORDER BY id';
        const params = [category, `%${q}%`];
        logSQL(sql, params);
        products = await all(sql, params);
      }
    } else {
      // Search term only
      if (VULN_MODE === 'on') {
        // Vulnerable LIKE with unsanitized input
        const sql = "SELECT id, name, price, image_url, category, stock FROM products WHERE name LIKE '%" + q + "%' ORDER BY id";
        logSQL(sql);
        products = await rawQuery(sql);
      } else {
        const sql = 'SELECT id, name, price, image_url, category, stock FROM products WHERE name LIKE ? ORDER BY id';
        logSQL(sql, [`%${q}%`]);
        products = await all(sql, [`%${q}%`]);
      }
    }
    const categories = await all('SELECT DISTINCT category FROM products ORDER BY category');
    res.render('products', { products, q, category, categories });
  } catch (err) {
    next(err);
  }
});

// Admin: create product form
app.get('/admin/products/new', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Only admin');
  res.render('product-edit', { mode: 'create', product: null, error: null });
});

// Admin: edit product form
app.get('/admin/products/:id/edit', async (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Only admin');
  try {
    const product = await get('SELECT * FROM products WHERE id = ?', [req.params.id]);
    if (!product) return res.status(404).send('Product not found');
    res.render('product-edit', { mode: 'edit', product, error: null });
  } catch (e) { next(e); }
});

// Admin: create product submit
app.post('/admin/products', async (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Only admin');
  const { name, description, price, image_url, category, stock } = req.body;
  try {
    let sql, params;
    if (VULN_MODE === 'on') {
      // Escape single quotes to avoid SQL syntax errors on apostrophes
      const n = escapeSqlString(name);
      const d = escapeSqlString(description);
      const img = escapeSqlString(image_url);
      const normalizedCategory = (category || '').trim();
      const cat = escapeSqlString(normalizedCategory);
      sql = `INSERT INTO products (name, description, price, image_url, category, stock) VALUES ('${n}', '${d}', ${parseFloat(price)||0}, '${img}', '${cat}', ${parseInt(stock)||0})`;
      logSQL(sql);
      const result = await run(sql);
      await logAudit(req, 'PRODUCT_CREATE', 'product', result.lastID, null, JSON.stringify({ name, price, category: normalizedCategory }));
    } else {
      sql = 'INSERT INTO products (name, description, price, image_url, category, stock) VALUES (?, ?, ?, ?, ?, ?)';
      const normalizedCategory = (category || '').trim();
      params = [name, description, parseFloat(price)||0, image_url, normalizedCategory, parseInt(stock)||0];
      logSQL(sql, params);
      const result = await run(sql, params);
      await logAudit(req, 'PRODUCT_CREATE', 'product', result.lastID, null, JSON.stringify({ name, price, category: normalizedCategory }));
    }
    res.redirect('/admin?msg=' + encodeURIComponent('Product created'));
  } catch (e) {
    next(e);
  }
});

// Admin: update product
app.post('/admin/products/:id', async (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Only admin');
  const { name, description, price, image_url, category, stock } = req.body;
  const id = parseInt(req.params.id, 10);
  const normalizedCategory = (category || '').trim();
  try {
    const before = await get('SELECT * FROM products WHERE id = ?', [id]);
    if (!before) return res.status(404).send('Product not found');
    let sql, params;
    if (VULN_MODE === 'on') {
      // Escape single quotes to avoid SQL syntax errors on apostrophes
      const n = escapeSqlString(name);
      const d = escapeSqlString(description);
      const img = escapeSqlString(image_url);
      const cat = escapeSqlString(normalizedCategory);
      sql = `UPDATE products SET name='${n}', description='${d}', price=${parseFloat(price)||0}, image_url='${img}', category='${cat}', stock=${parseInt(stock)||0} WHERE id=${id}`;
      logSQL(sql);
      await run(sql);
    } else {
      sql = 'UPDATE products SET name=?, description=?, price=?, image_url=?, category=?, stock=? WHERE id=?';
      params = [name, description, parseFloat(price)||0, image_url, normalizedCategory, parseInt(stock)||0, id];
      logSQL(sql, params);
      await run(sql, params);
    }
    const after = await get('SELECT * FROM products WHERE id = ?', [id]);
    await logAudit(req, 'PRODUCT_UPDATE', 'product', id, JSON.stringify(before), JSON.stringify(after));
    res.redirect('/admin?msg=' + encodeURIComponent('Product updated'));
  } catch (e) { next(e); }
});

// Product detail
app.get('/product/:id', async (req, res, next) => {
  const id = req.params.id;
  try {
    let product;
    if (VULN_MODE === 'on') {
      // Vulnerable: direct concatenation into WHERE clause
      const sql = 'SELECT id, name, description, price, image_url, category, stock FROM products WHERE id = ' + id + ' LIMIT 1';
      logSQL(sql);
      const rows = await rawQuery(sql);
      product = rows[0] || null;
    } else {
      const sql = 'SELECT id, name, description, price, image_url, category, stock FROM products WHERE id = ? LIMIT 1';
      logSQL(sql, [id]);
      product = await get(sql, [id]);
    }
    if (!product) return res.status(404).send('Product not found');
    res.render('product', { product });
  } catch (err) {
    next(err);
  }
});

// Cart routes
app.post('/cart/add', async (req, res, next) => {
  const { product_id, quantity } = req.body;
  try {
    const sql = 'SELECT id, name, price, image_url FROM products WHERE id = ?';
    const product = await get(sql, [product_id]);
    if (!product) return res.status(404).send('Product not found');
    
    if (!req.session.cart) req.session.cart = [];
    const existing = req.session.cart.find(item => item.id === product.id);
    if (existing) {
      existing.quantity += parseInt(quantity) || 1;
    } else {
      req.session.cart.push({ ...product, price: parseFloat(product.price), quantity: parseInt(quantity) || 1 });
    }
    res.redirect('/cart');
  } catch (err) {
    next(err);
  }
});

app.get('/cart', (req, res) => {
  const cart = req.session.cart || [];
  const total = cart.reduce((sum, item) => sum + (parseFloat(item.price) * item.quantity), 0);
  res.render('cart', { cart, total });
});

app.post('/cart/remove/:id', (req, res) => {
  const id = parseInt(req.params.id);
  if (req.session.cart) {
    req.session.cart = req.session.cart.filter(item => item.id !== id);
  }
  res.redirect('/cart');
});

app.post('/cart/update/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const quantity = parseInt(req.body.quantity) || 1;
  if (req.session.cart) {
    const item = req.session.cart.find(item => item.id === id);
    if (item) item.quantity = quantity;
  }
  res.redirect('/cart');
});

// Checkout
app.get('/checkout', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const cart = req.session.cart || [];
  if (cart.length === 0) return res.redirect('/cart');
  const total = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
  res.render('checkout', { cart, total });
});

app.post('/checkout', async (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  const { card_number, card_holder, expiry, cvv } = req.body;
  const cart = req.session.cart || [];
  if (cart.length === 0) return res.redirect('/cart');
  
  try {
    // 1. Validate stock for each cart item
    for (const item of cart) {
      const productRow = await get('SELECT stock FROM products WHERE id = ?', [item.id]);
      if (!productRow) {
        return res.status(400).send('Product not found during checkout');
      }
      if (productRow.stock < item.quantity) {
        return res.status(400).send(`Insufficient stock for product ID ${item.id}. Available: ${productRow.stock}, Requested: ${item.quantity}`);
      }
    }

    // 2. Calculate total
    const total = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    // 3. Create order
    const orderResult = await run(
      'INSERT INTO orders (user_id, total, status) VALUES (?, ?, ?)',
      [req.session.user.id, total, 'completed']
    );

    // 4. Add order items & decrement stock
    for (const item of cart) {
      await run(
        'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
        [orderResult.lastID, item.id, item.quantity, item.price]
      );
      // Decrement stock safely (never below zero)
      await run('UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?', [item.quantity, item.id, item.quantity]);
    }

    // 5. Save payment method (insecure storage - demo only)
    await run(
      'INSERT INTO payment_methods (user_id, card_number, card_holder, expiry, cvv) VALUES (?, ?, ?, ?, ?)',
      [req.session.user.id, card_number, card_holder, expiry, cvv]
    );

    // 6. Clear cart & redirect to order detail
    req.session.cart = [];
    await logAudit(req, 'ORDER_CREATE', 'order', orderResult.lastID, null, JSON.stringify({ total, items: cart }));
    res.redirect('/orders/' + orderResult.lastID);
  } catch (err) {
    next(err);
  }
});

// Order lookup (vulnerable)
app.get('/orders', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  (async () => {
    try {
      // Fetch recent orders for the logged-in user
      const sql = 'SELECT o.id, o.total, o.status, o.created_at, u.username FROM orders o JOIN users u ON o.user_id = u.id WHERE o.user_id = ? ORDER BY o.created_at DESC';
      logSQL(sql, [req.session.user.id]);
      const orders = await all(sql, [req.session.user.id]);
      // Format created_at to IST for display
      const ordersFormatted = orders.map(o => ({ ...o, created_at_local: formatToIST(o.created_at) }));
      res.render('orders', { orders: ordersFormatted, order_id: '', demo_message: '' });
    } catch (err) {
      res.render('orders', { orders: [], order_id: '', demo_message: '' });
    }
  })();
});

app.post('/orders/lookup', async (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  const { order_id } = req.body;
  try {
    // Behavior depends on VULN_MODE: in vulnerable mode allow SQL injection
    // via direct concatenation (educational). In secure mode, use a
    // parameterized query and enforce ownership.
    if (VULN_MODE === 'on') {
      // In vulnerable demo mode we only want to demonstrate *real* SQL injection
      // attempts. Plain numeric lookups are normal behaviour and not an
      // injection — so we reject simple numeric input here and ask the
      // user to provide an injection-style payload (e.g. "0 OR 1=1").
      let s = (order_id || '').trim();
      // MySQL treats -- as a comment only with a trailing space. Normalise.
      s = s.replace(/--(?!\s)/g, '-- ');
      const injectionMustContain = /\b(or|union)\b|--|\/\*/i;
      if (!injectionMustContain.test(s)) {
        return res.render('orders', { orders: [], order_id: s, demo_message: 'Try a payload like:  0 OR 1=1  or  0 UNION SELECT id,total,status,created_at,username FROM orders o JOIN users u ON o.user_id=u.id --' });
      }
      let sql;
      if (s.includes("'") || s.includes('"')) {
        sql = "SELECT o.id, o.total, o.status, o.created_at, u.username FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = '" + s + "'";
      } else {
        sql = 'SELECT o.id, o.total, o.status, o.created_at, u.username FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = ' + s;
      }
      logSQL(sql);
      const orders = await rawQuery(sql);
      const ordersFormatted = orders.map(o => ({ ...o, created_at_local: formatToIST(o.created_at) }));
      return res.render('orders', { orders: ordersFormatted, order_id: s, demo_message: '' });
    } else {
      const oid = parseInt(order_id, 10);
      if (isNaN(oid)) {
        return res.render('orders', { orders: [], order_id, demo_message: '' });
      }
      const sql = 'SELECT o.id, o.total, o.status, o.created_at, u.username FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = ? AND o.user_id = ?';
      logSQL(sql, [oid, req.session.user.id]);
      const orders = await all(sql, [oid, req.session.user.id]);
      const ordersFormatted = orders.map(o => ({ ...o, created_at_local: formatToIST(o.created_at) }));
      return res.render('orders', { orders: ordersFormatted, order_id, demo_message: '' });
    }
  } catch (err) {
    next(err);
  }
});

// SQLi demo endpoint: behaves vulnerably when VULN_MODE === 'on', safely otherwise.
app.post('/orders/sqli', async (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  const { sqli_q } = req.body;
  try {
    if (VULN_MODE === 'on') {
      // Intentionally vulnerable: user input is concatenated into WHERE clause.
      // This demonstrates SQL injection: e.g., '1 OR 1=1' will return all orders.
      const sql = 'SELECT o.id, o.total, o.status, o.created_at, u.username FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = ' + (sqli_q || '0');
      logSQL(sql);
      const orders = await rawQuery(sql);
      const ordersFormatted = orders.map(o => ({ ...o, created_at_local: formatToIST(o.created_at) }));
      return res.render('orders', { orders: ordersFormatted, order_id: sqli_q || '', demo_message: '' });
    } else {
      // Safe mode: parameterized query and enforce ownership
      const oid = parseInt(sqli_q, 10);
      if (isNaN(oid)) return res.render('orders', { orders: [], order_id: sqli_q || '', demo_message: '' });
      const sql = 'SELECT o.id, o.total, o.status, o.created_at, u.username FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = ? AND o.user_id = ?';
      logSQL(sql, [oid, req.session.user.id]);
      const orders = await all(sql, [oid, req.session.user.id]);
      const ordersFormatted = orders.map(o => ({ ...o, created_at_local: formatToIST(o.created_at) }));
      return res.render('orders', { orders: ordersFormatted, order_id: String(oid), demo_message: '' });
    }
  } catch (err) {
    next(err);
  }
});

app.get('/orders/:id', async (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  const id = req.params.id;
  try {
    let order;
    // Enforce that users can only view their own orders
    const oid = parseInt(id, 10);
    if (isNaN(oid)) return res.status(404).send('Order not found');
    const sql = 'SELECT * FROM orders WHERE id = ? AND user_id = ?';
    logSQL(sql, [oid, req.session.user.id]);
    order = await get(sql, [oid, req.session.user.id]);
    
    if (!order) return res.status(404).send('Order not found');
    
    const items = await all(
      'SELECT oi.*, p.name, p.image_url FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?',
      [order.id]
    );
    // Add localized timestamp
    order.created_at_local = formatToIST(order.created_at);
    res.render('order-detail', { order, items });
  } catch (err) {
    next(err);
  }
});

// Admin page
app.get('/admin', async (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Only admin can view this page');
  try {
    const userCount = await get('SELECT COUNT(*) as c FROM users');
    const productCount = await get('SELECT COUNT(*) as c FROM products');
    const orderCount = await get('SELECT COUNT(*) as c FROM orders');
    const recentOrders = await all('SELECT o.id, o.total, o.status, o.created_at, u.username FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC LIMIT 5');
    const products = await all('SELECT id, name, price, image_url, category, stock FROM products ORDER BY id');
    const msg = (req.query.msg || '').trim();
    const audits = await all('SELECT a.id, a.action, a.entity_type, a.entity_id, a.created_at, u.username FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.id DESC LIMIT 15');
    res.render('admin', { stats: { users: userCount.c, products: productCount.c, orders: orderCount.c }, recentOrders, products, msg, audits });
  } catch (err) {
    next(err);
  }
});

// Admin: increase stock
app.post('/admin/stock', async (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  // Optional: restrict to admin role only
  if (req.session.user.role !== 'admin') {
    return res.status(403).send('Only admin can update stock');
  }
  const { product_id, amount, action } = req.body;
  const pid = parseInt(product_id, 10);
  const qty = parseInt(amount, 10);
  const act = (action || 'add').toLowerCase();
  if (!pid || (isNaN(qty) && act !== 'set')) {
    return res.redirect('/admin?msg=' + encodeURIComponent('Invalid product or amount'));
  }
  try {
    let sql, params;
    const beforeRow = await get('SELECT id, stock FROM products WHERE id = ?', [pid]);
    if (act === 'add') {
      if (!qty || qty <= 0) return res.redirect('/admin?msg=' + encodeURIComponent('Amount must be > 0'));
      if (VULN_MODE === 'on') {
        sql = `UPDATE products SET stock = stock + ${qty} WHERE id = ${pid}`;
        logSQL(sql);
        await run(sql);
      } else {
        sql = 'UPDATE products SET stock = stock + ? WHERE id = ?';
        params = [qty, pid];
        logSQL(sql, params);
        await run(sql, params);
      }
      const afterRow = await get('SELECT id, stock FROM products WHERE id = ?', [pid]);
      await logAudit(req, 'STOCK_ADD', 'product', pid, JSON.stringify(beforeRow), JSON.stringify(afterRow));
    } else if (act === 'remove') {
      if (!qty || qty <= 0) return res.redirect('/admin?msg=' + encodeURIComponent('Amount must be > 0'));
      if (VULN_MODE === 'on') {
        // Prevent negative stock using CASE
        sql = `UPDATE products SET stock = CASE WHEN stock - ${qty} < 0 THEN 0 ELSE stock - ${qty} END WHERE id = ${pid}`;
        logSQL(sql);
        await run(sql);
      } else {
        sql = 'UPDATE products SET stock = CASE WHEN stock - ? < 0 THEN 0 ELSE stock - ? END WHERE id = ?';
        params = [qty, qty, pid];
        logSQL(sql, params);
        await run(sql, params);
      }
      const afterRow = await get('SELECT id, stock FROM products WHERE id = ?', [pid]);
      await logAudit(req, 'STOCK_REMOVE', 'product', pid, JSON.stringify(beforeRow), JSON.stringify(afterRow));
    } else if (act === 'set') {
      const val = parseInt(amount, 10);
      if (isNaN(val) || val < 0) return res.redirect('/admin?msg=' + encodeURIComponent('Stock must be >= 0'));
      if (VULN_MODE === 'on') {
        sql = `UPDATE products SET stock = ${val} WHERE id = ${pid}`;
        logSQL(sql);
        await run(sql);
      } else {
        sql = 'UPDATE products SET stock = ? WHERE id = ?';
        params = [val, pid];
        logSQL(sql, params);
        await run(sql, params);
      }
      const afterRow = await get('SELECT id, stock FROM products WHERE id = ?', [pid]);
      await logAudit(req, 'STOCK_SET', 'product', pid, JSON.stringify(beforeRow), JSON.stringify(afterRow));
    }
    return res.redirect('/admin?msg=' + encodeURIComponent('Stock updated'));
  } catch (err) {
    next(err);
  }
});

// Reset DB (for demo). Optional key check to avoid accidental resets.
app.post('/reset-db', async (req, res, next) => {
  // Only allow logged-in admin users to reset the demo database
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Only admin can reset the database');

  // Validate per-session reset token to reduce accidental/CSRF resets
  const provided = (req.body && req.body.reset_token) ? String(req.body.reset_token) : null;
  if (!provided || !req.session.resetToken || provided !== req.session.resetToken) {
    console.warn('Reset DB attempt with invalid or missing reset_token');
    return res.status(403).send('Invalid reset token');
  }

  try {
    if (resetInProgress) {
      console.warn('Reset already in progress; ignoring concurrent request');
      return res.redirect('/admin?msg=' + encodeURIComponent('Reset already in progress'));
    }
    const providedPhrase = (req.body && req.body.confirm_phrase) ? String(req.body.confirm_phrase).trim() : '';
    if (providedPhrase !== RESET_CONFIRM_PHRASE) {
      console.warn('Reset DB attempt with incorrect confirmation phrase');
      return res.redirect('/admin?msg=' + encodeURIComponent('Invalid confirmation phrase'));
    }

    resetInProgress = true;
    try {
      await reset();
    } finally {
      resetInProgress = false;
    }
    try { await logAudit(req, 'DB_RESET', 'database', null, null, JSON.stringify({ note: 'Reset performed' })); } catch (e) { console.warn('Failed to write DB reset audit', e); }
    res.redirect('/?msg=' + encodeURIComponent('Database reset completed'));
  } catch (err) {
    console.error('Reset DB failed', err);
    res.redirect('/admin?msg=' + encodeURIComponent('Reset failed — check server logs'));
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Internal Server Error');
});

// Start the HTTP server first so the wrapper/browser can connect immediately.
// Then run DB initialization/seeding in the background and mark `dbReady`
// when complete. This avoids long delays where the wrapper waits for the
// process to open a listening socket.
(async () => {
  // Bind explicitly to 127.0.0.1 to avoid interface binding ambiguities on Windows
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`SQLi Demo running on http://localhost:${PORT} (mode: ${VULN_MODE})`);
    console.log('Server listening; starting DB initialization in background...');
  });

  try {
    await init();
    dbReady = true;
    console.log('DB initialization complete; application ready');
  } catch (e) {
    console.error('DB initialization failed', e);
  }
})();
