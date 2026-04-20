# 🛡️ SQLi Demo Store (Education Only)

A fully-featured e-commerce application built to demonstrate **SQL Injection (SQLi)** vulnerabilities and their prevention. Features a toggleable vulnerable/secure mode, real-time SQL query visualization, shopping cart, checkout, and order management.

⚠️ **WARNING:** For local, educational use only. Do not expose to the internet or deploy to production.

## ✨ Features

- 🔄 **Toggle Mode:** Switch between vulnerable and secure mode in real-time
- 🛒 **Shopping Cart:** Full cart functionality with add/remove/update
- 💳 **Checkout System:** Payment form with intentionally vulnerable order lookup
- 📦 **Order Management:** View order history with SQLi-vulnerable queries
- 🔍 **SQL Visualization:** See executed queries in real-time at the bottom of each page
- 🖼️ **Product Images:** Visual catalog with images from Unsplash
- 📊 **Admin Dashboard:** Statistics and recent orders overview
- 🎨 **Modern UI:** Responsive design with gradients and smooth animations
- 📝 **User Signup:** Create new accounts with username, email, and password
- ✉️ **Email Verification:** Real SMTP email sending for account verification
- 👥 **Multi-user Support:** Multiple users can create accounts and place orders
- 💾 **Persistent Data:** User accounts and orders saved permanently across restarts

## Stack

- Node.js + Express
- SQLite (file DB)
- EJS templates

## Quick start (Windows PowerShell)

1) Install Node.js (v18+ recommended): https://nodejs.org/

2) Install dependencies:

```powershell
npm install
```

3) Configure email verification (optional but recommended):

Edit `.env` file and set your SMTP credentials:

```
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
```

**For Gmail:**
- Go to https://myaccount.google.com/apppasswords
- Generate a new App Password (requires 2FA enabled)
- Use that 16-character password in `EMAIL_PASS`

**For other providers:**
- Outlook: `EMAIL_HOST=smtp-mail.outlook.com`
- Yahoo: `EMAIL_HOST=smtp.mail.yahoo.com` and `EMAIL_PORT=465`
- Custom SMTP: Set all `EMAIL_*` variables accordingly

**Note:** If email is not configured, verification codes will be displayed on screen as fallback.

4) Initialize (or reset) the database:

```powershell
# Create tables and seed if empty
npm run seed

# OR drop and re-seed
npm run reset-db
```

5) Run the app:

```powershell
# Vulnerable mode (default)
npm start

# Safe mode
$env:VULN_MODE="off"; npm start
```

Visit http://localhost:3000

## 🖼️ Adding Product Images

Product images are stored locally in `public/images/products/`. To add your own images:

1. Place image files in the `public/images/products/` folder
2. Name them to match the product names (extension doesn't matter!):
   - `red-t-shirt` (add .png, .jpg, .jpeg, .webp, or .gif)
   - `blue-jeans`
   - `sneakers`
   - `hoodie`
   - `socks`
   - `baseball-cap`
   - `backpack`
   - `sunglasses`
   - `watch`
   - `leather-wallet`
   - `running-shoes`
   - `winter-jacket`

3. Supported formats: PNG, JPG, JPEG, WebP, GIF (automatically detected!)
4. Recommended size: 800x600px (or similar 4:3 ratio)
5. If an image is missing, a placeholder will be shown

**Example:** Both `red-t-shirt.png` and `red-t-shirt.jpg` work perfectly!**Note:** The app uses local images instead of external URLs for better control and offline functionality.

## 🎯 SQLi Attack Scenarios

### 1. Authentication Bypass (Login)
**Vulnerable Mode:**
- Username: `' OR '1'='1`
- Password: anything
- **Result:** Logs in as the first user (admin) without valid credentials
- **Alternative:** Username: `admin' --`, Password: anything

### 2. Product Search Injection
**Vulnerable Mode:**
- Search: `%' OR '1'='1`
- **Result:** Returns all products regardless of search term
- **Try:** `%' UNION SELECT id, name, price, NULL, NULL, NULL FROM products --`

### 3. Product ID Tampering
**Vulnerable Mode:**
- Visit `/product/1 OR 1=1`
- **Result:** May return unexpected data
- **Try:** `/product/1 UNION SELECT id,username,password,email,NULL,NULL,NULL FROM users LIMIT 1 --`

### 4. Order Lookup Exploitation
**Vulnerable Mode:**
- Order ID: `1 OR 1=1`
- **Result:** See ALL orders in the system (bypassing user ownership)
- **Try:** `1 UNION SELECT id, username, password, email, created_at, NULL FROM users --`

### 5. Category Filter Bypass
**Vulnerable Mode:**
- Category: `Clothing' OR '1'='1`
- **Result:** Returns all products

**Secure Mode:** Toggle to safe mode and try the same attacks—they won't work because queries use parameterized statements.

## 📁 Project Structure

```
server.js                      # Express app with all routes
src/db.js                      # SQLite connection, schema, seed data
scripts/seed.js                # DB initialization script
views/
  ├── index.ejs                # Home page with featured products
  ├── login.ejs                # Login form (SQLi vulnerable)
  ├── products.ejs             # Product catalog with search/filters
  ├── product.ejs              # Product detail page
  ├── cart.ejs                 # Shopping cart
  ├── checkout.ejs             # Payment form
  ├── orders.ejs               # Order lookup (SQLi vulnerable)
  ├── order-detail.ejs         # Order details
  ├── admin.ejs                # Admin dashboard
  └── partials/
      ├── header.ejs           # Header with mode toggle
      └── footer.ejs           # Footer with SQL demo panel
public/styles.css              # Modern styling with gradients
.env                           # Config (VULN_MODE, PORT, etc.)
data/app.db                    # SQLite database (auto-created)
```

## 🗃️ Database Schema

- **users:** id, username, password (plaintext), password_bcrypt (bcrypt hashed), role, email, is_verified
- **products:** id, name, description, price, image_url, category, stock
- **orders:** id, user_id, total, status, created_at
- **order_items:** id, order_id, product_id, quantity, price
- **payment_methods:** id, user_id, card_number, card_holder, expiry, cvv (insecure for demo)
- **audit_logs:** id, user_id, action, entity_type, entity_id, timestamps, etc.

**Note on passwords:** Both `password` (plaintext) and `password_bcrypt` (bcrypt hashed) are stored:
- **VULN_MODE=on**: Login query uses `password` field with string concatenation → SQLi vulnerable on both username AND password
- **VULN_MODE=off**: Login uses parameterized queries + bcrypt verification on `password_bcrypt` field

## 🎓 Learning Objectives

This demo teaches:

1. **How SQL Injection Works:** See real SQL queries being executed with user input concatenated directly
2. **Attack Vectors:** Login bypass, data extraction, UNION-based attacks, comment-based bypasses
3. **Prevention Techniques:** Parameterized queries, input validation, least privilege
4. **Secure vs Insecure Code:** Toggle between modes to see the exact code differences

## ⚠️ Security Warnings

This application intentionally contains multiple severe security vulnerabilities **(in vulnerable mode)**:

- ❌ Direct SQL concatenation with user input (SQLi vulnerable in VULN_MODE=on)
- ❌ No input validation or sanitization (in vulnerable mode)
- ❌ Plaintext password storage (password field, demo only)
- ❌ Payment data stored unencrypted
- ❌ No rate limiting or brute force protection
- ❌ No HTTPS/TLS encryption

**Security Features (both modes):**
- ✅ Parameterized queries in SECURE_MODE prevent SQLi
- ✅ Bcrypt password hashing in SECURE_MODE
- ✅ Comment-based SQLi bypass (`admin' --`) in VULN_MODE
- ✅ Full SQLi demo in vulnerable mode (both username and password exploitable)

**DO NOT:**
- Deploy to production
- Use on a public network
- Store real user data
- Use real payment information
- Copy these patterns into real applications

## 📚 Resources

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

## 🤝 Contributing

This is an educational project. Feel free to add more attack scenarios or improve the demonstrations!

## Run locally

- Quick start (Windows PowerShell):

```powershell
cd "C:\Users\Dewang\Downloads\SQLi Demo App"
.\start.bat
```

- Notes:
   - `start.bat` invokes `start.ps1` (PowerShell wrapper) to perform robust launch steps.
   - The wrapper detects an existing `node.exe` running `server.js` and reuses it to avoid duplicates, writes `server.pid`, and redirects logs to `server.out.log` / `server.err.log` and merges them into `server.log`.
   - If your Node installation is not at `D:\NodeJS\node.exe`, edit the `NodeExe` variable at the top of `start.ps1`.

Use the Desktop Start shortcut (if present) for one‑click launches.
