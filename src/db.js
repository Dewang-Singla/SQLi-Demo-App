const mysql = require('mysql2/promise');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

let pool = null;

function getPool() {
  if (pool) return pool;
  pool = mysql.createPool({
    host:     process.env.MYSQL_HOST     || 'localhost',
    port:     parseInt(process.env.MYSQL_PORT) || 3306,
    user:     process.env.MYSQL_USER     || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    database: process.env.MYSQL_DATABASE || 'sqlidemo',
    waitForConnections: true,
    connectionLimit: 10,
    multipleStatements: false
  });
  return pool;
}

// run() — INSERT / UPDATE / DELETE. Returns { lastID, changes }
async function run(sql, params = []) {
  const [result] = await getPool().execute(sql, params);
  return { lastID: result.insertId, changes: result.affectedRows };
}

// get() — returns first row or null
async function get(sql, params = []) {
  const [rows] = await getPool().execute(sql, params);
  return rows[0] || null;
}

// all() — returns all rows
async function all(sql, params = []) {
  const [rows] = await getPool().execute(sql, params);
  return rows;
}

// rawQuery() — used ONLY by intentionally vulnerable demo routes
// that concatenate user input into SQL strings on purpose.
async function rawQuery(sql) {
  const conn = await getPool().getConnection();
  try {
    const [rows] = await conn.query(sql);
    return rows;
  } finally {
    conn.release();
  }
}

async function init() {
  const p = getPool();

  async function ensureUserColumn(columnName, definitionSql) {
    const [rows] = await p.execute(
      'SELECT COUNT(*) AS c FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?',
      ['users', columnName]
    );
    if ((rows[0] && rows[0].c) === 0) {
      await p.execute(`ALTER TABLE users ADD COLUMN ${definitionSql}`);
    }
  }

  await p.execute(`CREATE TABLE IF NOT EXISTS users (
    id                INT AUTO_INCREMENT PRIMARY KEY,
    username          VARCHAR(64)  UNIQUE NOT NULL,
    password          VARCHAR(255) NOT NULL,
    password_bcrypt   VARCHAR(255) DEFAULT NULL,
    role              VARCHAR(16)  NOT NULL DEFAULT 'user',
    email             VARCHAR(254) UNIQUE NOT NULL,
    is_verified       TINYINT      DEFAULT 0,
    verification_code VARCHAR(16)  DEFAULT NULL,
    verification_expires_at DATETIME DEFAULT NULL,
    login_otp_code    VARCHAR(16)  DEFAULT NULL,
    login_otp_expires_at DATETIME DEFAULT NULL,
    created_at        DATETIME     DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB`);

  // Handle upgrades when users table already exists from older app versions.
  await ensureUserColumn('verification_expires_at', 'verification_expires_at DATETIME DEFAULT NULL');
  await ensureUserColumn('login_otp_code', 'login_otp_code VARCHAR(16) DEFAULT NULL');
  await ensureUserColumn('password_bcrypt', 'password_bcrypt VARCHAR(255) DEFAULT NULL');
  await ensureUserColumn('login_otp_expires_at', 'login_otp_expires_at DATETIME DEFAULT NULL');

  await p.execute(`CREATE TABLE IF NOT EXISTS products (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(255)  NOT NULL,
    description TEXT          NOT NULL,
    price       DECIMAL(10,2) NOT NULL,
    image_url   VARCHAR(255),
    category    VARCHAR(64)   NOT NULL DEFAULT 'General',
    stock       INT           NOT NULL DEFAULT 100
  ) ENGINE=InnoDB`);

  await p.execute(`CREATE TABLE IF NOT EXISTS orders (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT           NOT NULL,
    total      DECIMAL(10,2) NOT NULL,
    status     VARCHAR(32)   NOT NULL DEFAULT 'pending',
    created_at DATETIME      DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  ) ENGINE=InnoDB`);

  await p.execute(`CREATE TABLE IF NOT EXISTS order_items (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    order_id   INT           NOT NULL,
    product_id INT           NOT NULL,
    quantity   INT           NOT NULL,
    price      DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (order_id)   REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
  ) ENGINE=InnoDB`);

  await p.execute(`CREATE TABLE IF NOT EXISTS payment_methods (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT          NOT NULL,
    card_number VARCHAR(32)  NOT NULL,
    card_holder VARCHAR(128) NOT NULL,
    expiry      VARCHAR(8)   NOT NULL,
    cvv         VARCHAR(4)   NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  ) ENGINE=InnoDB`);

  await p.execute(`CREATE TABLE IF NOT EXISTS audit_logs (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT          DEFAULT NULL,
    action      VARCHAR(64)  NOT NULL,
    entity_type VARCHAR(64)  DEFAULT NULL,
    entity_id   INT          DEFAULT NULL,
    before_json TEXT         DEFAULT NULL,
    after_json  TEXT         DEFAULT NULL,
    ip          VARCHAR(64)  DEFAULT NULL,
    user_agent  TEXT         DEFAULT NULL,
    created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  ) ENGINE=InnoDB`);

  await p.execute('UPDATE products SET category = TRIM(category)');

  const [ucRows] = await p.execute('SELECT COUNT(*) AS c FROM users');
  if ((ucRows[0].c || 0) === 0) {
    const seedAdminPass = process.env.SEED_ADMIN_PASSWORD || crypto.randomBytes(16).toString('hex');
    const seedAlicePass = process.env.SEED_ALICE_PASSWORD || crypto.randomBytes(16).toString('hex');
    const seedBobPass   = process.env.SEED_BOB_PASSWORD   || crypto.randomBytes(16).toString('hex');

    // Hash passwords for secure mode
    const hashedAdminPass = await bcrypt.hash(seedAdminPass, 10);
    const hashedAlicePass = await bcrypt.hash(seedAlicePass, 10);
    const hashedBobPass   = await bcrypt.hash(seedBobPass, 10);

    // Store both plaintext (for VULN_MODE) and bcrypt hash (for SECURE_MODE)
    await run('INSERT INTO users (username, password, password_bcrypt, role, email, is_verified) VALUES (?, ?, ?, ?, ?, ?)',
      ['admin', seedAdminPass, hashedAdminPass, 'admin', 'admin@demo.com', 1]);
    await run('INSERT INTO users (username, password, password_bcrypt, role, email, is_verified) VALUES (?, ?, ?, ?, ?, ?)',
      ['alice', seedAlicePass, hashedAlicePass, 'user', 'alice@demo.com', 1]);
    await run('INSERT INTO users (username, password, password_bcrypt, role, email, is_verified) VALUES (?, ?, ?, ?, ?, ?)',
      ['bob', seedBobPass, hashedBobPass, 'user', 'bob@demo.com', 1]);

    if (!process.env.SEED_ADMIN_PASSWORD) console.log('Seeded admin  -> password:', seedAdminPass);
    if (!process.env.SEED_ALICE_PASSWORD) console.log('Seeded alice  -> password:', seedAlicePass);
    if (!process.env.SEED_BOB_PASSWORD)   console.log('Seeded bob    -> password:', seedBobPass);
  }

  const [pcRows] = await p.execute('SELECT COUNT(*) AS c FROM products');
  if ((pcRows[0].c || 0) === 0) {
    console.log('init(): seeding products');
    const products = [
      ['Red T-Shirt',    'Comfortable cotton t-shirt in red. Perfect for casual wear.', 19.99, 'red-t-shirt',    'Clothing',    50],
      ['Blue Jeans',     'Classic blue denim jeans. Durable and stylish.',              49.99, 'blue-jeans',     'Clothing',    30],
      ['Sneakers',       'Lightweight everyday sneakers. Comfortable all day long.',    59.99, 'sneakers',       'Footwear',    25],
      ['Hoodie',         'Warm and cozy hoodie. Great for cold weather.',               39.99, 'hoodie',         'Clothing',    40],
      ['Socks',          'Pack of 5 cotton socks. Breathable and soft.',                9.99, 'socks',          'Accessories', 100],
      ['Baseball Cap',   'Adjustable baseball cap. One size fits all.',                14.99, 'baseball-cap',   'Accessories', 60],
      ['Backpack',       'Durable backpack for daily use. Multiple compartments.',     34.99, 'backpack',       'Accessories', 20],
      ['Sunglasses',     'UV-protective sunglasses. Stylish and functional.',          24.99, 'sunglasses',     'Accessories', 35],
      ['Watch',          'Minimalist analog watch. Elegant design.',                   89.99, 'watch',          'Accessories', 15],
      ['Leather Wallet', 'Leather wallet with multiple slots. Premium quality.',       29.99, 'leather-wallet', 'Accessories', 45],
      ['Running Shoes',  'Professional running shoes. Maximum comfort and support.',   79.99, 'running-shoes',  'Footwear',    20],
      ['Winter Jacket',  'Heavy-duty winter jacket. Waterproof and warm.',             99.99, 'winter-jacket',  'Clothing',    18],
    ];
    for (const [name, description, price, image_url, category, stock] of products) {
      await run('INSERT INTO products (name, description, price, image_url, category, stock) VALUES (?, ?, ?, ?, ?, ?)',
        [name, description, price, image_url, category, stock]);
    }

    await run("INSERT INTO orders (user_id, total, status) VALUES (2, 69.98,  'completed')");
    await run("INSERT INTO orders (user_id, total, status) VALUES (2, 129.97, 'pending')");
    await run("INSERT INTO orders (user_id, total, status) VALUES (3, 39.99,  'completed')");

    await run('INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (1, 1, 2, 19.99)');
    await run('INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (1, 5, 3,  9.99)');
    await run('INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (2, 3, 1, 59.99)');
    await run('INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (2, 4, 1, 39.99)');

    await run("INSERT INTO payment_methods (user_id, card_number, card_holder, expiry, cvv) VALUES (2, '4532123456789012', 'Alice Smith', '12/25', '123')");
    await run("INSERT INTO payment_methods (user_id, card_number, card_holder, expiry, cvv) VALUES (3, '5425233430109903', 'Bob Johnson', '06/26', '456')");
  }
}

async function reset() {
  const conn = await getPool().getConnection();
  try {
    await conn.query('SET FOREIGN_KEY_CHECKS = 0');
    for (const t of ['audit_logs', 'order_items', 'orders', 'payment_methods', 'users', 'products']) {
      await conn.query(`DROP TABLE IF EXISTS ${t}`);
    }
    await conn.query('SET FOREIGN_KEY_CHECKS = 1');
  } finally {
    conn.release();
  }
  await init();
}

module.exports = { getPool, run, get, all, rawQuery, init, reset };
