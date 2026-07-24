PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    balance INTEGER NOT NULL DEFAULT 100000 CHECK(balance >= 0),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    flash TEXT,
    flash_kind TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seller_id INTEGER NOT NULL,
    title TEXT NOT NULL CHECK(length(title) BETWEEN 2 AND 80),
    description TEXT NOT NULL CHECK(length(description) BETWEEN 5 AND 2000),
    price INTEGER NOT NULL CHECK(price BETWEEN 0 AND 100000000),
    image_url TEXT,
    sold INTEGER NOT NULL DEFAULT 0 CHECK(sold IN (0,1)),
    hidden INTEGER NOT NULL DEFAULT 0 CHECK(hidden IN (0,1)),
    created_at TEXT NOT NULL,
    FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_products_title ON products(title);
CREATE INDEX IF NOT EXISTS idx_products_seller ON products(seller_id);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    product_id INTEGER,
    body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 500),
    created_at TEXT NOT NULL,
    FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(recipient_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE SET NULL,
    CHECK(sender_id <> recipient_id)
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER NOT NULL,
    target_type TEXT NOT NULL CHECK(target_type IN ('user','product')),
    target_id INTEGER NOT NULL,
    reason TEXT NOT NULL CHECK(length(reason) BETWEEN 3 AND 200),
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved','rejected')),
    created_at TEXT NOT NULL,
    FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(reporter_id, target_type, target_id)
);

CREATE TABLE IF NOT EXISTS transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    amount INTEGER NOT NULL CHECK(amount BETWEEN 1 AND 1000000),
    created_at TEXT NOT NULL,
    FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY(recipient_id) REFERENCES users(id) ON DELETE RESTRICT,
    CHECK(sender_id <> recipient_id)
);
