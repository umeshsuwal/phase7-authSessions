const path = require('path');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');

const db = new Database(path.join(__dirname, '..', 'users.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    passwordHash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
  )
`);

const columns = db.prepare('PRAGMA table_info(users)').all();
if (!columns.some((c) => c.name === 'role')) {
  db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
}

db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    userId INTEGER NOT NULL,
    expiresAt INTEGER NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    tokenHash TEXT NOT NULL UNIQUE,
    expiresAt INTEGER NOT NULL,
    revokedAt INTEGER,
    createdAt INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    FOREIGN KEY (userId) REFERENCES users(id)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    tokenHash TEXT NOT NULL UNIQUE,
    expiresAt INTEGER NOT NULL,
    usedAt INTEGER,
    createdAt INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    FOREIGN KEY (userId) REFERENCES users(id)
  )
`);

const adminEmail = 'admin@local.test';
const adminUser = db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
if (!adminUser) {
  const passwordHash = bcrypt.hashSync('AdminPass123!', 10);
  db.prepare("INSERT INTO users (email, passwordHash, role) VALUES (?, ?, 'admin')").run(adminEmail, passwordHash);
}

module.exports = db;