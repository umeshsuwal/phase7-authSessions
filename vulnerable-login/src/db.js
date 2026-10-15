const path = require('path');
const Database = require('better-sqlite3');

// Local file only. Never point this at a shared or cloud database.
const db = new Database(path.join(__dirname, '..', 'vuln.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,      -- plaintext on purpose (vulnerability #3)
    bio TEXT DEFAULT ''
  )
`);

module.exports = db;