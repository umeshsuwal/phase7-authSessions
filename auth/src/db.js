const path = require('path');
const Database = require('better-sqlite3');

// users.db lives in the project root (auth-kata/)
const db = new Database(path.join(__dirname, '..', 'users.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    passwordHash TEXT NOT NULL
  )
`);

module.exports = db;