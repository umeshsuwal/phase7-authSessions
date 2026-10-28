const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

// Local file only. Never point this at a shared or cloud database.
const db = new Database(path.join(__dirname, '..', 'vuln.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    bio TEXT DEFAULT ''
  )
`);

const columns = db.pragma('table_info(users)');
if (columns.some((column) => column.name === 'password')) {
  const legacyUsers = db.prepare('SELECT id, name, email, password, bio FROM users').all();
  const migrate = db.transaction(() => {
    db.exec(`
      CREATE TABLE users_migrated (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        bio TEXT DEFAULT ''
      )
    `);
    const insert = db.prepare(
      'INSERT INTO users_migrated (id, name, email, password_hash, bio) VALUES (?, ?, ?, ?, ?)'
    );
    for (const user of legacyUsers) {
      insert.run(user.id, user.name, user.email, bcrypt.hashSync(user.password, 12), user.bio || '');
    }
    db.exec('DROP TABLE users; ALTER TABLE users_migrated RENAME TO users;');
  });
  migrate();
}

module.exports = db;