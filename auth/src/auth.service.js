const bcrypt = require('bcrypt');
const db = require('./db');

const SALT_ROUNDS = 10; // the work factor

async function signup(email, plainPassword) {
  const passwordHash = await bcrypt.hash(plainPassword, SALT_ROUNDS);
  const info = db
    .prepare('INSERT INTO users (email, passwordHash) VALUES (?, ?)')
    .run(email, passwordHash);
  return { id: info.lastInsertRowid, email };
}

async function login(email, plainPassword) {
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return null; // don't reveal whether the email exists

  const isValid = await bcrypt.compare(plainPassword, user.passwordHash);
  if (!isValid) return null;

  return { id: user.id, email: user.email };
}

module.exports = { signup, login };