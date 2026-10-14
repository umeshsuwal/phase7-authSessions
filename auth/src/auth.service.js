const bcrypt = require('bcrypt');
const crypto = require('crypto');
const db = require('./db');

const SALT_ROUNDS = 10;
const SESSION_TTL_MS = 1000 * 60 * 60; // 1 hour

async function signup(email, plainPassword) {
  const passwordHash = await bcrypt.hash(plainPassword, SALT_ROUNDS);
  const info = db
    .prepare("INSERT INTO users (email, passwordHash, role) VALUES (?, ?, 'user')")
    .run(email, passwordHash);
  return { id: info.lastInsertRowid, email, role: 'user' };
}

async function login(email, plainPassword) {
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return null;

  const isValid = await bcrypt.compare(plainPassword, user.passwordHash);
  if (!isValid) return null;

  return { id: user.id, email: user.email, role: user.role };
}

function createSession(userId) {
  const sessionId = crypto.randomBytes(32).toString('hex'); // unguessable
  db.prepare('INSERT INTO sessions (id, userId, expiresAt) VALUES (?, ?, ?)').run(
    sessionId,
    userId,
    Date.now() + SESSION_TTL_MS
  );
  return sessionId;
}

function getUserBySession(sessionId) {
  const row = db
    .prepare(
      `SELECT u.id, u.email, u.role, s.expiresAt
       FROM sessions s JOIN users u ON u.id = s.userId
       WHERE s.id = ?`
    )
    .get(sessionId);

  if (!row) return null;
  if (row.expiresAt < Date.now()) {
    destroySession(sessionId);
    return null;
  }
  return { id: row.id, email: row.email, role: row.role };
}

function destroySession(sessionId) {
  db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
}

module.exports = {
  signup,
  login,
  createSession,
  getUserBySession,
  destroySession,
  SESSION_TTL_MS,
};