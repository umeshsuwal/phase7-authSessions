const bcrypt = require('bcrypt');
const crypto = require('crypto');
const db = require('./db');

const SALT_ROUNDS = 10;
const SESSION_TTL_MS = 1000 * 60 * 60; // 1 hour
const ACCESS_TOKEN_EXPIRY_MS = 1000 * 60 * 15;
const REFRESH_TOKEN_EXPIRY_MS = 1000 * 60 * 60 * 24 * 7;
const RESET_TOKEN_EXPIRY_MS = 1000 * 60 * 15;
const JWT_SECRET = process.env.JWT_SECRET || 'phase7-dev-secret-change-me';

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function getUserById(id) {
  return db.prepare('SELECT id, email, passwordHash, role FROM users WHERE id = ?').get(id) || null;
}

function getUserByEmail(email) {
  return db.prepare('SELECT id, email, passwordHash, role FROM users WHERE email = ?').get(email) || null;
}

function hashTokenValue(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

function base64UrlDecode(value) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function signToken(payload, expiresInMs) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const nowSeconds = Math.floor(Date.now() / 1000);
  const tokenPayload = {
    ...payload,
    iat: nowSeconds,
    exp: Math.floor((Date.now() + expiresInMs) / 1000),
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(tokenPayload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(signingInput)
    .digest('base64url');

  return `${signingInput}.${signature}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') {
    throw new Error('Token missing');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid token format');
  }

  const [headerBase64, payloadBase64, signature] = parts;
  const signingInput = `${headerBase64}.${payloadBase64}`;
  const expectedSignature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(signingInput)
    .digest('base64url');

  const a = Buffer.from(signature);
  const b = Buffer.from(expectedSignature);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error('Invalid token signature');
  }

  const payload = JSON.parse(base64UrlDecode(payloadBase64));
  if (payload.exp && Math.floor(Date.now() / 1000) >= payload.exp) {
    throw new Error('Token expired');
  }

  return payload;
}

function createAccessToken(user) {
  return signToken({ sub: user.id, email: user.email, role: user.role, type: 'access' }, ACCESS_TOKEN_EXPIRY_MS);
}

function createRefreshToken(user) {
  const token = crypto.randomBytes(32).toString('hex');
  const hash = hashTokenValue(token);
  const expiresAt = Date.now() + REFRESH_TOKEN_EXPIRY_MS;

  db.prepare('INSERT INTO refresh_tokens (userId, tokenHash, expiresAt, revokedAt) VALUES (?, ?, ?, NULL)').run(
    user.id,
    hash,
    expiresAt
  );

  return {
    token,
    expiresAt,
    hash,
  };
}

async function signup(email, plainPassword) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail || !plainPassword || String(plainPassword).length < 8) {
    const err = new Error('Email and password are required, and password must be at least 8 chars long');
    err.code = 'INVALID_INPUT';
    throw err;
  }

  const passwordHash = await bcrypt.hash(plainPassword, SALT_ROUNDS);
  const info = db
    .prepare("INSERT INTO users (email, passwordHash, role) VALUES (?, ?, 'user')")
    .run(normalizedEmail, passwordHash);

  const user = db.prepare('SELECT id, email, role FROM users WHERE id = ?').get(info.lastInsertRowid);
  return user;
}

async function login(email, plainPassword) {
  const normalizedEmail = normalizeEmail(email);
  const user = getUserByEmail(normalizedEmail);
  if (!user) return null;

  const isValid = await bcrypt.compare(plainPassword, user.passwordHash);
  if (!isValid) return null;

  const accessToken = createAccessToken(user);
  const refreshToken = createRefreshToken(user);

  return {
    id: user.id,
    email: user.email,
    role: user.role,
    accessToken,
    refreshToken: refreshToken.token,
    refreshTokenId: refreshToken.token,
  };
}

function createSession(userId) {
  const sessionId = crypto.randomBytes(32).toString('hex');
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

function revokeRefreshTokenByHash(tokenHash) {
  db.prepare('UPDATE refresh_tokens SET revokedAt = ? WHERE tokenHash = ?').run(Date.now(), tokenHash);
}

function refreshAccessToken(rawRefreshToken) {
  if (!rawRefreshToken || typeof rawRefreshToken !== 'string') {
    throw new Error('Refresh token required');
  }

  const tokenHash = hashTokenValue(rawRefreshToken);
  const record = db
    .prepare('SELECT * FROM refresh_tokens WHERE tokenHash = ?')
    .get(tokenHash);

  if (!record) {
    throw new Error('Refresh token not found');
  }

  if (record.revokedAt) {
    throw new Error('Refresh token revoked');
  }

  if (record.expiresAt < Date.now()) {
    db.prepare('UPDATE refresh_tokens SET revokedAt = ? WHERE id = ?').run(Date.now(), record.id);
    throw new Error('Refresh token expired');
  }

  const user = getUserById(record.userId);
  if (!user) {
    throw new Error('User not found');
  }

  const next = createRefreshToken(user);
  db.prepare('UPDATE refresh_tokens SET revokedAt = ? WHERE id = ?').run(Date.now(), record.id);
  const accessToken = createAccessToken(user);

  return { accessToken, refreshToken: next.token };
}

function requestPasswordReset(email) {
  const normalizedEmail = normalizeEmail(email);
  const user = getUserByEmail(normalizedEmail);

  if (!user) {
    return { message: 'If an account exists, a reset email has been sent.', resetToken: null };
  }

  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashTokenValue(token);
  const expiresAt = Date.now() + RESET_TOKEN_EXPIRY_MS;

  db.prepare('INSERT INTO password_reset_tokens (userId, tokenHash, expiresAt, usedAt) VALUES (?, ?, ?, NULL)').run(
    user.id,
    tokenHash,
    expiresAt
  );

  return {
    message: 'If an account exists, a reset email has been sent.',
    resetToken: token,
  };
}

function completePasswordReset(resetToken, newPassword) {
  if (!resetToken || !newPassword || String(newPassword).length < 8) {
    throw new Error('Reset token and a new password are required');
  }

  const tokenHash = hashTokenValue(resetToken);
  const record = db
    .prepare('SELECT * FROM password_reset_tokens WHERE tokenHash = ? ORDER BY id DESC LIMIT 1')
    .get(tokenHash);

  if (!record) {
    throw new Error('Reset token invalid');
  }

  if (record.usedAt) {
    throw new Error('Reset token already used');
  }

  if (record.expiresAt < Date.now()) {
    db.prepare('UPDATE password_reset_tokens SET usedAt = ? WHERE id = ?').run(Date.now(), record.id);
    throw new Error('Reset token expired');
  }

  const user = getUserById(record.userId);
  if (!user) {
    throw new Error('User not found');
  }

  const passwordHash = bcrypt.hashSync(newPassword, SALT_ROUNDS);
  db.prepare('UPDATE users SET passwordHash = ? WHERE id = ?').run(passwordHash, record.userId);
  db.prepare('UPDATE password_reset_tokens SET usedAt = ? WHERE id = ?').run(Date.now(), record.id);

  return { message: 'Password reset successful' };
}

module.exports = {
  signup,
  login,
  createSession,
  getUserBySession,
  destroySession,
  SESSION_TTL_MS,
  getUserByEmail,
  getUserById,
  createAccessToken,
  createRefreshToken,
  verifyToken,
  refreshAccessToken,
  requestPasswordReset,
  completePasswordReset,
  hashTokenValue,
};