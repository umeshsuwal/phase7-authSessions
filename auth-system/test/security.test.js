const assert = require('node:assert/strict');
const test = require('node:test');
const crypto = require('node:crypto');
const app = require('../src/app');
const db = require('../src/db');
const {
  signup,
  login,
  requestPasswordReset,
  completePasswordReset,
  hashTokenValue,
} = require('../src/auth.service');

let server;
const createdEmails = [];

test.before(async () => {
  server = await new Promise((resolve) => {
    const instance = app.listen(0, () => resolve(instance));
  });
});

test.after(async () => {
  for (const email of createdEmails) {
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (user) {
      db.prepare('DELETE FROM refresh_tokens WHERE userId = ?').run(user.id);
      db.prepare('DELETE FROM password_reset_tokens WHERE userId = ?').run(user.id);
      db.prepare('DELETE FROM sessions WHERE userId = ?').run(user.id);
      db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
    }
  }
  await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
});

async function createUser() {
  const email = `security-${crypto.randomUUID()}@example.test`;
  createdEmails.push(email);
  return signup(email, 'StrongPass123!');
}

async function request(path, options) {
  return fetch(`http://127.0.0.1:${server.address().port}${path}`, {
    headers: { 'content-type': 'application/json', ...(options && options.headers) },
    ...options,
  });
}

test('authenticated non-admin users receive 403 for admin routes', async () => {
  const user = await createUser();
  const tokens = await login(user.email, 'StrongPass123!');
  const response = await request('/admin/dashboard', {
    headers: { authorization: `Bearer ${tokens.accessToken}` },
  });

  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: 'Forbidden' });
});

test('signup creates a user without returning their password hash', async () => {
  const email = `security-${crypto.randomUUID()}@example.test`;
  createdEmails.push(email);
  const user = await signup(email, 'StrongPass123!');
  const stored = db.prepare('SELECT passwordHash FROM users WHERE email = ?').get(email);

  assert.equal(user.email, email);
  assert.equal(Object.hasOwn(user, 'passwordHash'), false);
  assert.notEqual(stored.passwordHash, 'StrongPass123!');
  assert.match(stored.passwordHash, /^\$2[aby]\$/);
});

test('invalid login returns a generic unauthorized response', async () => {
  const user = await createUser();
  const response = await request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email: user.email, password: 'WrongPassword123!' }),
  });

  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'Invalid email or password' });
});

test('cookie-authenticated state changes require a CSRF token', async () => {
  const user = await createUser();
  const loginResponse = await request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email: user.email, password: 'StrongPass123!' }),
  });
  const setCookie = loginResponse.headers.get('set-cookie');
  const sessionCookie = setCookie.match(/session_id=([^;]+)/)[1];

  const response = await request('/auth/logout', {
    method: 'POST',
    headers: { cookie: `session_id=${sessionCookie}` },
  });
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: 'CSRF validation failed' });
});

test('refresh tokens rotate and cannot be reused', async () => {
  const user = await createUser();
  const tokens = await login(user.email, 'StrongPass123!');
  const first = await request('/auth/refresh', {
    method: 'POST',
    body: JSON.stringify({ refreshToken: tokens.refreshToken }),
  });
  assert.equal(first.status, 200);
  const rotated = await first.json();
  assert.ok(rotated.accessToken);
  assert.ok(rotated.refreshToken);

  const reused = await request('/auth/refresh', {
    method: 'POST',
    body: JSON.stringify({ refreshToken: tokens.refreshToken }),
  });
  assert.equal(reused.status, 401);
  assert.deepEqual(await reused.json(), { error: 'Invalid refresh token' });
});

test('expired refresh tokens are rejected', async () => {
  const user = await createUser();
  const rawToken = crypto.randomBytes(32).toString('hex');
  db.prepare(
    'INSERT INTO refresh_tokens (userId, tokenHash, expiresAt, revokedAt) VALUES (?, ?, ?, NULL)'
  ).run(user.id, hashTokenValue(rawToken), Date.now() - 1);

  const response = await request('/auth/refresh', {
    method: 'POST',
    body: JSON.stringify({ refreshToken: rawToken }),
  });
  assert.equal(response.status, 401);
});

test('reset requests have the same response shape for known and unknown emails', async () => {
  const user = await createUser();
  const known = await request('/auth/request-reset', {
    method: 'POST',
    body: JSON.stringify({ email: user.email }),
  });
  const unknown = await request('/auth/request-reset', {
    method: 'POST',
    body: JSON.stringify({ email: 'does-not-exist@example.test' }),
  });

  assert.equal(known.status, 200);
  assert.equal(unknown.status, 200);
  assert.deepEqual(await known.json(), await unknown.json());
});

test('reset tokens expire and cannot be reused', async () => {
  const user = await createUser();
  const { resetToken } = requestPasswordReset(user.email);
  const record = db.prepare('SELECT id FROM password_reset_tokens WHERE tokenHash = ?').get(hashTokenValue(resetToken));
  db.prepare('UPDATE password_reset_tokens SET expiresAt = ? WHERE id = ?').run(Date.now() - 1, record.id);
  assert.throws(() => completePasswordReset(resetToken, 'NewStrongPass123!'), /expired/);

  const secondToken = requestPasswordReset(user.email).resetToken;
  assert.deepEqual(completePasswordReset(secondToken, 'NewStrongPass123!'), {
    message: 'Password reset successful',
  });
  assert.throws(() => completePasswordReset(secondToken, 'AnotherStrongPass123!'), /already used/);
});
