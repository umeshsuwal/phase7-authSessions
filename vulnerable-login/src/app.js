const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '..', 'public')));

const sessions = {};

function currentUser(req) {
  const userId = sessions[req.cookies.session_id];
  if (!userId) return null;
  return db.prepare('SELECT id, name, email, bio FROM users WHERE id = ?').get(userId);
}

// VULNERABILITY 3: weak password storage
app.post('/signup', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email and password required' });
  }
  try {
    const info = db
      .prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)')
      .run(name, email, password); // no hashing
    res.status(201).json({ id: info.lastInsertRowid, name, email });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: err.message });
  }
});

// VULNERABILITY 1: SQL injection
// VULNERABILITY 4: session cookie with no HttpOnly / Secure / SameSite
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;

  try {
    const user = db.prepare(query).get();
    if (!user) return res.status(401).json({ success: false });

    const sessionId = crypto.randomBytes(16).toString('hex');
    sessions[sessionId] = user.id;

    res.cookie('session_id', sessionId);
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/me', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  res.json(user);
});

app.post('/bio', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });

  const { name, bio } = req.body;
  db.prepare('UPDATE users SET name = ?, bio = ? WHERE id = ?').run(
    name || user.name,
    bio || '',
    user.id
  );
  res.json({ message: 'Profile saved', id: user.id });
});

// VULNERABILITY 2: stored XSS
app.get('/profile/:id', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).send('User not found');

  res.send(`<h1>${user.name}'s Profile</h1><p>${user.bio}</p>`);
});

app.listen(3000, '127.0.0.1', () => {
  console.log('VULNERABLE APP running at http://127.0.0.1:3000 (local only)');
});