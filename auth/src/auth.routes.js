const express = require('express');
const {
  signup,
  login,
  createSession,
  destroySession,
  SESSION_TTL_MS,
} = require('./auth.service');

const router = express.Router();

const cookieOptions = {
  httpOnly: true,
  secure: process.env.COOKIE_SECURE !== 'false',
  sameSite: 'strict',
  maxAge: SESSION_TTL_MS,
};

router.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const user = await signup(email, password);
    res.status(201).json(user);
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: 'Something went wrong' });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const user = await login(email, password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const sessionId = createSession(user.id);
  res.cookie('session_id', sessionId, cookieOptions);
  res.json({ message: 'Login successful', user });
});

router.post('/logout', (req, res) => {
  const sessionId = req.cookies && req.cookies.session_id;
  if (sessionId) destroySession(sessionId);
  res.clearCookie('session_id', {
    httpOnly: cookieOptions.httpOnly,
    secure: cookieOptions.secure,
    sameSite: cookieOptions.sameSite,
  });
  res.json({ message: 'Logged out' });
});

router.get('/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not logged in' });
  res.json(req.user);
});

module.exports = router;
