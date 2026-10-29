const express = require('express');
const {
  signup,
  login,
  createSession,
  destroySession,
  SESSION_TTL_MS,
  refreshAccessToken,
  requestPasswordReset,
  completePasswordReset,
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
    return res.status(201).json({
      id: user.id,
      email: user.email,
      role: user.role,
    });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Email already registered' });
    }
    if (err.code === 'INVALID_INPUT') {
      return res.status(400).json({ error: err.message });
    }
    return res.status(500).json({ error: 'Something went wrong' });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const result = await login(email, password);
  if (!result) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const sessionId = createSession(result.id);
  res.cookie('session_id', sessionId, cookieOptions);
  res.json({
    message: 'Login successful',
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    user: { id: result.id, email: result.email, role: result.role },
  });
});

router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token required' });
  }

  try {
    const tokens = refreshAccessToken(refreshToken);
    return res.json(tokens);
  } catch (err) {
    return res.status(401).json({ error: err.message || 'Invalid refresh token' });
  }
});

router.post('/request-reset', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }

  const result = requestPasswordReset(email);
  return res.json({
    message: result.message,
    resetToken: result.resetToken,
  });
});

router.post('/complete-reset', (req, res) => {
  const { resetToken, newPassword } = req.body;
  if (!resetToken || !newPassword) {
    return res.status(400).json({ error: 'Reset token and new password required' });
  }

  try {
    const result = completePasswordReset(resetToken, newPassword);
    return res.json(result);
  } catch (err) {
    const status = err.message === 'Reset token expired' || err.message === 'Reset token already used' || err.message === 'Reset token invalid' ? 401 : 400;
    return res.status(status).json({ error: err.message });
  }
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
