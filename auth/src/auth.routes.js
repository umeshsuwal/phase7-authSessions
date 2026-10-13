const express = require('express');
const { signup, login } = require('./auth.service');

const router = express.Router();

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
    // same message for "no such user" and "wrong password"
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  res.json({ message: 'Login successful', user });
});

module.exports = router;