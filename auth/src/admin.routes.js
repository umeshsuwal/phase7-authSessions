const express = require('express');
const db = require('./db');
const { requireRole } = require('./auth.middleware');

const router = express.Router();

router.get('/users', requireRole('admin'), (req, res) => {
  const users = db.prepare('SELECT id, email, role FROM users').all();
  res.json(users);
});

module.exports = router;
