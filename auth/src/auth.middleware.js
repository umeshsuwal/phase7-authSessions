const { getUserBySession } = require('./auth.service');

function authenticate(req, res, next) {
  const sessionId = req.cookies && req.cookies.session_id;
  req.user = sessionId ? getUserBySession(sessionId) : null;
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not logged in' });
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

module.exports = { authenticate, requireRole };
