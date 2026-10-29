const { getUserBySession, verifyToken, getUserById } = require('./auth.service');

function authenticate(req, res, next) {
  req.user = null;

  const authHeader = req.headers.authorization || '';
  const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);

  if (bearerMatch) {
    try {
      const payload = verifyToken(bearerMatch[1]);
      if (payload.type === 'access') {
        const user = getUserById(payload.sub);
        if (user) {
          req.user = { id: user.id, email: user.email, role: user.role };
        }
      }
    } catch (err) {
      req.user = null;
    }
  }

  if (!req.user) {
    const sessionId = req.cookies && req.cookies.session_id;
    req.user = sessionId ? getUserBySession(sessionId) : null;
  }

  next();
}

function requireRole(requiredRole) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not logged in' });
    }

    if (req.user.role !== requiredRole) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    next();
  };
}

module.exports = { authenticate, requireRole };
