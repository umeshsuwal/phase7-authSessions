require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const authRoutes = require('./auth.routes');
const adminRoutes = require('./admin.routes');
const { authenticate } = require('./auth.middleware');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(authenticate); // sets req.user on every request

app.use((req, res, next) => {
  const stateChanging = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
  if (!stateChanging || !req.cookies || !req.cookies.session_id) {
    return next();
  }

  const cookieToken = req.cookies.csrf_token;
  const headerToken = req.get('x-csrf-token');
  if (!cookieToken || !headerToken || cookieToken.length !== headerToken.length) {
    return res.status(403).json({ error: 'CSRF validation failed' });
  }

  const cookieBuffer = Buffer.from(cookieToken);
  const headerBuffer = Buffer.from(headerToken);
  if (!crypto.timingSafeEqual(cookieBuffer, headerBuffer)) {
    return res.status(403).json({ error: 'CSRF validation failed' });
  }

  next();
});

app.use('/auth', authRoutes);
app.use('/', authRoutes);
app.use('/admin', adminRoutes);

if (require.main === module) {
  const PORT = Number(process.env.PORT || 3000);
  app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
}

module.exports = app;