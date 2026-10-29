require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const authRoutes = require('./auth.routes');
const adminRoutes = require('./admin.routes');
const { authenticate } = require('./auth.middleware');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(authenticate); // sets req.user on every request

app.use('/auth', authRoutes);
app.use('/', authRoutes);
app.use('/admin', adminRoutes);

const PORT = 3000;
app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));

module.exports = app;