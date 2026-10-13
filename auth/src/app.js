const express = require('express');
const authRoutes = require('./auth.routes');

const app = express();
app.use(express.json());
app.use('/', authRoutes);

const PORT = 3000;
app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));

module.exports = app;