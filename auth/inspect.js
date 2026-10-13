const db = require('./src/db');

const users = db.prepare('SELECT id, email, passwordHash FROM users').all();
console.table(users);