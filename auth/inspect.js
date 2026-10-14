const db = require('./src/db');

console.table(db.prepare('SELECT id, email, role, passwordHash FROM users').all());