const db = require('./src/db');

const [, , email, role = 'admin'] = process.argv;

if (!email || !['admin', 'user'].includes(role)) {
  console.log('Usage: node promote.js <email> [admin|user]');
  process.exit(1);
}

const info = db.prepare('UPDATE users SET role = ? WHERE email = ?').run(role, email);
console.log(info.changes ? `${email} is now ${role}` : 'No user found with that email');