const crypto = require('crypto');
const { all, run } = require('../src/db');

(async () => {
  try {
    const keep = ['admin', 'alice', 'bob'];
    const others = await all('SELECT id, username, email FROM users WHERE username NOT IN (?,?,?)', keep);
    console.log('Users to anonymize count:', others.length);
    for (const u of others) {
      const newu = 'deleted_' + u.id;
      const newe = `deleted_${u.id}@example.invalid`;
      const pwd = crypto.randomBytes(12).toString('hex');
      await run('UPDATE users SET username=?, email=?, password=?, is_verified=0 WHERE id=?', [newu, newe, pwd, u.id]);
      console.log('Anonymized user', u.id, '->', newu);
    }
    console.log('Done');
  } catch (e) {
    console.error('ERROR', e);
    process.exit(1);
  }
  process.exit(0);
})();
