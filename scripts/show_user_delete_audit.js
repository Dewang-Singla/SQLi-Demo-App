require('dotenv').config();
const { all } = require('../src/db');

const uid = parseInt(process.argv[2], 10) || 9;

(async () => {
  try {
    const rows = await all(
      'SELECT id, user_id, action, entity_type, entity_id, before_json, created_at FROM audit_logs WHERE action = ? AND entity_id = ? ORDER BY id DESC LIMIT 10',
      ['USER_DELETE', uid]
    );
    console.log(JSON.stringify(rows, null, 2));
  } catch (e) {
    console.error('Error:', e);
    process.exit(1);
  }
  process.exit(0);
})();
