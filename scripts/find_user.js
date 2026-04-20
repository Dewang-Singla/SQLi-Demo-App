const { all } = require('../src/db');

async function main() {
  const username = process.argv[2] || 'SarveshThakur';
  const email = process.argv[3] || null;
  try {
    console.log('Searching for username:', username);
    const byUser = await all('SELECT * FROM users WHERE username = ?', [username]);
    console.log('Matches by username:', JSON.stringify(byUser, null, 2));
    if (email) {
      console.log('Searching for email:', email);
      const byEmail = await all('SELECT * FROM users WHERE email = ?', [email]);
      console.log('Matches by email:', JSON.stringify(byEmail, null, 2));
    } else {
      console.log('No email argument provided; skipping email search.');
    }
  } catch (e) {
    console.error('Error querying DB:', e);
    process.exit(2);
  }
}

main().then(() => process.exit(0));
