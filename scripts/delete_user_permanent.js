const { all, get, run } = require('../src/db');

async function deleteUser(userId) {
  try {
    const user = await get('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user) {
      console.log('User not found:', userId);
      return;
    }

    console.log('Deleting user:', user.id, user.username, user.email);

    await run('START TRANSACTION');
    try {
      // Delete payment methods and add audit entries
      const pms = await all('SELECT * FROM payment_methods WHERE user_id = ?', [userId]);
      for (const pm of pms) {
        const before = JSON.stringify(pm);
        await run('INSERT INTO audit_logs (user_id, action, entity_type, entity_id, before_json) VALUES (?, ?, ?, ?, ?)', [null, 'PAYMENT_METHOD_DELETE', 'payment_method', pm.id, before]);
        await run('DELETE FROM payment_methods WHERE id = ?', [pm.id]);
        console.log('  Deleted payment_method', pm.id);
      }

      // Delete orders and order_items and add audit entries
      const orders = await all('SELECT * FROM orders WHERE user_id = ?', [userId]);
      for (const ord of orders) {
        const items = await all('SELECT * FROM order_items WHERE order_id = ?', [ord.id]);
        const before = JSON.stringify({ order: ord, items });
        await run('INSERT INTO audit_logs (user_id, action, entity_type, entity_id, before_json) VALUES (?, ?, ?, ?, ?)', [null, 'ORDER_DELETE', 'order', ord.id, before]);
        await run('DELETE FROM order_items WHERE order_id = ?', [ord.id]);
        await run('DELETE FROM orders WHERE id = ?', [ord.id]);
        console.log('  Deleted order', ord.id);
      }

      // Dissociate existing audit logs referring to this user
      await run('UPDATE audit_logs SET user_id = NULL WHERE user_id = ?', [userId]);
      console.log('  Dissociated audit_logs for user', userId);

      // Insert USER_DELETE audit (user_id NULL because this is an admin cleanup)
      const userBefore = JSON.stringify(user);
      await run('INSERT INTO audit_logs (user_id, action, entity_type, entity_id, before_json) VALUES (?, ?, ?, ?, ?)', [null, 'USER_DELETE', 'user', userId, userBefore]);

      // Delete the user
      await run('DELETE FROM users WHERE id = ?', [userId]);
      console.log('  Deleted user', userId);

      await run('COMMIT');
      console.log('User deletion committed.');
    } catch (e) {
      console.error('Error during deletion, rolling back', e);
      try { await run('ROLLBACK'); } catch (er) { console.error('Rollback failed', er); }
      process.exit(1);
    }
  } catch (e) {
    console.error('Fatal error', e);
    process.exit(2);
  }
}

const id = parseInt(process.argv[2], 10);
if (!id) { console.error('Usage: node delete_user_permanent.js <userId>'); process.exit(1); }

deleteUser(id).then(() => process.exit(0));
