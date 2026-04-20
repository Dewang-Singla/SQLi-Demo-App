#!/usr/bin/env node
require('dotenv').config();
const { init, reset } = require('../src/db');

(async () => {
  const resetFlag = process.argv.includes('--reset');
  if (resetFlag) {
    console.log('Resetting database...');
    await reset();
    console.log('Database reset complete.');
  } else {
    console.log('Initializing database (create-if-needed + seed-if-empty)...');
    await init();
    console.log('Database initialization complete.');
  }
})();
