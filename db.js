/* ================================================================
   Virtual Oracle — PostgreSQL connection + schema init
   Render provides DATABASE_URL for a managed Postgres instance.
   ================================================================ */
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.warn('⚠  DATABASE_URL is not set. Set it in your environment / Render dashboard.');
}

// Render's managed Postgres requires SSL. Locally (DATABASE_SSL=off) we skip it.
const useSSL = process.env.DATABASE_SSL !== 'off';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSSL ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
});

pool.on('error', (err) => console.error('Unexpected PG pool error', err));

/* Run the schema (idempotent — safe to call on every boot) */
async function initSchema() {
  const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(sql);
  console.log('✓ Schema ensured');
}

const query = (text, params) => pool.query(text, params);

module.exports = { pool, query, initSchema };

/* `node db.js --init` runs the schema once and exits */
if (require.main === module && process.argv.includes('--init')) {
  require('dotenv').config();
  initSchema()
    .then(() => { console.log('Done.'); process.exit(0); })
    .catch((e) => { console.error(e); process.exit(1); });
}
