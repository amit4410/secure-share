const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const cors = require('cors');
const { Pool } = require('pg');
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} = require('@aws-sdk/client-s3');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const BUCKET = 'secure-share-files';

/* ---------- Neon Postgres ---------- */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('sslmode=require')
    ? { rejectUnauthorized: false }
    : false,
});

/* ---------- Neon Object Storage (S3-compatible) ---------- */
const s3 = new S3Client({
  region: process.env.AWS_REGION || 'auto',
  endpoint: process.env.AWS_ENDPOINT_URL_S3,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
  forcePathStyle: true,
});

/* ---------- Create tables on startup ---------- */
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      public_key TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS files (
      id UUID PRIMARY KEY,
      owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      encrypted_metadata TEXT NOT NULL,
      self_wrapped_key TEXT,
      size BIGINT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shares (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
      recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      wrapped_key TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shares_file ON shares(file_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shares_recipient ON shares(recipient_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);`);
}

/* ---------- Middleware ---------- */
app.use(cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 },
});

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

/* ---------- Auth ---------- */
app.post('/api/register', async (req, res) => {
  const { username, password, publicKey } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const existing = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Username taken' });

    const password_hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, public_key) VALUES ($1, $2, $3) RETURNING id',
      [username, password_hash, publicKey || null]
    );
    const token = jwt.sign({ id: result.rows[0].id, username }, JWT_SECRET);
    res.json({ token, userId: result.rows[0].id });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
    res.json({ token, userId: user.id });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/users', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, public_key FROM users WHERE id != $1',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Users error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

/* ---------- Upload ---------- */
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  const { encryptedMetadata, selfWrappedKey, fileId } = req.body;
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const id = fileId || crypto.randomUUID();

  try {
    await s3.send(new PutObjectCommand({
      Bucket: BUCKET,
      Key: id,
      Body: req.file.buffer,
      ContentType: 'application/octet-stream',
    }));

    await pool.query(
      'INSERT INTO files (id, owner_id, encrypted_metadata, self_wrapped_key, size) VALUES ($1, $2, $3, $4, $5)',
      [id, req.user.id, encryptedMetadata, selfWrappedKey || null, req.file.size]
    );

    res.json({ id });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed: ' + err.message });
  }
});

/* ---------- List files ---------- */
app.get('/api/files', auth, async (req, res) => {
  try {
    const ownedResult = await pool.query(
      'SELECT id, encrypted_metadata, self_wrapped_key, size, created_at FROM files WHERE owner_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );

    const sharedResult = await pool.query(
      `SELECT s.file_id, s.wrapped_key, s.created_at AS shared_at,
              f.encrypted_metadata, f.size, u.username AS owner
       FROM shares s
       JOIN files f ON f.id = s.file_id
       JOIN users u ON u.id = f.owner_id
       WHERE s.recipient_id = $1
       ORDER BY s.created_at DESC`,
      [req.user.id]
    );

    res.json({
      owned: ownedResult.rows,
      shared: sharedResult.rows.map(r => ({
        file_id: r.file_id,
        wrapped_key: r.wrapped_key,
        encrypted_metadata: r.encrypted_metadata,
        size: r.size,
        created_at: r.shared_at,
        owner: r.owner,
      })),
    });
  } catch (err) {
    console.error('Files error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

/* ---------- Share (upsert) ---------- */
app.post('/api/share', auth, async (req, res) => {
  const { fileId, recipientId, wrappedKey } = req.body;
  try {
    const fileResult = await pool.query(
      'SELECT id FROM files WHERE id = $1 AND owner_id = $2',
      [fileId, req.user.id]
    );
    if (fileResult.rows.length === 0) return res.status(403).json({ error: 'Not your file' });

    const existing = await pool.query(
      'SELECT id FROM shares WHERE file_id = $1 AND recipient_id = $2',
      [fileId, recipientId]
    );
    if (existing.rows.length > 0) {
      await pool.query(
        'UPDATE shares SET wrapped_key = $1, created_at = NOW() WHERE file_id = $2 AND recipient_id = $3',
        [wrappedKey, fileId, recipientId]
      );
    } else {
      await pool.query(
        'INSERT INTO shares (file_id, recipient_id, wrapped_key) VALUES ($1, $2, $3)',
        [fileId, recipientId, wrappedKey]
      );
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Share error:', err);
    res.status(500).json({ error: 'Share failed' });
  }
});

/* ---------- List shares of a file ---------- */
app.get('/api/files/:id/shares', auth, async (req, res) => {
  try {
    const fileResult = await pool.query(
      'SELECT id FROM files WHERE id = $1 AND owner_id = $2',
      [req.params.id, req.user.id]
    );
    if (fileResult.rows.length === 0) return res.status(403).json({ error: 'Not your file' });

    const sharesResult = await pool.query(
      `SELECT s.id, s.recipient_id, s.created_at, u.username AS recipient_username
       FROM shares s
       JOIN users u ON u.id = s.recipient_id
       WHERE s.file_id = $1
       ORDER BY s.created_at DESC`,
      [req.params.id]
    );

    res.json({ shares: sharesResult.rows });
  } catch (err) {
    console.error('File shares error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

/* ---------- Rotate ---------- */
app.post('/api/files/:id/rotate', auth, upload.single('file'), async (req, res) => {
  const { encryptedMetadata, selfWrappedKey, newShares } = req.body;
  if (!req.file) return res.status(400).json({ error: 'No file' });
  if (!encryptedMetadata) return res.status(400).json({ error: 'No metadata' });

  const fileId = req.params.id;
  const client = await pool.connect();

  try {
    const fileResult = await client.query(
      'SELECT id FROM files WHERE id = $1 AND owner_id = $2',
      [fileId, req.user.id]
    );
    if (fileResult.rows.length === 0) {
      client.release();
      return res.status(403).json({ error: 'Not your file' });
    }

    await s3.send(new PutObjectCommand({
      Bucket: BUCKET,
      Key: fileId,
      Body: req.file.buffer,
      ContentType: 'application/octet-stream',
    }));

    await client.query('BEGIN');
    await client.query(
      'UPDATE files SET encrypted_metadata = $1, self_wrapped_key = $2, size = $3 WHERE id = $4',
      [encryptedMetadata, selfWrappedKey || null, req.file.size, fileId]
    );
    await client.query('DELETE FROM shares WHERE file_id = $1', [fileId]);

    let shares = [];
    try { shares = JSON.parse(newShares || '[]'); } catch (e) {}
    for (const s of shares) {
      await client.query(
        'INSERT INTO shares (file_id, recipient_id, wrapped_key) VALUES ($1, $2, $3)',
        [fileId, s.recipientId, s.wrappedKey]
      );
    }
    await client.query('COMMIT');
    client.release();

    res.json({ ok: true, remainingShares: shares.length });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (e) {}
    client.release();
    console.error('Rotate error:', err);
    res.status(500).json({ error: 'Rotate failed: ' + err.message });
  }
});

/* ---------- Self-wrap ---------- */
app.post('/api/files/:id/self-wrap', auth, async (req, res) => {
  const { selfWrappedKey } = req.body;
  if (!selfWrappedKey) return res.status(400).json({ error: 'Missing key' });

  try {
    const result = await pool.query(
      'UPDATE files SET self_wrapped_key = $1 WHERE id = $2 AND owner_id = $3 AND self_wrapped_key IS NULL',
      [selfWrappedKey, req.params.id, req.user.id]
    );
    if (result.rowCount === 0) {
      const check = await pool.query(
        'SELECT id, self_wrapped_key FROM files WHERE id = $1 AND owner_id = $2',
        [req.params.id, req.user.id]
      );
      if (check.rows.length === 0) return res.status(403).json({ error: 'Not your file' });
      return res.json({ ok: true, already: true });
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Self-wrap error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

/* ---------- Delete file ---------- */
app.delete('/api/files/:id', auth, async (req, res) => {
  try {
    const fileResult = await pool.query(
      'SELECT id FROM files WHERE id = $1 AND owner_id = $2',
      [req.params.id, req.user.id]
    );
    if (fileResult.rows.length === 0) {
      return res.status(404).json({ error: 'Not found or not yours' });
    }

    try {
      await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: req.params.id }));
    } catch (e) {
      console.warn('S3 delete warning:', e.message);
    }

    await pool.query('DELETE FROM files WHERE id = $1 AND owner_id = $2', [
      req.params.id,
      req.user.id,
    ]);

    res.json({ ok: true });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

/* ---------- Remove own share record ---------- */
app.delete('/api/shares/recipient/:fileId', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM shares WHERE file_id = $1 AND recipient_id = $2',
      [req.params.fileId, req.user.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Remove share error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

/* ---------- Download ---------- */
app.get('/api/download/:id', auth, async (req, res) => {
  try {
    const fileResult = await pool.query('SELECT * FROM files WHERE id = $1', [req.params.id]);
    const file = fileResult.rows[0];
    if (!file) return res.status(404).json({ error: 'Not found' });

    if (file.owner_id !== req.user.id) {
      const shareCheck = await pool.query(
        'SELECT id FROM shares WHERE file_id = $1 AND recipient_id = $2',
        [req.params.id, req.user.id]
      );
      if (shareCheck.rows.length === 0) return res.status(403).json({ error: 'Forbidden' });
    }

    const s3Response = await s3.send(new GetObjectCommand({
      Bucket: BUCKET,
      Key: req.params.id,
    }));
    const chunks = [];
    for await (const chunk of s3Response.Body) chunks.push(chunk);
    const buffer = Buffer.concat(chunks);

    res.set('Content-Type', 'application/json');
    res.send(buffer);
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).json({ error: 'Download failed' });
  }
});

/* ---------- Health check + start ---------- */
app.get('/health', (req, res) => res.send('OK'));

initDb()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`\n🔐 Secure Share running on port ${PORT}\n`);
      console.log(`   Database: ${process.env.DATABASE_URL ? 'Neon Postgres (connected)' : 'MISSING DATABASE_URL'}`);
      console.log(`   Storage:  ${BUCKET} @ ${process.env.AWS_ENDPOINT_URL_S3 || 'MISSING ENDPOINT'}\n`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });