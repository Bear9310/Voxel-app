import fastify from 'fastify';
import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import jwt from '@fastify/jwt';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import argon2 from 'argon2';
import { Pool } from 'pg';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { pipeline } from 'stream/promises';

// 1. Environment Initialization
const PORT = Number(process.env.PORT) || 3000;
const DB_URL = process.env.DATABASE_URL || 'postgres://voxel_admin:VoxelSecurePassword2026!@localhost:5432/voxel_prod';
const JWT_SECRET = process.env.JWT_SECRET || 'ProductionSuperSecretKeyThatMustBeAtLeast32BytesLong!';
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'CookieSigningSecretKeyForProductionVoxelApp!';

// Where uploaded video files live. MUST be a mounted persistent volume in
// production (see docker-compose.yml) or files disappear on every restart.
const STORAGE_DIR = process.env.STORAGE_DIR || path.join(__dirname, 'data');
const VIDEOS_DIR = path.join(STORAGE_DIR, 'videos');
const TMP_DIR = path.join(STORAGE_DIR, 'uploads_tmp');
fs.mkdirSync(VIDEOS_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });

// Max size for a single video upload. Default 50GB. The server never
// buffers a whole upload in memory regardless of this number — chunks are
// streamed straight to disk — but this cap still protects total disk usage.
const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_BYTES) || 50 * 1024 * 1024 * 1024;
const CHUNK_SIZE = 8 * 1024 * 1024; // 8MB per chunk

const db = new Pool({ connectionString: DB_URL });
const app = fastify({ logger: true, bodyLimit: 2 * 1024 * 1024 }); // 2MB default cap for normal JSON routes; the chunk route overrides this per-route below

// 2. Database Schema Bootstrapping
async function initDatabase() {
  const client = await db.connect();
  try {
    await client.query(`
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'USER' NOT NULL,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) UNIQUE NOT NULL
      );

      CREATE TABLE IF NOT EXISTS videos (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        creator_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        category VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        thumbnail_url VARCHAR(512),
        video_url VARCHAR(512) NOT NULL,
        duration VARCHAR(20),
        size BIGINT DEFAULT 0,
        hue INTEGER DEFAULT 0,
        views BIGINT DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      -- these ALTERs make the columns above appear even on a database that
      -- already had the old version of this table created
      ALTER TABLE videos ALTER COLUMN thumbnail_url DROP NOT NULL;
      ALTER TABLE videos ALTER COLUMN duration DROP NOT NULL;
      ALTER TABLE videos ADD COLUMN IF NOT EXISTS size BIGINT DEFAULT 0;
      ALTER TABLE videos ADD COLUMN IF NOT EXISTS hue INTEGER DEFAULT 0;

      CREATE TABLE IF NOT EXISTS saved_videos (
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        video_id UUID NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
        PRIMARY KEY (user_id, video_id)
      );

      -- tracks an in-progress chunked upload until all chunks arrive
      CREATE TABLE IF NOT EXISTS uploads (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        filename VARCHAR(512) NOT NULL,
        size BIGINT NOT NULL,
        chunk_size INTEGER NOT NULL,
        total_chunks INTEGER NOT NULL,
        mime_type VARCHAR(100),
        title VARCHAR(255) NOT NULL,
        category VARCHAR(50) NOT NULL,
        creator_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      INSERT INTO categories (name) VALUES ('Tech'), ('Nature'), ('Music'), ('Gaming'), ('Art')
      ON CONFLICT (name) DO NOTHING;
    `);
    app.log.info('Database schema initialized successfully.');
  } finally {
    client.release();
  }
}

// 3. Plugin Registration
app.register(cors, { origin: true, credentials: true });
app.register(helmet, { contentSecurityPolicy: false });
app.register(cookie, { secret: COOKIE_SECRET });
app.register(jwt, { secret: JWT_SECRET });
app.register(rateLimit, { max: 100, timeWindow: '1 minute' });

app.register(fastifyStatic, {
  root: path.join(__dirname, 'public'),
  prefix: '/',
});

// Second static root for served video files (range requests supported
// out of the box by @fastify/static). decorateReply:false is required
// when registering @fastify/static more than once in the same app.
app.register(fastifyStatic, {
  root: VIDEOS_DIR,
  prefix: '/videos/',
  decorateReply: false,
  acceptRanges: true,
});

// Raw binary chunks arrive as application/octet-stream. This parser hands
// the untouched readable stream straight to the route handler instead of
// buffering it into memory — the key piece that keeps large uploads cheap.
app.addContentTypeParser('application/octet-stream', (request, payload, done) => {
  done(null, payload);
});

// Authentication Middleware (required — rejects if not logged in)
const authenticate = async (request: any, reply: any) => {
  try {
    const token = request.cookies.access_token || request.headers.authorization?.replace('Bearer ', '');
    if (!token) throw new Error('Unauthorized');
    request.user = app.jwt.verify(token);
  } catch (err) {
    reply.status(401).send({ error: 'Authentication required' });
  }
};

// Optional auth — attaches request.user if a valid token is present,
// but never rejects. Used on public routes that personalize when logged in.
const optionalAuth = async (request: any) => {
  try {
    const token = request.cookies.access_token || request.headers.authorization?.replace('Bearer ', '');
    if (token) request.user = app.jwt.verify(token);
  } catch (err) {
    /* not logged in — fine, this route is public */
  }
};

function timeAgo(iso: string) {
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

// Maps a raw Postgres video row (+ optional current user) into exactly the
// shape public/index.html's cardHTML() function expects.
function toCard(row: any, savedIds: Set<string>) {
  return {
    id: row.id,
    title: row.title,
    creator: row.creator,
    category: row.category,
    cat: row.category,
    views: String(row.views ?? 0),
    time: timeAgo(row.created_at),
    duration: row.duration || '—',
    hue: row.hue ?? 0,
    videoUrl: row.video_url,
    saved: savedIds.has(String(row.id)),
  };
}

async function getSavedIdSet(db_: Pool, userId?: string): Promise<Set<string>> {
  if (!userId) return new Set();
  const res = await db_.query('SELECT video_id FROM saved_videos WHERE user_id = $1', [userId]);
  return new Set(res.rows.map((r: any) => String(r.video_id)));
}

// 4. Production API Endpoints

// Auth: Sign Up
app.post('/api/v1/auth/signup', async (req: any, reply) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password || password.length < 8) {
    return reply.status(400).send({ error: 'Valid username, email, and password (min 8 chars) are required.' });
  }

  try {
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    const res = await db.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, role',
      [username, email, hash]
    );
    const user = res.rows[0];
    const token = app.jwt.sign({ id: user.id, username: user.username, role: user.role });

    reply.setCookie('access_token', token, {
      path: '/',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 86400 // 1 day
    });

    return reply.status(201).send({ user: { id: user.id, username: user.username, role: user.role }, token });
  } catch (err: any) {
    if (err.code === '23505') return reply.status(409).send({ error: 'Username or email already exists.' });
    throw err;
  }
});

// Auth: Log In
app.post('/api/v1/auth/login', async (req: any, reply) => {
  const { username, password } = req.body;
  const res = await db.query('SELECT * FROM users WHERE username = $1 OR email = $1', [username]);
  const user = res.rows[0];

  if (!user || !(await argon2.verify(user.password_hash, password))) {
    return reply.status(401).send({ error: 'Invalid credentials.' });
  }

  const token = app.jwt.sign({ id: user.id, username: user.username, role: user.role });
  reply.setCookie('access_token', token, {
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 86400
  });

  return reply.send({ user: { id: user.id, username: user.username, role: user.role }, token });
});

// Auth: Log Out
app.post('/api/v1/auth/logout', async (_, reply) => {
  reply.clearCookie('access_token', { path: '/' });
  return reply.send({ success: true });
});

// Videos: Fetch All / Filter by Category (public, personalized if logged in)
app.get('/api/v1/videos', { preHandler: [optionalAuth] }, async (req: any) => {
  const { category, search } = req.query;
  let query = `
    SELECT v.*, u.username as creator
    FROM videos v
    JOIN users u ON v.creator_id = u.id
    WHERE 1=1
  `;
  const params: any[] = [];

  if (category && category !== 'All') {
    params.push(category);
    query += ` AND v.category = $${params.length}`;
  }
  if (search) {
    params.push(`%${search}%`);
    query += ` AND (v.title ILIKE $${params.length} OR u.username ILIKE $${params.length})`;
  }

  query += ' ORDER BY v.created_at DESC LIMIT 50';
  const res = await db.query(query, params);
  const savedIds = await getSavedIdSet(db, req.user?.id);
  return res.rows.map((row: any) => toCard(row, savedIds));
});

// Videos: Save / Bookmark (Requires Auth)
app.post('/api/v1/videos/:id/save', { preHandler: [authenticate] }, async (req: any, reply) => {
  const videoId = req.params.id;
  const userId = req.user.id;

  try {
    await db.query('INSERT INTO saved_videos (user_id, video_id) VALUES ($1, $2)', [userId, videoId]);
    return { saved: true };
  } catch (err: any) {
    if (err.code === '23505') {
      await db.query('DELETE FROM saved_videos WHERE user_id = $1 AND video_id = $2', [userId, videoId]);
      return { saved: false };
    }
    throw err;
  }
});

// Videos: Get Saved Library (Requires Auth)
app.get('/api/v1/library', { preHandler: [authenticate] }, async (req: any) => {
  const res = await db.query(`
    SELECT v.*, u.username as creator
    FROM saved_videos sv
    JOIN videos v ON sv.video_id = v.id
    JOIN users u ON v.creator_id = u.id
    WHERE sv.user_id = $1
    ORDER BY sv.video_id DESC
  `, [req.user.id]);
  const savedIds = new Set(res.rows.map((r: any) => String(r.id)));
  return res.rows.map((row: any) => toCard(row, savedIds));
});

// Videos: Delete (Requires Auth + Ownership)
app.delete('/api/v1/videos/:id', { preHandler: [authenticate] }, async (req: any, reply) => {
  const res = await db.query('SELECT * FROM videos WHERE id = $1', [req.params.id]);
  const row = res.rows[0];
  if (!row) return reply.status(404).send({ error: 'Not found.' });
  if (row.creator_id !== req.user.id) return reply.status(403).send({ error: 'You can only delete your own videos.' });

  const filename = path.basename(row.video_url);
  fs.unlink(path.join(VIDEOS_DIR, filename), () => {});
  await db.query('DELETE FROM saved_videos WHERE video_id = $1', [row.id]);
  await db.query('DELETE FROM videos WHERE id = $1', [row.id]);
  return { ok: true };
});

/* ================= CHUNKED RESUMABLE UPLOAD =================
   The server never buffers a whole file in memory. Each 8MB chunk is
   streamed straight to its own file on disk via the raw-passthrough
   content-type parser above. On "complete", chunks are concatenated
   stream-to-stream into the final video file, so peak memory stays flat
   no matter whether the video is 300MB or 50GB. */

app.post('/api/v1/uploads/init', { preHandler: [authenticate] }, async (req: any, reply) => {
  const { filename, size, mimeType, title, category } = req.body || {};
  if (!filename || !size || !title) {
    return reply.status(400).send({ error: 'Missing filename, size, or title.' });
  }
  if (size > MAX_UPLOAD_BYTES) {
    return reply.status(413).send({
      error: `That file is larger than the ${(MAX_UPLOAD_BYTES / 1024 / 1024 / 1024).toFixed(0)}GB limit on this server.`,
    });
  }

  const totalChunks = Math.ceil(size / CHUNK_SIZE);
  const res = await db.query(
    `INSERT INTO uploads (filename, size, chunk_size, total_chunks, mime_type, title, category, creator_id, status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending') RETURNING id`,
    [filename, size, CHUNK_SIZE, totalChunks, mimeType || 'video/mp4', title, category || 'Tech', req.user.id]
  );
  const uploadId = res.rows[0].id;
  fs.mkdirSync(path.join(TMP_DIR, uploadId), { recursive: true });

  return { uploadId, chunkSize: CHUNK_SIZE, totalChunks };
});

app.get('/api/v1/uploads/:id/status', { preHandler: [authenticate] }, async (req: any, reply) => {
  const res = await db.query('SELECT * FROM uploads WHERE id = $1', [req.params.id]);
  const upload = res.rows[0];
  if (!upload) return reply.status(404).send({ error: 'Upload not found.' });

  const dir = path.join(TMP_DIR, req.params.id);
  let received: number[] = [];
  if (fs.existsSync(dir)) {
    received = fs.readdirSync(dir)
      .filter((f) => f.startsWith('chunk_'))
      .map((f) => parseInt(f.replace('chunk_', ''), 10))
      .sort((a, b) => a - b);
  }
  return { received };
});

app.put(
  '/api/v1/uploads/:id/chunk/:index',
  {
    preHandler: [authenticate],
    config: { rateLimit: false }, // a single upload is many chunk requests; per-chunk limiting doesn't make sense
    bodyLimit: CHUNK_SIZE + 1024 * 1024, // chunk size + a little slack for framing overhead
  },
  async (req: any, reply) => {
    const res = await db.query('SELECT * FROM uploads WHERE id = $1', [req.params.id]);
    const upload = res.rows[0];
    if (!upload) return reply.status(404).send({ error: 'Upload session not found.' });
    if (upload.creator_id !== req.user.id) return reply.status(403).send({ error: 'Not your upload.' });

    const index = parseInt(req.params.index, 10);
    if (Number.isNaN(index) || index < 0 || index >= upload.total_chunks) {
      return reply.status(400).send({ error: 'Invalid chunk index.' });
    }

    const chunkPath = path.join(TMP_DIR, upload.id, `chunk_${String(index).padStart(6, '0')}`);
    const tmpPath = chunkPath + '.part';

    try {
      await pipeline(req.body, fs.createWriteStream(tmpPath));
      fs.renameSync(tmpPath, chunkPath);
      return { ok: true, index };
    } catch (err) {
      fs.unlink(tmpPath, () => {});
      return reply.status(500).send({ error: 'Could not write chunk to disk.' });
    }
  }
);

app.post('/api/v1/uploads/:id/complete', { preHandler: [authenticate] }, async (req: any, reply) => {
  const res = await db.query('SELECT * FROM uploads WHERE id = $1', [req.params.id]);
  const upload = res.rows[0];
  if (!upload) return reply.status(404).send({ error: 'Upload session not found.' });
  if (upload.creator_id !== req.user.id) return reply.status(403).send({ error: 'Not your upload.' });

  const dir = path.join(TMP_DIR, upload.id);
  for (let i = 0; i < upload.total_chunks; i++) {
    const p = path.join(dir, `chunk_${String(i).padStart(6, '0')}`);
    if (!fs.existsSync(p)) {
      return reply.status(400).send({ error: `Missing chunk ${i} — resume the upload and try again.` });
    }
  }

  const ext = (path.extname(upload.filename) || '.mp4').toLowerCase();
  const finalFilename = `${crypto.randomUUID()}${ext}`;
  const finalPath = path.join(VIDEOS_DIR, finalFilename);

  try {
    await streamConcatenate(dir, upload.total_chunks, finalPath);
  } catch (err) {
    return reply.status(500).send({ error: 'Failed to assemble the final video file.' });
  }
  fs.rm(dir, { recursive: true, force: true }, () => {});

  const hue = Math.floor(Math.random() * 360);
  const videoRes = await db.query(
    `INSERT INTO videos (creator_id, category, title, video_url, size, hue, views)
     VALUES ($1, $2, $3, $4, $5, $6, 0) RETURNING *`,
    [upload.creator_id, upload.category, upload.title, `/videos/${finalFilename}`, upload.size, hue]
  );
  await db.query(`UPDATE uploads SET status = 'complete' WHERE id = $1`, [upload.id]);

  const row = { ...videoRes.rows[0], creator: req.user.username };
  return toCard(row, new Set());
});

app.delete('/api/v1/uploads/:id', { preHandler: [authenticate] }, async (req: any, reply) => {
  fs.rm(path.join(TMP_DIR, req.params.id), { recursive: true, force: true }, () => {});
  await db.query('DELETE FROM uploads WHERE id = $1', [req.params.id]);
  return { ok: true };
});

// Streams chunk files in order into the final file, never holding more
// than one chunk's worth of data in memory at a time.
function streamConcatenate(dir: string, totalChunks: number, destPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const out = fs.createWriteStream(destPath);
    out.on('error', reject);
    out.on('finish', resolve);

    function pipeNext(i: number) {
      if (i >= totalChunks) return out.end();
      const chunkPath = path.join(dir, `chunk_${String(i).padStart(6, '0')}`);
      const rs = fs.createReadStream(chunkPath);
      rs.on('error', reject);
      rs.on('end', () => pipeNext(i + 1));
      rs.pipe(out, { end: false });
    }
    pipeNext(0);
  });
}

// 5. Server Bootstrap
const start = async () => {
  try {
    await initDatabase();
    await app.listen({ port: PORT, host: '0.0.0.0' });
    app.log.info(`Storage directory: ${STORAGE_DIR}`);
    app.log.info(`Max upload size: ${(MAX_UPLOAD_BYTES / 1024 / 1024 / 1024).toFixed(0)}GB`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};
start();
