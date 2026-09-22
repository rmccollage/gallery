require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;

// ---------- Cloudinary ----------
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ---------- CORS ----------
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      // Allow same-origin / curl / server-to-server (no origin header)
      if (!origin) return cb(null, true);
      if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        return cb(null, true);
      }
      return cb(new Error('Not allowed by CORS: ' + origin));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// NOTE: No app.options('*', ...) — Express 5 rejects bare '*'.
// The cors() middleware above already handles OPTIONS preflight.

// ---------- Data setup ----------
const DATA_DIR = path.join(__dirname, 'data');
const GALLERY_FILE = path.join(DATA_DIR, 'gallery.json');
const MEMBERS_FILE = path.join(DATA_DIR, 'members.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(GALLERY_FILE))
  fs.writeFileSync(GALLERY_FILE, JSON.stringify({ images: [] }, null, 2));
if (!fs.existsSync(MEMBERS_FILE))
  fs.writeFileSync(MEMBERS_FILE, JSON.stringify({ members: [] }, null, 2));

function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ---------- Middleware ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Only JPG, JPEG, PNG, WebP files are allowed'));
  },
});

// ---------- Session (simple in-memory) ----------
const sessions = new Map();

function createSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username, createdAt: Date.now() });
  return token;
}

function requireAuth(req, res, next) {
  const token = req.cookies?.session;
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  req.user = sessions.get(token);
  next();
}

function ok(res, data) {
  res.json({ success: true, data });
}
function fail(res, message, status = 400) {
  res.status(status).json({ success: false, message });
}

// ---------- Cookie options ----------
const isProd = process.env.NODE_ENV === 'production';

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: isProd ? 'none' : 'lax',
    secure: isProd,
    maxAge: 1000 * 60 * 60 * 24,
    path: '/',
  };
}

// ---------- Cloudinary helpers ----------
function uploadToCloudinary(buffer, folder) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder, resource_type: 'image' },
      (err, result) => (err ? reject(err) : resolve(result))
    );
    stream.end(buffer);
  });
}

function destroyFromCloudinary(publicId) {
  return new Promise((resolve) => {
    if (!publicId) return resolve(null);
    cloudinary.uploader.destroy(publicId, (err, result) => resolve(result));
  });
}

// ---------- Auth routes ----------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    const token = createSession(username);
    res.cookie('session', token, cookieOptions());
    return ok(res, { username });
  }
  return fail(res, 'Invalid credentials', 401);
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies?.session;
  if (token) sessions.delete(token);
  res.clearCookie('session', { ...cookieOptions(), maxAge: 0 });
  ok(res, { loggedOut: true });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies?.session;
  if (!token || !sessions.has(token)) return fail(res, 'Not logged in', 401);
  ok(res, { username: sessions.get(token).username });
});

// ---------- Gallery ----------
app.get('/api/gallery', (req, res) => {
  const db = readJSON(GALLERY_FILE) || { images: [] };
  ok(res, db.images);
});

app.post('/api/gallery', requireAuth, upload.single('image'), async (req, res) => {
  try {
    const { title } = req.body;
    if (!req.file) return fail(res, 'Image is required');
    if (!title || !title.trim()) return fail(res, 'Title is required');

    const result = await uploadToCloudinary(req.file.buffer, 'company/gallery');

    const db = readJSON(GALLERY_FILE) || { images: [] };
    const image = {
      id: 'gal_' + crypto.randomBytes(8).toString('hex'),
      title: title.trim(),
      url: result.secure_url,
      publicId: result.public_id,
      createdAt: new Date().toISOString(),
    };
    db.images.unshift(image);
    writeJSON(GALLERY_FILE, db);

    ok(res, image);
  } catch (err) {
    fail(res, err.message || 'Upload failed', 500);
  }
});

app.delete('/api/gallery/:id', requireAuth, async (req, res) => {
  const db = readJSON(GALLERY_FILE) || { images: [] };
  const idx = db.images.findIndex((i) => i.id === req.params.id);
  if (idx === -1) return fail(res, 'Image not found', 404);

  const [image] = db.images.splice(idx, 1);
  await destroyFromCloudinary(image.publicId);
  writeJSON(GALLERY_FILE, db);
  ok(res, { id: image.id });
});

// ---------- Members ----------
app.get('/api/members', (req, res) => {
  const db = readJSON(MEMBERS_FILE) || { members: [] };
  ok(res, db.members);
});

app.post('/api/members', requireAuth, upload.single('image'), async (req, res) => {
  try {
    const { name, role } = req.body;
    if (!name || !name.trim()) return fail(res, 'Name is required');
    if (!role || !role.trim()) return fail(res, 'Role is required');
    if (!req.file) return fail(res, 'Photo is required');

    const result = await uploadToCloudinary(req.file.buffer, 'company/members');

    const db = readJSON(MEMBERS_FILE) || { members: [] };
    const member = {
      id: 'mem_' + crypto.randomBytes(8).toString('hex'),
      name: name.trim(),
      role: role.trim(),
      image: { url: result.secure_url, publicId: result.public_id },
      createdAt: new Date().toISOString(),
    };
    db.members.unshift(member);
    writeJSON(MEMBERS_FILE, db);

    ok(res, member);
  } catch (err) {
    fail(res, err.message || 'Upload failed', 500);
  }
});

app.put('/api/members/:id', requireAuth, upload.single('image'), async (req, res) => {
  try {
    const db = readJSON(MEMBERS_FILE) || { members: [] };
    const member = db.members.find((m) => m.id === req.params.id);
    if (!member) return fail(res, 'Member not found', 404);

    const { name, role } = req.body;
    if (name && name.trim()) member.name = name.trim();
    if (role && role.trim()) member.role = role.trim();

    if (req.file) {
      // 1. Upload new image FIRST
      const result = await uploadToCloudinary(req.file.buffer, 'company/members');
      const oldPublicId = member.image?.publicId;

      // 2. Update JSON
      member.image = { url: result.secure_url, publicId: result.public_id };
      writeJSON(MEMBERS_FILE, db);

      // 3. Then delete old image
      await destroyFromCloudinary(oldPublicId);
    } else {
      writeJSON(MEMBERS_FILE, db);
    }

    ok(res, member);
  } catch (err) {
    fail(res, err.message || 'Update failed', 500);
  }
});

app.delete('/api/members/:id', requireAuth, async (req, res) => {
  const db = readJSON(MEMBERS_FILE) || { members: [] };
  const idx = db.members.findIndex((m) => m.id === req.params.id);
  if (idx === -1) return fail(res, 'Member not found', 404);

  const [member] = db.members.splice(idx, 1);
  await destroyFromCloudinary(member.image?.publicId);
  writeJSON(MEMBERS_FILE, db);
  ok(res, { id: member.id });
});

// ---------- Download proxy ----------
app.get('/api/download', async (req, res) => {
  try {
    const { url } = req.query;
    if (!url) return fail(res, 'url is required');

    const gallery = readJSON(GALLERY_FILE) || { images: [] };
    const members = readJSON(MEMBERS_FILE) || { members: [] };

    const galleryMatch = gallery.images.find((i) => i.url === url);
    const memberMatch = members.members.find((m) => m.image?.url === url);

    if (!galleryMatch && !memberMatch) {
      return fail(res, 'URL not found in database', 403);
    }

    const filename =
      (galleryMatch?.title || memberMatch?.name || 'image')
        .replace(/[^a-z0-9\-_]/gi, '_') + '.jpg';

    const response = await fetch(url);
    if (!response.ok) return fail(res, 'Failed to fetch image', 502);

    const arrayBuffer = await response.arrayBuffer();
    res.setHeader('Content-Type', response.headers.get('content-type') || 'image/jpeg');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(Buffer.from(arrayBuffer));
  } catch (err) {
    fail(res, err.message || 'Download failed', 500);
  }
});

// ---------- Health check ----------
app.get('/api/health', (req, res) => {
  ok(res, { status: 'ok', time: new Date().toISOString() });
});

// ---------- Serve admin UI (only if index.html exists next to server.js) ----------
const indexPath = path.join(__dirname, 'index.html');
if (fs.existsSync(indexPath)) {
  app.get('/', (req, res) => res.sendFile(indexPath));
}

// ---------- Error handler ----------
app.use((err, req, res, next) => {
  if (err) return fail(res, err.message || 'Server error', 400);
  next();
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
  console.log(`Allowed origins: ${allowedOrigins.join(', ') || '(all)'}`);
});