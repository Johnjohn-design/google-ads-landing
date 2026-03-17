const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Directories ──
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });

// ── Database ──
const db = new Database(path.join(__dirname, 'data', 'database.sqlite'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    token TEXT
  );

  CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    phone TEXT,
    message TEXT,
    status TEXT DEFAULT 'Новий',
    source TEXT DEFAULT 'Сайт',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lead_id INTEGER NOT NULL,
    author TEXT DEFAULT 'admin',
    text TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (lead_id) REFERENCES leads(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// ── Seed default admin user (admin / admin) ──
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

const existingAdmin = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!existingAdmin) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword('admin', salt);
  db.prepare('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)').run('admin', hash, salt);
}

// ── Seed default settings ──
const defaultSettings = {
  pixel_id: '',
  capi_token: '',
  whatsapp: '',
  telegram: '',
};
const upsertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
for (const [k, v] of Object.entries(defaultSettings)) {
  upsertSetting.run(k, v);
}

// ── Multer for favicon upload ──
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      cb(null, 'favicon' + ext);
    }
  }),
  limits: { fileSize: 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.png', '.ico', '.jpg', '.jpeg', '.svg'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

// ── Middleware ──
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(__dirname, { index: false }));

// ── Auth middleware ──
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const user = db.prepare('SELECT id, username FROM users WHERE token = ?').get(token);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  req.user = user;
  next();
}

// ══════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const hash = hashPassword(password, user.salt);
  if (hash !== user.password_hash) return res.status(401).json({ error: 'Invalid credentials' });

  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('UPDATE users SET token = ? WHERE id = ?').run(token, user.id);

  res.json({ token, username: user.username });
});

app.post('/api/auth/logout', auth, (req, res) => {
  db.prepare('UPDATE users SET token = NULL WHERE id = ?').run(req.user.id);
  res.json({ ok: true });
});

app.get('/api/auth/check', auth, (req, res) => {
  res.json({ username: req.user.username });
});

app.put('/api/auth/password', auth, (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) return res.status(400).json({ error: 'Missing fields' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const hash = hashPassword(current_password, user.salt);
  if (hash !== user.password_hash) return res.status(401).json({ error: 'Wrong current password' });

  const newSalt = crypto.randomBytes(16).toString('hex');
  const newHash = hashPassword(new_password, newSalt);
  db.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?').run(newHash, newSalt, req.user.id);

  res.json({ ok: true });
});

// ══════════════════════════════════════════════
//  LEADS ROUTES
// ══════════════════════════════════════════════

// Public: create lead from landing page
app.post('/api/leads', (req, res) => {
  const { name, phone, message } = req.body;
  if (!name || !phone) return res.status(400).json({ error: 'Name and phone are required' });

  const result = db.prepare(
    'INSERT INTO leads (name, phone, message) VALUES (?, ?, ?)'
  ).run(name, phone, message || '');

  // Facebook CAPI
  sendCapiEvent('Lead', { name, phone }, req);

  res.json({ ok: true, id: result.lastInsertRowid });
});

// Protected: list leads
app.get('/api/leads', auth, (req, res) => {
  const leads = db.prepare('SELECT * FROM leads ORDER BY created_at DESC').all();
  res.json(leads);
});

// Protected: get single lead with comments
app.get('/api/leads/:id', auth, (req, res) => {
  const lead = db.prepare('SELECT * FROM leads WHERE id = ?').get(req.params.id);
  if (!lead) return res.status(404).json({ error: 'Not found' });
  const comments = db.prepare('SELECT * FROM comments WHERE lead_id = ? ORDER BY created_at ASC').all(req.params.id);
  res.json({ ...lead, comments });
});

// Protected: update lead
app.put('/api/leads/:id', auth, (req, res) => {
  const lead = db.prepare('SELECT * FROM leads WHERE id = ?').get(req.params.id);
  if (!lead) return res.status(404).json({ error: 'Not found' });

  const { name, phone, message, status } = req.body;
  db.prepare(`
    UPDATE leads SET
      name = COALESCE(?, name),
      phone = COALESCE(?, phone),
      message = COALESCE(?, message),
      status = COALESCE(?, status),
      updated_at = datetime('now','localtime')
    WHERE id = ?
  `).run(name, phone, message, status, req.params.id);

  res.json({ ok: true });
});

// Protected: delete lead
app.delete('/api/leads/:id', auth, (req, res) => {
  db.prepare('DELETE FROM comments WHERE lead_id = ?').run(req.params.id);
  db.prepare('DELETE FROM leads WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Protected: create lead manually
app.post('/api/leads/manual', auth, (req, res) => {
  const { name, phone, message, source } = req.body;
  if (!name || !phone) return res.status(400).json({ error: 'Name and phone are required' });

  const result = db.prepare(
    'INSERT INTO leads (name, phone, message, source) VALUES (?, ?, ?, ?)'
  ).run(name, phone, message || '', source || 'Вручну');

  res.json({ ok: true, id: result.lastInsertRowid });
});

// Protected: add comment
app.post('/api/leads/:id/comments', auth, (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });

  const lead = db.prepare('SELECT id FROM leads WHERE id = ?').get(req.params.id);
  if (!lead) return res.status(404).json({ error: 'Lead not found' });

  db.prepare('INSERT INTO comments (lead_id, author, text) VALUES (?, ?, ?)').run(
    req.params.id, req.user.username, text
  );

  res.json({ ok: true });
});

// ══════════════════════════════════════════════
//  SETTINGS ROUTES
// ══════════════════════════════════════════════

app.get('/api/settings/public', (req, res) => {
  const rows = db.prepare("SELECT key, value FROM settings WHERE key IN ('pixel_id','whatsapp','telegram')").all();
  const obj = {};
  rows.forEach(r => { obj[r.key] = r.value; });
  res.json(obj);
});

app.get('/api/settings', auth, (req, res) => {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const obj = {};
  rows.forEach(r => { obj[r.key] = r.value; });
  res.json(obj);
});

app.put('/api/settings', auth, (req, res) => {
  const upsert = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
  const transaction = db.transaction((data) => {
    for (const [k, v] of Object.entries(data)) {
      upsert.run(k, v);
    }
  });
  transaction(req.body);
  res.json({ ok: true });
});

app.post('/api/settings/favicon', auth, upload.single('favicon'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({ ok: true, path: '/uploads/' + req.file.filename });
});

// ══════════════════════════════════════════════
//  FACEBOOK CONVERSIONS API
// ══════════════════════════════════════════════

async function sendCapiEvent(eventName, userData, req) {
  try {
    const pixelId = db.prepare("SELECT value FROM settings WHERE key = 'pixel_id'").get()?.value;
    const token = db.prepare("SELECT value FROM settings WHERE key = 'capi_token'").get()?.value;

    if (!pixelId || !token) return;

    const hashedPhone = userData.phone
      ? crypto.createHash('sha256').update(userData.phone.replace(/\D/g, '')).digest('hex')
      : undefined;
    const hashedName = userData.name
      ? crypto.createHash('sha256').update(userData.name.trim().toLowerCase()).digest('hex')
      : undefined;

    const eventData = {
      data: [{
        event_name: eventName,
        event_time: Math.floor(Date.now() / 1000),
        action_source: 'website',
        user_data: {
          ph: hashedPhone ? [hashedPhone] : undefined,
          fn: hashedName ? [hashedName] : undefined,
          client_ip_address: req?.ip,
          client_user_agent: req?.headers?.['user-agent'],
        },
        custom_data: {
          value: 149,
          currency: 'USD',
        }
      }]
    };

    const url = `https://graph.facebook.com/v21.0/${pixelId}/events?access_token=${token}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(eventData),
    });

    if (!response.ok) {
      console.error('CAPI error:', await response.text());
    }
  } catch (err) {
    console.error('CAPI error:', err.message);
  }
}

// ══════════════════════════════════════════════
//  SERVE PAGES
// ══════════════════════════════════════════════

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/landing', (req, res) => res.sendFile(path.join(__dirname, 'landing.html')));
app.get('/business', (req, res) => res.sendFile(path.join(__dirname, 'business.html')));
app.get('/shop', (req, res) => res.sendFile(path.join(__dirname, 'shop.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.listen(PORT, () => {
  console.log(`✦ Vivchar Solutions server running at http://localhost:${PORT}`);
  console.log(`  Landing page: http://localhost:${PORT}/`);
  console.log(`  Admin panel:  http://localhost:${PORT}/admin`);
  console.log(`  Default login: admin / admin`);
});
