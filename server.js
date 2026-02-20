const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(cors());
app.use(express.static('public'));

// ── Conexión MongoDB ──────────────────────────────
mongoose.connect(process.env.MONGO_URI);

// ── Modelos ───────────────────────────────────────
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true, lowercase: true },
  password: String,
  isAdmin:  { type: Boolean, default: false }
}));

const Build = mongoose.model('Build', new mongoose.Schema({
  username: String,
  name:     { type: String, default: 'Mi Base' },
  data:     Object,   // el estado completo de la base
  updatedAt:{ type: Date, default: Date.now }
}));

const Submission = mongoose.model('Submission', new mongoose.Schema({
  username:  String,
  totalGame: Number,
  totalReal: Number,
  data:      Object,
  createdAt: { type: Date, default: Date.now }
}));

// ── Middleware auth ───────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}

// ── Rutas auth ────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan campos' });
  if (username.toLowerCase() === 'admin') return res.status(400).json({ error: 'Nombre reservado' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await User.create({ username, password: hash });
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'El usuario ya existe' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  // Admin hardcodeado
  if (username === 'admin' && password === process.env.ADMIN_PASS) {
    const token = jwt.sign({ username: 'admin', isAdmin: true }, process.env.JWT_SECRET);
    return res.json({ token, username: 'admin', isAdmin: true });
  }
  const user = await User.findOne({ username: username.toLowerCase() });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  const token = jwt.sign({ username: user.username, isAdmin: false }, process.env.JWT_SECRET);
  res.json({ token, username: user.username, isAdmin: false });
});

// ── Rutas builds ──────────────────────────────────
app.post('/api/build/save', auth, async (req, res) => {
  const { data } = req.body;
  await Build.findOneAndUpdate(
    { username: req.user.username },
    { data, updatedAt: new Date() },
    { upsert: true }
  );
  res.json({ ok: true });
});

app.get('/api/build/load', auth, async (req, res) => {
  const build = await Build.findOne({ username: req.user.username });
  res.json(build ? build.data : null);
});

// ── Rutas submissions ─────────────────────────────
app.post('/api/submit', auth, async (req, res) => {
  const { totalGame, totalReal, data } = req.body;
  await Submission.create({ username: req.user.username, totalGame, totalReal, data });
  res.json({ ok: true });
});

app.get('/api/submissions', auth, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Solo admin' });
  const subs = await Submission.find().sort({ createdAt: -1 });
  res.json(subs);
});

// ── Fallback SPA ──────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(process.env.PORT || 3000, () => console.log('Servidor corriendo'));