const express  = require('express');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// ── MongoDB ───────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB conectado'))
  .catch(err => {
    console.error('Error al conectar MongoDB:', err.message);
    console.error('Revisa tu MONGO_URI en las variables de entorno de Render.');
  });

// Evita que un error de promesa no capturado mate el servidor
process.on('unhandledRejection', (err) => {
  console.error('Error no capturado:', err.message);
});

// ── Modelos ───────────────────────────────────────
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true, lowercase: true, trim: true },
  password: String,
  isAdmin:  { type: Boolean, default: false }
}));

const Build = mongoose.model('Build', new mongoose.Schema({
  username:  { type: String, lowercase: true },
  data:      Object,
  updatedAt: { type: Date, default: Date.now }
}));

const Submission = mongoose.model('Submission', new mongoose.Schema({
  username:  String,
  totalGame: Number,
  totalReal: Number,
  data:      Object,
  createdAt: { type: Date, default: Date.now }
}));

const CustomBuilding = mongoose.model('CustomBuilding', new mongoose.Schema({
  name:        String,
  desc:        String,
  width:       Number,
  height:      Number,
  priceGame:   Number,
  priceReal:   Number,
  color:       String,
  borderColor: String,
  isVariable:  Boolean,
  reqAdmin:    Boolean,
  createdAt:   { type: Date, default: Date.now }
}));

// ── Middleware auth ───────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ── Middleware: verificar que MongoDB está conectado
function dbCheck(req, res, next) {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Base de datos no disponible. Revisa MONGO_URI.' });
  }
  next();
}

// ── POST /api/register ────────────────────────────
app.post('/api/register', dbCheck, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Faltan campos' });
  if (username.toLowerCase() === 'admin')
    return res.status(400).json({ error: 'El nombre "admin" está reservado' });
  if (password.length < 4)
    return res.status(400).json({ error: 'La contrasena debe tener al menos 4 caracteres' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await User.create({ username: username.toLowerCase(), password: hash });
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Ese usuario ya existe' });
  }
});

// ── POST /api/login ───────────────────────────────
app.post('/api/login', dbCheck, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Faltan campos' });

  if (username.toLowerCase() === 'admin') {
    if (password !== process.env.ADMIN_PASS)
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    const token = jwt.sign(
      { username: 'admin', isAdmin: true },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    return res.json({ token, username: 'admin', isAdmin: true });
  }

  const user = await User.findOne({ username: username.toLowerCase() });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Credenciales incorrectas' });

  const token = jwt.sign(
    { username: user.username, isAdmin: false },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({ token, username: user.username, isAdmin: false });
});

// ── POST /api/build/save ──────────────────────────
app.post('/api/build/save', auth, dbCheck, async (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'Sin datos' });
  await Build.findOneAndUpdate(
    { username: req.user.username },
    { data, updatedAt: new Date() },
    { upsert: true, new: true }
  );
  res.json({ ok: true });
});

// ── GET /api/build/load ───────────────────────────
app.get('/api/build/load', auth, dbCheck, async (req, res) => {
  const build = await Build.findOne({ username: req.user.username });
  res.json(build ? build.data : null);
});

// ── POST /api/submit ──────────────────────────────
app.post('/api/submit', auth, dbCheck, async (req, res) => {
  const { totalGame, totalReal, data } = req.body;
  await Submission.create({
    username: req.user.username,
    totalGame,
    totalReal,
    data
  });
  res.json({ ok: true });
});

// ── GET /api/submissions (solo admin) ────────────
app.get('/api/submissions', auth, dbCheck, async (req, res) => {
  if (!req.user.isAdmin)
    return res.status(403).json({ error: 'Solo el admin puede ver esto' });
  const subs = await Submission.find().sort({ createdAt: -1 }).limit(100);
  res.json(subs);
});

// ── GET /api/custom-buildings (todos los usuarios) ─
app.get('/api/custom-buildings', auth, dbCheck, async (req, res) => {
  const items = await CustomBuilding.find().sort({ createdAt: 1 });
  res.json(items);
});

// ── POST /api/custom-buildings (solo admin) ────────
app.post('/api/custom-buildings', auth, dbCheck, async (req, res) => {
  if (!req.user.isAdmin)
    return res.status(403).json({ error: 'Solo el admin puede crear edificios' });
  const item = await CustomBuilding.create(req.body);
  res.json({ ok: true, item });
});

// ── Fallback → index.html ─────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));