"use strict";

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const knexLib = require('knex');

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({ windowMs: 60*1000, max: 100 });
app.use(limiter);

// Database setup
let knex;
if (process.env.DB_MODE === 'POSTGRES') {
  knex = knexLib({
    client: 'pg',
    connection: {
      host: process.env.POSTGRES_HOST,
      user: process.env.POSTGRES_USER,
      password: process.env.POSTGRES_PASSWORD,
      database: process.env.POSTGRES_DB,
    },
  });
} else {
  knex = knexLib({
    client: 'sqlite3',
    connection: { filename: './database/familienhof.db' },
    useNullAsDefault: true,
  });
}

// -------------------
// Auth Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// -------------------
// Routes
// Auth routes
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await knex('users').where({ email }).first();
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// -------------------
// News routes
app.get('/api/news', async (req, res) => {
  const news = await knex('news').where({ published: true });
  res.json(news);
});

// Admin News CRUD
app.post('/api/news', authenticateToken, async (req, res) => {
  const { title, content } = req.body;
  const [id] = await knex('news').insert({ title, content });
  res.json({ id });
});

// -------------------
// Horses routes
app.get('/api/horses', async (req, res) => {
  const horses = await knex('horses').where({ available: true });
  res.json(horses);
});

// Admin Horses CRUD
app.post('/api/horses', authenticateToken, async (req, res) => {
  const { name, price, description } = req.body;
  const [id] = await knex('horses').insert({ name, price, description });
  res.json({ id });
});

// -------------------
// Calendar routes
app.get('/api/calendar', authenticateToken, async (req, res) => {
  const events = await knex('calendar_events').select('*');
  res.json(events);
});

app.post('/api/calendar', authenticateToken, async (req, res) => {
  const { title, start_date, end_date } = req.body;
  const [id] = await knex('calendar_events').insert({ title, start_date, end_date });
  res.json({ id });
});

// -------------------
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server läuft auf Port ${PORT}`);
});
