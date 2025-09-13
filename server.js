"use strict";

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const knexLib = require('knex');
const { Pool } = require("pg");

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cors({
  origin: [
    "http://localhost:3000", // dein lokales Frontend
     // später deine echte Domain
  ],
  credentials: true
}));

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

// --- PostgreSQL Pool ---
const pool = new Pool({
  host: process.env.POSTGRES_HOST,
  port: process.env.POSTGRES_PORT,
  user: process.env.POSTGRES_USER,
  password: process.env.POSTGRES_PASSWORD,
  database: process.env.POSTGRES_DB,
});

// --- Auto-Migration ---
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS news (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS horses (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      price NUMERIC,
      available BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS calendar_events (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      start_date DATE NOT NULL,
      end_date DATE NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Admin prüfen
  const res = await pool.query("SELECT * FROM users WHERE email = $1", ["admin@familienhof-schmagold.de"]);
  if (res.rows.length === 0) {
    const hashed = await bcrypt.hash("robins1412", 10);
    await pool.query("INSERT INTO users (email, password) VALUES ($1, $2)", [
      "admin@familienhof-schmagold.de",
      hashed,
    ]);
    console.log("✅ Admin-User erstellt: admin@familienhof-schmagold.de / admin123");
  }
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

app.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

app.post('/api/calendar', authenticateToken, async (req, res) => {
  const { title, start_date, end_date } = req.body;
  const [id] = await knex('calendar_events').insert({ title, start_date, end_date });
  res.json({ id });
});

// -------------------
const PORT = process.env.PORT || 3001;

// --- Serverstart ---
app.listen(PORT, async () => {
  console.log(`🚀 Server läuft auf Port ${PORT}`);
  try {
    await initDb();
    console.log("📦 Datenbank ist bereit");
  } catch (err) {
    console.error("❌ DB Init Fehler:", err);
  }
});
