const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const SCHEMA = 'multiplay_edu_standalone';

let pool;
let dbReady = false;

async function initDb() {
  if (!DATABASE_URL) throw new Error('DATABASE_URL não configurada');
  if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET deve ter pelo menos 32 caracteres');
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false },
    max: 5
  });
  await pool.query(`CREATE SCHEMA IF NOT EXISTS ${SCHEMA}`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${SCHEMA}.students (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ${SCHEMA}.courses (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      hours INTEGER NOT NULL DEFAULT 0 CHECK (hours >= 0),
      category TEXT NOT NULL DEFAULT 'Geral',
      source TEXT NOT NULL DEFAULT 'multiplay',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ${SCHEMA}.lessons (
      id BIGSERIAL PRIMARY KEY,
      course_id BIGINT NOT NULL REFERENCES ${SCHEMA}.courses(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      video_url TEXT NOT NULL DEFAULT '',
      position INTEGER NOT NULL DEFAULT 1,
      active BOOLEAN NOT NULL DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS ${SCHEMA}.enrollments (
      id BIGSERIAL PRIMARY KEY,
      student_id BIGINT NOT NULL REFERENCES ${SCHEMA}.students(id) ON DELETE CASCADE,
      course_id BIGINT NOT NULL REFERENCES ${SCHEMA}.courses(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','completed','cancelled')),
      enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(student_id, course_id)
    );
    CREATE TABLE IF NOT EXISTS ${SCHEMA}.lesson_progress (
      student_id BIGINT NOT NULL REFERENCES ${SCHEMA}.students(id) ON DELETE CASCADE,
      lesson_id BIGINT NOT NULL REFERENCES ${SCHEMA}.lessons(id) ON DELETE CASCADE,
      completed BOOLEAN NOT NULL DEFAULT FALSE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(student_id, lesson_id)
    );
    CREATE TABLE IF NOT EXISTS ${SCHEMA}.assessments (
      id BIGSERIAL PRIMARY KEY,
      course_id BIGINT NOT NULL REFERENCES ${SCHEMA}.courses(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      questions JSONB NOT NULL DEFAULT '[]'::jsonb,
      passing_score INTEGER NOT NULL DEFAULT 70 CHECK (passing_score BETWEEN 0 AND 100)
    );
    CREATE TABLE IF NOT EXISTS ${SCHEMA}.assessment_attempts (
      id BIGSERIAL PRIMARY KEY,
      student_id BIGINT NOT NULL REFERENCES ${SCHEMA}.students(id) ON DELETE CASCADE,
      assessment_id BIGINT NOT NULL REFERENCES ${SCHEMA}.assessments(id) ON DELETE CASCADE,
      score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
      passed BOOLEAN NOT NULL,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ${SCHEMA}.certificates (
      id BIGSERIAL PRIMARY KEY,
      student_id BIGINT NOT NULL REFERENCES ${SCHEMA}.students(id) ON DELETE CASCADE,
      course_id BIGINT NOT NULL REFERENCES ${SCHEMA}.courses(id) ON DELETE CASCADE,
      code TEXT NOT NULL UNIQUE,
      issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(student_id, course_id)
    );
  `);
  dbReady = true;
}

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    if (!token) throw new Error('missing');
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Acesso não autorizado' });
  }
}
function requireDb(req, res, next) {
  if (!dbReady) return res.status(503).json({ error: 'Banco não configurado; plataforma em preparação.' });
  next();
}
app.get('/api/health', (req, res) => res.json({ ok: true, service: 'multiplay-educacao-standalone', database: dbReady ? 'ready' : 'not_configured' }));
app.get('/api/educacao/courses', requireDb, async (req, res) => {
  try {
    const result = await pool.query(`SELECT id,title,description,hours,category,source FROM ${SCHEMA}.courses WHERE active=true ORDER BY title`);
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Não foi possível carregar os cursos.' }); }
});
app.post('/api/educacao/register', requireDb, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!name || !/^\S+@\S+\.\S+$/.test(email) || password.length < 10) {
    return res.status(400).json({ error: 'Informe nome, e-mail válido e senha com pelo menos 10 caracteres.' });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(`INSERT INTO ${SCHEMA}.students(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email`, [name,email,hash]);
    res.status(201).json({ student: result.rows[0] });
  } catch (e) {
    res.status(e.code === '23505' ? 409 : 500).json({ error: e.code === '23505' ? 'Este e-mail já está cadastrado.' : 'Não foi possível criar a conta.' });
  }
});
app.post('/api/educacao/login', requireDb, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  try {
    const result = await pool.query(`SELECT id,name,email,password_hash,active FROM ${SCHEMA}.students WHERE email=$1`, [email]);
    const student = result.rows[0];
    if (!student || !student.active || !(await bcrypt.compare(password, student.password_hash))) {
      return res.status(401).json({ error: 'E-mail ou senha inválidos.' });
    }
    const token = jwt.sign({ sub: String(student.id), email: student.email, role: 'student' }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, student: { id: student.id, name: student.name, email: student.email } });
  } catch { res.status(500).json({ error: 'Não foi possível entrar.' }); }
});
app.get('/api/educacao/me', requireDb, auth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT id,name,email FROM ${SCHEMA}.students WHERE id=$1 AND active=true`, [req.user.sub]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Aluno não encontrado.' });
    res.json({ student: result.rows[0] });
  } catch { res.status(500).json({ error: 'Não foi possível carregar o perfil.' }); }
});
app.get('/api/educacao/my-certificates', requireDb, auth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT c.code,c.issued_at,co.title,co.hours,s.name FROM ${SCHEMA}.certificates c JOIN ${SCHEMA}.courses co ON co.id=c.course_id JOIN ${SCHEMA}.students s ON s.id=c.student_id WHERE c.student_id=$1 ORDER BY c.issued_at DESC`, [req.user.sub]);
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Não foi possível carregar certificados.' }); }
});
app.get('/api/educacao/admin/status', (req, res) => res.status(403).json({ error: 'Painel administrativo será habilitado após configurar credenciais seguras.' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
initDb().catch(err => { console.error('Database initialization failed:', err.message); dbReady = false; });
app.listen(PORT, () => console.log('Multiplay Educação standalone listening on', PORT));
