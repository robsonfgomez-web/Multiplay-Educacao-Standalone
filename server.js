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
function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso exclusivo do administrador.' });
    next();
  });
}
function adminConfigured() {
  return Boolean(process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD_HASH);
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
// Admin credentials are configured only through Render environment variables.
app.post('/api/educacao/admin/login', requireDb, async (req, res) => {
  if (!adminConfigured()) return res.status(503).json({ error: 'Configure ADMIN_EMAIL e ADMIN_PASSWORD_HASH no Render.' });
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const expectedEmail = String(process.env.ADMIN_EMAIL).trim().toLowerCase();
  const ok = email === expectedEmail && await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
  if (!ok) return res.status(401).json({ error: 'Credenciais administrativas inválidas.' });
  const token = jwt.sign({ sub: 'admin', email, role: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ token, admin: { email } });
});
app.get('/api/educacao/admin/status', requireDb, adminAuth, async (req, res) => {
  try {
    const [students,courses,enrollments,certificates] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS count FROM ${SCHEMA}.students`),
      pool.query(`SELECT COUNT(*)::int AS count FROM ${SCHEMA}.courses WHERE active=true`),
      pool.query(`SELECT COUNT(*)::int AS count FROM ${SCHEMA}.enrollments WHERE status='active'`),
      pool.query(`SELECT COUNT(*)::int AS count FROM ${SCHEMA}.certificates`)
    ]);
    res.json({ students: students.rows[0].count, courses: courses.rows[0].count, enrollments: enrollments.rows[0].count, certificates: certificates.rows[0].count });
  } catch { res.status(500).json({ error: 'Não foi possível carregar o painel.' }); }
});
app.get('/api/educacao/admin/students', requireDb, adminAuth, async (req, res) => {
  try { const r = await pool.query(`SELECT id,name,email,active,created_at FROM ${SCHEMA}.students ORDER BY created_at DESC LIMIT 500`); res.json(r.rows); }
  catch { res.status(500).json({ error: 'Não foi possível listar alunos.' }); }
});
app.post('/api/educacao/admin/students', requireDb, adminAuth, async (req, res) => {
  const name = String(req.body.name || '').trim(), email = String(req.body.email || '').trim().toLowerCase(), password = String(req.body.password || '');
  if (!name || !/^\\S+@\\S+\\.\\S+$/.test(email) || password.length < 10) return res.status(400).json({ error: 'Nome, e-mail válido e senha com pelo menos 10 caracteres são obrigatórios.' });
  try {
    const hash = await bcrypt.hash(password,12);
    const r = await pool.query(`INSERT INTO ${SCHEMA}.students(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email,active,created_at`,[name,email,hash]);
    res.status(201).json(r.rows[0]);
  } catch(e) { res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'E-mail já cadastrado.':'Falha ao cadastrar aluno.'}); }
});
app.patch('/api/educacao/admin/students/:id', requireDb, adminAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({error:'ID inválido.'});
  const fields=[], values=[];
  if (typeof req.body.name === 'string' && req.body.name.trim()) { values.push(req.body.name.trim()); fields.push('name=
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
initDb().catch(err => { console.error('Database initialization failed:', err.message); dbReady = false; });
app.listen(PORT, () => console.log('Multiplay Educação standalone listening on', PORT));
+values.length); }
  if (typeof req.body.email === 'string' && /^\\S+@\\S+\\.\\S+$/.test(req.body.email.trim())) { values.push(req.body.email.trim().toLowerCase()); fields.push('email=
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
initDb().catch(err => { console.error('Database initialization failed:', err.message); dbReady = false; });
app.listen(PORT, () => console.log('Multiplay Educação standalone listening on', PORT));
+values.length); }
  if (typeof req.body.active === 'boolean') { values.push(req.body.active); fields.push('active=
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
initDb().catch(err => { console.error('Database initialization failed:', err.message); dbReady = false; });
app.listen(PORT, () => console.log('Multiplay Educação standalone listening on', PORT));
+values.length); }
  if (typeof req.body.password === 'string' && req.body.password.length >= 10) { values.push(await bcrypt.hash(req.body.password,12)); fields.push('password_hash=
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
initDb().catch(err => { console.error('Database initialization failed:', err.message); dbReady = false; });
app.listen(PORT, () => console.log('Multiplay Educação standalone listening on', PORT));
+values.length); }
  if (!fields.length) return res.status(400).json({error:'Nenhum campo válido para atualizar.'});
  values.push(id);
  try {
    const r=await pool.query(`UPDATE ${SCHEMA}.students SET ${fields.join(',')} WHERE id=${values.length} RETURNING id,name,email,active,created_at`,values);
    if (!r.rowCount) return res.status(404).json({error:'Aluno não encontrado.'});
    res.json(r.rows[0]);
  } catch(e) { res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'E-mail já cadastrado.':'Falha ao atualizar aluno.'}); }
});
app.delete('/api/educacao/admin/students/:id', requireDb, adminAuth, async (req, res) => {
  if (req.body.confirm !== true) return res.status(400).json({error:'Envie confirm:true para confirmar a exclusão permanente.'});
  const id=Number(req.params.id);
  if (!Number.isInteger(id)||id<1) return res.status(400).json({error:'ID inválido.'});
  try { const r=await pool.query(`DELETE FROM ${SCHEMA}.students WHERE id=$1 RETURNING id`,[id]); if(!r.rowCount)return res.status(404).json({error:'Aluno não encontrado.'}); res.json({deleted:true,id}); }
  catch { res.status(500).json({error:'Falha ao excluir aluno.'}); }
});
app.get('/api/educacao/admin/courses', requireDb, adminAuth, async (req,res) => {
  try { const r=await pool.query(`SELECT c.*, (SELECT COUNT(*)::int FROM ${SCHEMA}.lessons l WHERE l.course_id=c.id) AS lessons_count FROM ${SCHEMA}.courses c ORDER BY c.title`); res.json(r.rows); }
  catch { res.status(500).json({error:'Falha ao listar cursos.'}); }
});
app.post('/api/educacao/admin/courses', requireDb, adminAuth, async (req,res) => {
  const title=String(req.body.title||'').trim();
  const hours=Number(req.body.hours||0);
  if(!title||!Number.isInteger(hours)||hours<0) return res.status(400).json({error:'Título e carga horária válida são obrigatórios.'});
  try {
    const r=await pool.query(`INSERT INTO ${SCHEMA}.courses(title,description,hours,category,source) VALUES($1,$2,$3,$4,$5) RETURNING *`,[title,String(req.body.description||''),hours,String(req.body.category||'Geral'),String(req.body.source||'multiplay')]);
    res.status(201).json(r.rows[0]);
  } catch { res.status(500).json({error:'Falha ao criar curso.'}); }
});
app.patch('/api/educacao/admin/courses/:id', requireDb, adminAuth, async (req,res) => {
  const id=Number(req.params.id), fields=[],values=[];
  if(!Number.isInteger(id)||id<1)return res.status(400).json({error:'ID inválido.'});
  for(const key of ['title','description','category','source']) if(typeof req.body[key]==='string' && (key!=='title'||req.body[key].trim())){values.push(key==='title'?req.body[key].trim():req.body[key]);fields.push(key+'=
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
initDb().catch(err => { console.error('Database initialization failed:', err.message); dbReady = false; });
app.listen(PORT, () => console.log('Multiplay Educação standalone listening on', PORT));
+values.length);}
  if(Number.isInteger(req.body.hours)&&req.body.hours>=0){values.push(req.body.hours);fields.push('hours=
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
initDb().catch(err => { console.error('Database initialization failed:', err.message); dbReady = false; });
app.listen(PORT, () => console.log('Multiplay Educação standalone listening on', PORT));
+values.length);}
  if(typeof req.body.active==='boolean'){values.push(req.body.active);fields.push('active=
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
initDb().catch(err => { console.error('Database initialization failed:', err.message); dbReady = false; });
app.listen(PORT, () => console.log('Multiplay Educação standalone listening on', PORT));
+values.length);}
  if(!fields.length)return res.status(400).json({error:'Nenhum campo válido para atualizar.'});
  values.push(id);
  try{const r=await pool.query(`UPDATE ${SCHEMA}.courses SET ${fields.join(',')} WHERE id=${values.length} RETURNING *`,values);if(!r.rowCount)return res.status(404).json({error:'Curso não encontrado.'});res.json(r.rows[0]);}
  catch{res.status(500).json({error:'Falha ao atualizar curso.'});}
});
app.delete('/api/educacao/admin/courses/:id', requireDb, adminAuth, async (req,res) => {
  if(req.body.confirm!==true)return res.status(400).json({error:'Envie confirm:true para confirmar exclusão permanente.'});
  const id=Number(req.params.id);if(!Number.isInteger(id)||id<1)return res.status(400).json({error:'ID inválido.'});
  try{const r=await pool.query(`UPDATE ${SCHEMA}.courses SET active=false WHERE id=$1 RETURNING id`,[id]);if(!r.rowCount)return res.status(404).json({error:'Curso não encontrado.'});res.json({deactivated:true,id});}
  catch{res.status(500).json({error:'Falha ao desativar curso.'});}
});
app.post('/api/educacao/admin/courses/:id/lessons', requireDb, adminAuth, async (req,res) => {
  const courseId=Number(req.params.id), title=String(req.body.title||'').trim(), videoUrl=String(req.body.video_url||'').trim(), position=Number(req.body.position||1);
  if(!Number.isInteger(courseId)||courseId<1||!title||!Number.isInteger(position)||position<1)return res.status(400).json({error:'Curso, título e posição válidos são obrigatórios.'});
  if(videoUrl && !/^https:\\/\\//i.test(videoUrl))return res.status(400).json({error:'O link da videoaula deve usar HTTPS.'});
  try{const r=await pool.query(`INSERT INTO ${SCHEMA}.lessons(course_id,title,video_url,position) SELECT id,$2,$3,$4 FROM ${SCHEMA}.courses WHERE id=$1 AND active=true RETURNING *`,[courseId,title,videoUrl,position]);if(!r.rowCount)return res.status(404).json({error:'Curso não encontrado ou inativo.'});res.status(201).json(r.rows[0]);}
  catch{res.status(500).json({error:'Falha ao criar aula.'});}
});
app.post('/api/educacao/admin/enrollments', requireDb, adminAuth, async (req,res) => {
  const studentId=Number(req.body.student_id),courseId=Number(req.body.course_id);
  if(!Number.isInteger(studentId)||!Number.isInteger(courseId)||studentId<1||courseId<1)return res.status(400).json({error:'Aluno e curso válidos são obrigatórios.'});
  try{const r=await pool.query(`INSERT INTO ${SCHEMA}.enrollments(student_id,course_id) VALUES($1,$2) ON CONFLICT(student_id,course_id) DO UPDATE SET status='active' RETURNING *`,[studentId,courseId]);res.status(201).json(r.rows[0]);}
  catch(e){res.status(500).json({error:'Falha ao matricular aluno.'});}
});
app.post('/api/educacao/admin/certificates/issue', requireDb, adminAuth, async (req,res) => {
  const studentId=Number(req.body.student_id),courseId=Number(req.body.course_id);
  if(!Number.isInteger(studentId)||!Number.isInteger(courseId)||studentId<1||courseId<1)return res.status(400).json({error:'Aluno e curso válidos são obrigatórios.'});
  try{
    const check=await pool.query(`
      SELECT e.id,
      (SELECT COUNT(*)::int FROM ${SCHEMA}.lessons l WHERE l.course_id=e.course_id AND l.active=true) AS total_lessons,
      (SELECT COUNT(*)::int FROM ${SCHEMA}.lessons l JOIN ${SCHEMA}.lesson_progress p ON p.lesson_id=l.id AND p.student_id=e.student_id AND p.completed=true WHERE l.course_id=e.course_id AND l.active=true) AS completed_lessons,
      EXISTS(SELECT 1 FROM ${SCHEMA}.assessments a JOIN ${SCHEMA}.assessment_attempts aa ON aa.assessment_id=a.id AND aa.student_id=e.student_id AND aa.passed=true WHERE a.course_id=e.course_id) AS passed_assessment
      FROM ${SCHEMA}.enrollments e WHERE e.student_id=$1 AND e.course_id=$2 AND e.status IN ('active','completed')`,[studentId,courseId]);
    const x=check.rows[0];
    if(!x)return res.status(409).json({error:'Aluno não está matriculado neste curso.'});
    if(x.total_lessons===0||x.completed_lessons<x.total_lessons||!x.passed_assessment)return res.status(409).json({error:'Certificado bloqueado: todas as aulas e a avaliação aprovada são obrigatórias.',total_lessons:x.total_lessons,completed_lessons:x.completed_lessons,passed_assessment:x.passed_assessment});
    const code='MPL-'+require('crypto').randomBytes(8).toString('hex').toUpperCase();
    const r=await pool.query(`INSERT INTO ${SCHEMA}.certificates(student_id,course_id,code) VALUES($1,$2,$3) ON CONFLICT(student_id,course_id) DO NOTHING RETURNING *`,[studentId,courseId,code]);
    if(!r.rowCount){const existing=await pool.query(`SELECT * FROM ${SCHEMA}.certificates WHERE student_id=$1 AND course_id=$2`,[studentId,courseId]);return res.json(existing.rows[0]);}
    await pool.query(`UPDATE ${SCHEMA}.enrollments SET status='completed' WHERE student_id=$1 AND course_id=$2`,[studentId,courseId]);
    res.status(201).json(r.rows[0]);
  }catch{res.status(500).json({error:'Falha ao emitir certificado.'});}
});
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
initDb().catch(err => { console.error('Database initialization failed:', err.message); dbReady = false; });
app.listen(PORT, () => console.log('Multiplay Educação standalone listening on', PORT));
