require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'pulse_secret_key_2025';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/api/health', (req, res) => {
  db.query('SELECT 1', (err) => {
    if (err) return res.json({ status: 'DB error', error: err.message });
    res.json({ status: 'OK' });
  });
});

// ── Подключение к БД через переменные окружения ──────────────────────────────
const db = mysql.createConnection({
  host:     process.env.DB_HOST,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port:     process.env.DB_PORT || 3306,
});

db.connect(err => {
  if (err) { console.error('Ошибка подключения к БД:', err); return; }
  console.log('Подключено к MySQL');
});

// ── Регистрация ───────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, email, password, role } = req.body;
  const passwordRegex = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({ message: 'Пароль должен содержать минимум 8 символов, заглавную букву, цифру и спецсимвол' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)';
    db.query(sql, [username, email, hashedPassword, role || 'reader'], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'Пользователь с таким именем или email уже существует' });
        }
        return res.status(500).json({ message: 'Ошибка сервера' });
      }
      res.json({ message: 'Регистрация успешна' });
    });
  } catch (err) {
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// ── Вход ──────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const sql = 'SELECT * FROM users WHERE username = ?';
  db.query(sql, [username], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Ошибка сервера' });
    if (results.length === 0) return res.status(401).json({ message: 'Неверный логин или пароль' });
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Неверный логин или пароль' });
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      SECRET_KEY,
      { expiresIn: '24h' }
    );
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  });
});

// ── Статьи ────────────────────────────────────────────────────────────────────
app.get('/api/articles', (req, res) => {
  const sql = `
    SELECT a.*, u.username as author_name, c.name as category_name,
      (SELECT COUNT(*) FROM comments WHERE article_id = a.id) as comment_count,
      (SELECT COUNT(*) FROM likes WHERE article_id = a.id) as likes_count
    FROM articles a
    JOIN users u ON a.author_id = u.id
    LEFT JOIN categories c ON a.category_id = c.id
    WHERE a.status = 'published'
    ORDER BY a.created_at DESC
  `;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ message: 'Ошибка сервера' });
    res.json(results);
  });
});

app.post('/api/articles', verifyToken, (req, res) => {
  const { title, content, category_id, image_url } = req.body;
  const sql = 'INSERT INTO articles (title, content, author_id, category_id, image_url, status) VALUES (?, ?, ?, ?, ?, ?)';
  db.query(sql, [title, content, req.user.id, category_id, image_url || null, 'published'], (err, result) => {
    if (err) return res.status(500).json({ message: 'Ошибка сервера: ' + err.message });
    res.json({ message: 'Статья создана', id: result.insertId });
  });
});

// ── Лайки ─────────────────────────────────────────────────────────────────────
app.post('/api/articles/:id/like', verifyToken, (req, res) => {
  const checkSql = 'SELECT id FROM likes WHERE article_id = ? AND user_id = ?';
  db.query(checkSql, [req.params.id, req.user.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Ошибка сервера' });
    const countSql = 'SELECT COUNT(*) as count FROM likes WHERE article_id = ?';
    if (results.length > 0) {
      db.query('DELETE FROM likes WHERE article_id = ? AND user_id = ?', [req.params.id, req.user.id], (err2) => {
        if (err2) return res.status(500).json({ message: 'Ошибка сервера' });
        db.query(countSql, [req.params.id], (_, countResult) => {
          res.json({ liked: false, likes_count: countResult[0].count });
        });
      });
    } else {
      db.query('INSERT INTO likes (article_id, user_id) VALUES (?, ?)', [req.params.id, req.user.id], (err2) => {
        if (err2) return res.status(500).json({ message: 'Ошибка сервера' });
        db.query(countSql, [req.params.id], (_, countResult) => {
          res.json({ liked: true, likes_count: countResult[0].count });
        });
      });
    }
  });
});

app.get('/api/articles/:id/like', verifyToken, (req, res) => {
  db.query('SELECT id FROM likes WHERE article_id = ? AND user_id = ?', [req.params.id, req.user.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Ошибка сервера' });
    res.json({ liked: results.length > 0 });
  });
});

// ── Комментарии ───────────────────────────────────────────────────────────────
app.get('/api/articles/:id/comments', (req, res) => {
  const sql = `
    SELECT c.*, u.username 
    FROM comments c 
    JOIN users u ON c.user_id = u.id 
    WHERE c.article_id = ? 
    ORDER BY c.created_at DESC
  `;
  db.query(sql, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Ошибка сервера' });
    res.json(results);
  });
});

app.post('/api/articles/:id/comments', verifyToken, (req, res) => {
  const { text } = req.body;
  db.query('INSERT INTO comments (article_id, user_id, text) VALUES (?, ?, ?)', [req.params.id, req.user.id, text], (err, result) => {
    if (err) return res.status(500).json({ message: 'Ошибка сервера' });
    res.json({ message: 'Комментарий добавлен', id: result.insertId });
  });
});

app.delete('/api/comments/:id', verifyToken, (req, res) => {
  db.query('DELETE FROM comments WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, result) => {
    if (err) return res.status(500).json({ message: 'Ошибка сервера' });
    if (result.affectedRows === 0) return res.status(403).json({ message: 'Нельзя удалить чужой комментарий' });
    res.json({ message: 'Комментарий удалён' });
  });
});

// ── Middleware ────────────────────────────────────────────────────────────────
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(403).json({ message: 'Требуется авторизация' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(403).json({ message: 'Требуется авторизация' });
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Неверный токен' });
    req.user = decoded;
    next();
  });
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});