const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');

require('dotenv').config();

// 👉 REGISTRO DE USUARIO
router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

  const hash = await bcrypt.hash(password, 10);
  db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (err) => {
    if (err) return res.status(400).json({ error: 'El usuario ya existe' });
    res.json({ message: 'Usuario registrado con éxito' });
  });
});

// 👉 LOGIN DE USUARIO
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ error: 'Usuario no encontrado' });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
    res.json({ token });
  });
});

// 🛡️ MIDDLEWARE para verificar token
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1]; // "Bearer TOKEN"
  if (!token) return res.status(401).json({ error: 'Token requerido' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ error: 'Token inválido' });
  }
}

// ✍️ CREAR ENTRADA
router.post('/entries', auth, (req, res) => {
  const { title, content } = req.body;
  db.query('INSERT INTO entries (user_id, title, content) VALUES (?, ?, ?)', [req.user.id, title, content], (err) => {
    if (err) return res.status(500).json({ error: 'Error al guardar entrada' });
    res.json({ message: 'Entrada guardada' });
  });
});

// 📖 OBTENER ENTRADAS DEL USUARIO
router.get('/entries', auth, (req, res) => {
    db.query('SELECT * FROM entries WHERE user_id = ? ORDER BY created_at DESC', [req.user.id], (err, results) => {
      if (err) return res.status(500).json({ error: 'Error al obtener entradas' });
      res.json(results);
    });
  });
  
// 📝 EDITAR entrada
router.put('/entries/:id', auth, (req, res) => {
    const entryId = req.params.id;
    const { title, content } = req.body;
  
    db.query(
      'UPDATE entries SET title = ?, content = ? WHERE id = ? AND user_id = ?',
      [title, content, entryId, req.user.id],
      (err) => {
        if (err) return res.status(500).json({ error: 'Error al editar entrada' });
        res.json({ message: 'Entrada actualizada' });
      }
    );
  });
  
  // 🗑️ BORRAR entrada
  router.delete('/entries/:id', auth, (req, res) => {
    const entryId = req.params.id;
  
    db.query(
      'DELETE FROM entries WHERE id = ? AND user_id = ?',
      [entryId, req.user.id],
      (err) => {
        if (err) return res.status(500).json({ error: 'Error al borrar entrada' });
        res.json({ message: 'Entrada eliminada' });
      }
    );
  });
  router.delete('/entries/:id', auth, (req, res) => {
    const entryId = req.params.id;
    console.log('Intentando borrar entrada con ID:', entryId, 'de usuario:', req.user.id);
    
    db.query(
    'DELETE FROM entries WHERE id = ? AND user_id = ?',
    [entryId, req.user.id],
    (err, results) => {
      if (err) {
        console.error('Error al borrar entrada:', err);
        return res.status(500).json({ error: 'Error al borrar entrada' });
      }

      // Este console.log nos dice cuántas filas afectó (affectedRows).
      console.log('Resultado de DELETE:', results);

      // results contiene información sobre la operación, por ejemplo, results.affectedRows
      res.json({ message: 'Entrada eliminada' });
    }
  );
});
module.exports = router;

