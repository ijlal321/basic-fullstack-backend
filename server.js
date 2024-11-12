const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Initialize SQLite database with a file for persistence
const db = new sqlite3.Database('./database.db', (err) => {
  if (err) {
    console.error("Couldn't connect to the database:", err);
  } else {
    console.log('Connected to the persistent SQLite database.');
  }
});

// Create tables if they don't already exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS checklist (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      completed BOOLEAN NOT NULL CHECK (completed IN (0, 1)),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
});

// Helper function to authenticate user
async function authenticateUser(username, password, callback) {
  db.get('SELECT * FROM users WHERE name = ?', username, async (err, user) => {
    if (err) return callback(err);
    if (!user) return callback(null, false);

    const match = await bcrypt.compare(password, user.password);
    if (match) callback(null, user);
    else callback(null, false);
  });
}

// REGISTER - POST /register
app.post('/register', async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Name and password are required' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const sql = 'INSERT INTO users (name, password) VALUES (?, ?)';
  db.run(sql, [name, hashedPassword], function (err) {
    if (err) return res.status(500).json({ error: 'Username already taken' });
    res.status(201).json({ id: this.lastID, name });
  });
});

// LOGIN - POST /login
app.post('/login', (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Name and password are required' });

  authenticateUser(name, password, (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    res.status(200).json({ message: 'Login successful', userId: user.id });
  });
});

// CRUD for Checklist Items for Authenticated Users

// GET /users/:userId/checklist - Get all checklist items for a specific user
app.get('/users/:userId/checklist', (req, res) => {
  const { userId } = req.params;
  const sql = 'SELECT * FROM checklist WHERE user_id = ?';
  db.all(sql, userId, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// POST /users/:userId/checklist - Add a new checklist item for a user
app.post('/users/:userId/checklist', (req, res) => {
  const { userId } = req.params;
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Checklist item name is required' });

  const sql = 'INSERT INTO checklist (user_id, name, completed) VALUES (?, ?, ?)';
  db.run(sql, [userId, name, false], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: this.lastID, user_id: userId, name, completed: false });
  });
});

// DELETE /users/:userId/checklist/:id - Delete a checklist item for a user
app.delete('/users/:userId/checklist/:id', (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM checklist WHERE id = ?';
  db.run(sql, id, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Checklist item not found' });
    res.status(200).json({ message: 'Checklist item deleted' });
  });
});

// PATCH /users/:userId/checklist/:id/complete - Mark a checklist item as completed
app.patch('/users/:userId/checklist/:id/complete', (req, res) => {
  const { id } = req.params;
  const sql = 'UPDATE checklist SET completed = 1 WHERE id = ?';
  db.run(sql, id, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Checklist item not found' });
    res.status(200).json({ message: 'Checklist item marked as complete' });
  });
});

// PATCH /users/:userId/checklist/:id/incomplete - Mark a checklist item as incomplete
app.patch('/users/:userId/checklist/:id/incomplete', (req, res) => {
  const { id } = req.params;
  const sql = 'UPDATE checklist SET completed = 0 WHERE id = ?';
  db.run(sql, id, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Checklist item not found' });
    res.status(200).json({ message: 'Checklist item marked as incomplete' });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
