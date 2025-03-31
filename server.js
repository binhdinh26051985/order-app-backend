const fs = require('fs');
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(express.json());

// Configure CORS properly for Vercel
const allowedOrigins = [
  'http://localhost:5173',
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

// Database connection with better error handling
let db;
try {
  db = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: process.env.DB_SSL_CA ? {
      ca: fs.readFileSync(process.env.DB_SSL_CA)
    } : null
  });

  // Test the connection
  db.getConnection()
    .then(connection => {
      console.log('Connected to MySQL database');
      connection.release();
    })
    .catch(err => {
      console.error('Database connection error:', err);
    });
} catch (err) {
  console.error('Database configuration error:', err);
}

// Improved error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, process.env.JWT_SECRET || '123456', (err, user) => {
    if (err) return res.status(403).json({ error: 'Forbidden' });
    req.user = user;
    next();
  });
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

// Register endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );
    
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    console.log('Login attempt for:', username);

    // Add database query logging
    console.log('Executing database query...');
    const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    console.log('Query results:', users);

    if (users.length === 0) {
      console.log('User not found:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    console.log('User found, comparing passwords...');
    const passwordMatch = await bcrypt.compare(password, user.password);
    console.log('Password match result:', passwordMatch);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    console.log('Generating JWT token...');
    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET || '123456',
      { expiresIn: '1h' }
    );

    res.json({ 
      token,
      user: { id: user.id, username: user.username }
    });
  } catch (error) {
    console.error('FULL LOGIN ERROR:', {
      message: error.message,
      stack: error.stack,
      rawError: error
    });
    res.status(500).json({ 
      error: 'Internal server error',
      // Only show details in development
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


// Order endpoints
app.get('/orders', authenticateToken, async (req, res) => {
  try {
    const [results] = await db.execute('SELECT * FROM orders WHERE user_id = ?', [req.user.id]);
    res.json(results);
  } catch (err) {
    console.error('Get orders error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/orders', authenticateToken, async (req, res) => {
  try {
    const { order_details } = req.body;
    const [result] = await db.execute(
      'INSERT INTO orders (user_id, order_details) VALUES (?, ?)',
      [req.user.id, order_details]
    );
    res.status(201).json({ 
      id: result.insertId, 
      user_id: req.user.id, 
      order_details 
    });
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/orders/:id', authenticateToken, async (req, res) => {
  try {
    const [result] = await db.execute(
      'UPDATE orders SET order_details = ? WHERE id = ? AND user_id = ?',
      [req.body.order_details, req.params.id, req.user.id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    res.json({ 
      id: req.params.id, 
      user_id: req.user.id, 
      order_details: req.body.order_details 
    });
  } catch (err) {
    console.error('Update order error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/orders/:id', authenticateToken, async (req, res) => {
  try {
    const [result] = await db.execute(
      'DELETE FROM orders WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    res.sendStatus(204);
  } catch (err) {
    console.error('Delete order error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Vercel requires module.exports for serverless functions
module.exports = app;

// Only listen when not in Vercel environment
if (process.env.VERCEL !== '1') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}
