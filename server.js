const fs = require('fs');
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based version
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(express.json());

// Configure CORS properly for Vercel
const allowedOrigins = [
  'http://localhost:5173',
  process.env.FRONTEND_URL // Add your Vercel frontend URL here
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
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
  res.status(500).send('Something broke!');
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET || '123456', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Register endpoint with async/await
app.post('/register', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    // Check if the username already exists
    const [results] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (results.length > 0) {
      return res.status(400).send('Username already exists');
    }

    // Hash the password
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Insert the new user into the database
    const [insertResult] = await db.execute(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );
    
    res.status(201).send('User registered successfully');
  } catch (err) {
    next(err);
  }
});

// Login endpoint with async/await
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    console.log('Login attempt for:', username); // Debug log

    const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    
    if (users.length === 0) {
      console.log('User not found:', username); // Debug log
      return res.status(401).json({ error: 'Invalid credentials' }); // Don't reveal if user exists
    }

    const user = users[0];
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    console.log('Password match:', passwordMatch); // Debug log

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ 
      token,
      user: { id: user.id, username: user.username }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


// Fetch orders endpoint with async/await
app.get('/orders', authenticateToken, async (req, res, next) => {
  try {
    const userId = req.user.id;

    // Fetch orders for the logged-in user
    const [results] = await db.execute('SELECT * FROM orders WHERE user_id = ?', [userId]);
    res.json(results);
  } catch (err) {
    next(err);
  }
});

// Create order endpoint with async/await
app.post('/orders', authenticateToken, async (req, res, next) => {
  try {
    const { order_details } = req.body;
    const userId = req.user.id;

    // Insert the new order into the database
    const [results] = await db.execute(
      'INSERT INTO orders (user_id, order_details) VALUES (?, ?)',
      [userId, order_details]
    );
    
    res.json({ id: results.insertId, user_id: userId, order_details });
  } catch (err) {
    next(err);
  }
});

// Update order endpoint with async/await
app.put('/orders/:id', authenticateToken, async (req, res, next) => {
  try {
    const { order_details } = req.body;
    const orderId = req.params.id;
    const userId = req.user.id;

    // Update the order in the database
    const [results] = await db.execute(
      'UPDATE orders SET order_details = ? WHERE id = ? AND user_id = ?',
      [order_details, orderId, userId]
    );
    
    if (results.affectedRows === 0) {
      return res.status(404).send('Order not found');
    }
    
    res.json({ id: orderId, user_id: userId, order_details });
  } catch (err) {
    next(err);
  }
});

// Delete order endpoint with async/await
app.delete('/orders/:id', authenticateToken, async (req, res, next) => {
  try {
    const orderId = req.params.id;
    const userId = req.user.id;

    // Delete the order from the database
    const [results] = await db.execute(
      'DELETE FROM orders WHERE id = ? AND user_id = ?',
      [orderId, userId]
    );
    
    if (results.affectedRows === 0) {
      return res.status(404).send('Order not found');
    }
    
    res.sendStatus(204);
  } catch (err) {
    next(err);
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
